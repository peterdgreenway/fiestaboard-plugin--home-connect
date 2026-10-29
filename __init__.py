"""Home Connect — appliance status for Vestaboard Note (up to 5 devices).

Credentials (user identity + password, client secret) are stored encrypted
with Fernet when cryptography is available; otherwise obfuscated at rest.
Status strings are abridged to Note limits (15 tiles/row, 45 total).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from src.plugins.base import PluginBase, PluginResult

logger = logging.getLogger(__name__)

NOTE_WIDTH = 15
NOTE_CHARS = 45
MAX_APPLIANCES = 5
UA = "FiestaBoard-HomeConnect/1.0 (+https://fiestaboard.app)"

# Production API (use simulator host if configured)
API_HOST = "https://api.home-connect.com"
TOKEN_URL = "https://api.home-connect.com/security/oauth/token"
SIM_API_HOST = "https://simulator.home-connect.com"
SIM_TOKEN_URL = "https://simulator.home-connect.com/security/oauth/token"

RED = "{63}"
ORANGE = "{64}"
YELLOW = "{65}"
GREEN = "{66}"
BLUE = "{67}"
VIOLET = "{68}"
WHITE = "{69}"


def _parse_hhmm(value: str, default: str) -> tuple:
    raw = (value or default).strip().replace(".", ":")
    parts = raw.split(":")
    try:
        h = int(parts[0])
        m = int(parts[1]) if len(parts) > 1 else 0
        if not (0 <= h <= 23 and 0 <= m <= 59):
            raise ValueError
        return h, m
    except (ValueError, IndexError):
        dh, dm = default.replace(".", ":").split(":")
        return int(dh), int(dm)


def _in_monitor_window(start: str, end: str, now=None) -> bool:
    """True if local time is within start–end (default 07:30–23:45)."""
    try:
        from zoneinfo import ZoneInfo
        now = now or datetime.now(ZoneInfo("Europe/London"))
        if getattr(now, "tzinfo", None) is None:
            now = now.replace(tzinfo=ZoneInfo("Europe/London"))
    except Exception:
        now = now or datetime.now(timezone.utc)
    sh, sm = _parse_hhmm(start, "07:30")
    eh, em = _parse_hhmm(end, "23:45")
    cur = now.hour * 60 + now.minute
    s = sh * 60 + sm
    e = eh * 60 + em
    if s <= e:
        return s <= cur <= e
    return cur >= s or cur <= e


# Short replacements for status abridgment
_ABBREV = [
    (r"\boperation state\b", "state"),
    (r"\boperating\b", "run"),
    (r"\brun program\b", "prog"),
    (r"\bprogram\b", "prog"),
    (r"\bfinished\b", "done"),
    (r"\bready\b", "ready"),
    (r"\binactive\b", "off"),
    (r"\bactive\b", "on"),
    (r"\bdryer\b", "dryer"),
    (r"\bwashing machine\b", "washer"),
    (r"\bdishwasher\b", "dishwasher"),
    (r"\boven\b", "oven"),
    (r"\bfridge\b", "fridge"),
    (r"\brefrigerator\b", "fridge"),
    (r"\bcoffee\b", "coffee"),
    (r"\bhood\b", "hood"),
    (r"\bcooktop\b", "hob"),
    (r"\bremote control\b", "remote"),
    (r"\bdoor state\b", "door"),
    (r"\bopen\b", "open"),
    (r"\bclosed\b", "shut"),
    (r"\btemperature\b", "temp"),
    (r"\bremaining\b", "left"),
    (r"\bminutes?\b", "m"),
    (r"\bseconds?\b", "s"),
    (r"\bhours?\b", "h"),
    (r"\bpercent(age)?\b", "pct"),
    (r"\bnotification\b", "note"),
    (r"\berror\b", "err"),
    (r"\bwarning\b", "warn"),
]


def _tile_len(s: str) -> int:
    codes = re.findall(r"\{\d{2}\}", s)
    stripped = re.sub(r"\{\d{2}\}", "", s)
    return len(stripped) + len(codes)


def _pad(s: str, width: int = NOTE_WIDTH) -> str:
    return (s or "")[:width].ljust(width)


def _fernet_key() -> Optional[Any]:
    """Derive or load Fernet key for credential encryption."""
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        return None
    raw = (
        os.environ.get("HOME_CONNECT_FERNET_KEY")
        or os.environ.get("FIESTABOARD_SECRET_KEY")
        or ""
    ).strip()
    if raw:
        try:
            # Accept url-safe base64 key or passphrase
            if len(raw) == 44:
                return Fernet(raw.encode("utf-8"))
            digest = hashlib.sha256(raw.encode("utf-8")).digest()
            return Fernet(base64.urlsafe_b64encode(digest))
        except Exception:
            pass
    # Stable per-host fallback (not ideal for multi-host; document env key)
    digest = hashlib.sha256(b"fiestaboard-home-connect-v1").digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_secret(plain: str) -> str:
    if not plain:
        return ""
    if plain.startswith("enc:"):
        return plain
    f = _fernet_key()
    if f is not None:
        try:
            token = f.encrypt(plain.encode("utf-8")).decode("ascii")
            return "enc:" + token
        except Exception as e:
            logger.warning("encrypt failed: %s", e)
    # Fallback obfuscation (not strong crypto)
    mixed = base64.urlsafe_b64encode(plain.encode("utf-8")).decode("ascii")
    return "obf:" + mixed


def decrypt_secret(stored: str) -> str:
    if not stored:
        return ""
    if stored.startswith("enc:"):
        f = _fernet_key()
        if f is None:
            return ""
        try:
            return f.decrypt(stored[4:].encode("ascii")).decode("utf-8")
        except Exception as e:
            logger.warning("decrypt failed: %s", e)
            return ""
    if stored.startswith("obf:"):
        try:
            return base64.urlsafe_b64decode(stored[4:].encode("ascii")).decode("utf-8")
        except Exception:
            return ""
    return stored  # plaintext legacy


def abridge_status(text: str, max_len: int = NOTE_WIDTH) -> str:
    """Deterministic 'AI-style' abridgment for Vestaboard Note limits."""
    if not text:
        return ""
    s = re.sub(r"\s+", " ", str(text)).strip()
    # Drop vendor prefixes
    s = re.sub(r"^BSH\.Common\.(Status|Event|Option)\.", "", s, flags=re.I)
    s = re.sub(r"^Cooking\.\w+\.", "", s, flags=re.I)
    s = s.replace("_", " ").replace(".", " ")
    for pat, rep in _ABBREV:
        s = re.sub(pat, rep, s, flags=re.I)
    s = re.sub(r"\s+", " ", s).strip()
    # Title-ish short form
    if len(s) <= max_len:
        return s
    # Prefer cutting at space
    cut = s[: max_len + 1]
    if " " in cut:
        cut = cut.rsplit(" ", 1)[0]
    return cut[:max_len].strip()


def abridge_note_block(title: str, status: str, detail: str = "") -> Tuple[str, str, str, str]:
    """Build 15×3 Note rows from abridged parts."""
    t = abridge_status(title, 13).upper()
    st = abridge_status(status, 15)
    det = abridge_status(detail, 15) if detail else ""

    # Colour by status keyword
    low = (status + " " + detail).lower()
    if any(x in low for x in ("err", "error", "fault", "fail")):
        c1, c2 = RED, ORANGE
    elif any(x in low for x in ("run", "active", "on", "prog")):
        c1, c2 = GREEN, GREEN
    elif any(x in low for x in ("done", "finished", "ready")):
        c1, c2 = YELLOW, GREEN
    elif any(x in low for x in ("off", "inactive", "idle")):
        c1, c2 = BLUE, WHITE
    else:
        c1, c2 = VIOLET, BLUE

    body = (" " + t)[:13].ljust(13)
    r1 = f"{c1}{c2}{body}"
    while _tile_len(r1) > NOTE_WIDTH and len(body) > 0:
        body = body[:-1]
        r1 = f"{c1}{c2}{body.ljust(13)[:13]}"
    r2 = _pad(st.upper() if st else "—")
    r3 = _pad(det.upper() if det else "")
    block = f"{r1}\n{r2}\n{r3}"
    return block, r1, r2, r3


class HomeConnectPlugin(PluginBase):
    """Home Connect appliance status (max 5) for Vestaboard Note."""

    @property
    def plugin_id(self) -> str:
        return "home_connect"

    def validate_config(self, config: Dict[str, Any]) -> List[str]:
        errors: List[str] = []
        refresh = config.get("refresh_seconds", 300)
        if not isinstance(refresh, int) or refresh < 60:
            errors.append("refresh_seconds must be an integer >= 60 (default 300 = 5 minutes)")
        if "run_refresh_now" in config and not isinstance(config["run_refresh_now"], bool):
            errors.append("run_refresh_now must be a boolean")
        if "monitor_window_enabled" in config and not isinstance(
            config["monitor_window_enabled"], bool
        ):
            errors.append("monitor_window_enabled must be a boolean")
        for key, default in (("monitor_start", "07:30"), ("monitor_end", "23:45")):
            val = config.get(key, default)
            if not isinstance(val, str):
                errors.append(f"{key} must be HH:MM")
                continue
            try:
                _parse_hhmm(val, default)
            except Exception:
                errors.append(f"{key} must be HH:MM (e.g. 07:30)")
        return errors

    def on_config_change(self, old_config: Dict[str, Any], new_config: Dict[str, Any]) -> None:
        """Encrypt secrets on save; clear cache (supports Run refresh now)."""
        try:
            changed = False
            for key in ("password", "client_secret", "refresh_token"):
                val = new_config.get(key)
                if isinstance(val, str) and val and not val.startswith(("enc:", "obf:")):
                    new_config[key] = encrypt_secret(val)
                    changed = True
            if changed:
                self.config = dict(new_config)
            self.clear_cache()
        except Exception as e:
            logger.warning("on_config_change: %s", e)

    def _api_roots(self) -> Tuple[str, str]:
        if bool(self.config.get("use_simulator", False)):
            return SIM_API_HOST, SIM_TOKEN_URL
        return API_HOST, TOKEN_URL

    def _get_token(self) -> str:
        """OAuth2 token via refresh_token or password grant (if allowed)."""
        direct = decrypt_secret(str(self.config.get("access_token") or ""))
        if direct and not direct.startswith("enc:"):
            # Raw access token pasted by user
            if not str(self.config.get("access_token") or "").startswith(("enc:", "obf:")):
                return str(self.config.get("access_token") or direct)

        client_id = (self.config.get("client_id") or "").strip()
        client_secret = decrypt_secret(str(self.config.get("client_secret") or ""))
        refresh = decrypt_secret(str(self.config.get("refresh_token") or ""))
        user = (self.config.get("username") or "").strip()
        password = decrypt_secret(str(self.config.get("password") or ""))

        _, token_url = self._api_roots()

        def _token_request(body: Dict[str, str]) -> str:
            data = urllib.parse.urlencode(body).encode("utf-8")
            req = urllib.request.Request(
                token_url,
                data=data,
                method="POST",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": UA,
                },
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            token = payload.get("access_token") or ""
            if not token:
                raise RuntimeError(payload.get("error_description") or "no access_token")
            # Persist new refresh token if returned (caller may save)
            new_rt = payload.get("refresh_token")
            if new_rt:
                self.config["refresh_token"] = encrypt_secret(new_rt)
            return token

        if client_id and refresh:
            return _token_request(
                {
                    "grant_type": "refresh_token",
                    "refresh_token": refresh,
                    "client_id": client_id,
                    "client_secret": client_secret or "",
                }
            )

        if client_id and user and password:
            # Password grant — works on simulator / some setups; production prefers OAuth code flow
            return _token_request(
                {
                    "grant_type": "password",
                    "username": user,
                    "password": password,
                    "client_id": client_id,
                    "client_secret": client_secret or "",
                }
            )

        raise RuntimeError(
            "Configure client_id + refresh_token, or username/password, or access_token"
        )

    def _api_get(self, path: str, token: str) -> Dict[str, Any]:
        host, _ = self._api_roots()
        url = host.rstrip("/") + path
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.bsh.sdk.v1+json",
                "User-Agent": UA,
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _list_appliances(self, token: str) -> List[Dict[str, Any]]:
        data = self._api_get("/api/homeappliances", token)
        return list((data.get("data") or {}).get("homeappliances") or [])

    def _appliance_status(self, token: str, ha_id: str) -> List[Dict[str, Any]]:
        try:
            data = self._api_get(f"/api/homeappliances/{ha_id}/status", token)
            return list((data.get("data") or {}).get("status") or [])
        except Exception as e:
            logger.warning("status %s: %s", ha_id, e)
            return []

    def _pick_status_summary(self, items: List[Dict[str, Any]]) -> Tuple[str, str]:
        """Return (primary, detail) human strings from status keys."""
        by_key = {str(i.get("key") or ""): i for i in items}
        # Prefer operation state
        primary = ""
        detail = ""
        for key in (
            "BSH.Common.Status.OperationState",
            "BSH.Common.Status.DoorState",
            "BSH.Common.Status.RemoteControlActive",
        ):
            if key in by_key:
                val = by_key[key].get("displayvalue") or by_key[key].get("value") or ""
                name = key.split(".")[-1]
                if not primary:
                    primary = f"{name} {val}"
                else:
                    detail = f"{name} {val}"
                    break
        if not primary and items:
            it = items[0]
            primary = f"{it.get('key', '')} {it.get('displayvalue') or it.get('value') or ''}"
        if not detail and len(items) > 1:
            it = items[1]
            detail = f"{it.get('displayvalue') or it.get('value') or ''}"
        return str(primary), str(detail)

    def fetch_data(self) -> PluginResult:
        try:
            force = bool(self.config.get("run_refresh_now", False))
            start = str(self.config.get("monitor_start", "07:30") or "07:30")
            end = str(self.config.get("monitor_end", "23:45") or "23:45")
            window_enabled = bool(self.config.get("monitor_window_enabled", True))
            in_window = (not window_enabled) or _in_monitor_window(start, end)
            refresh_seconds = int(self.config.get("refresh_seconds", 300) or 300)

            # Outside monitoring window: skip live API unless forced
            if not in_window and not force:
                data = {
                    "appliance_count": "0",
                    "name": "Home",
                    "status": "outside hours",
                    "detail": f"{start}-{end}",
                    "monitor_window_active": "NO",
                    "monitor_start": start,
                    "monitor_end": end,
                    "run_refresh_now": "NO",
                    "refresh_seconds": str(refresh_seconds),
                    "refresh_mode": "OUTSIDE",
                    "suggested_refresh_seconds": str(refresh_seconds),
                    "last_updated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                }
                block, r1, r2, r3 = abridge_note_block("Home", "outside hours", f"{start}-{end}")
                data.update({
                    "note_row1": r1, "note_row2": r2, "note_row3": r3, "note_block": block,
                })
                for i in range(MAX_APPLIANCES):
                    data[f"appliance_{i+1}_name"] = ""
                    data[f"appliance_{i+1}_status"] = ""
                    data[f"appliance_{i+1}_detail"] = ""
                    data[f"appliance_{i+1}_note_block"] = ""
                    data[f"appliance_{i+1}_note_row1"] = ""
                    data[f"appliance_{i+1}_note_row2"] = ""
                    data[f"appliance_{i+1}_note_row3"] = ""
                return PluginResult(available=True, data=data)

            # Demo mode without credentials
            if bool(self.config.get("demo_mode", False)):
                data = self._demo_data()
                data["monitor_window_active"] = "YES" if in_window else "NO"
                data["monitor_start"] = start
                data["monitor_end"] = end
                data["run_refresh_now"] = "YES" if force else "NO"
                data["refresh_seconds"] = str(refresh_seconds)
                data["refresh_mode"] = "FORCED" if force else "ACTIVE"
                data["suggested_refresh_seconds"] = str(refresh_seconds)
                return PluginResult(available=True, data=data)

            token = self._get_token()
            appliances = self._list_appliances(token)
            # Optional name filter (comma-separated substrings)
            filt = (self.config.get("appliance_filter") or "").strip().lower()
            if filt:
                parts = [p.strip() for p in filt.split(",") if p.strip()]
                appliances = [
                    a
                    for a in appliances
                    if any(p in (a.get("name") or "").lower() or p in (a.get("type") or "").lower() for p in parts)
                ]

            appliances = appliances[:MAX_APPLIANCES]
            rows: List[Dict[str, str]] = []
            note_blocks: List[str] = []

            for idx, app in enumerate(appliances):
                ha_id = str(app.get("haId") or app.get("id") or "")
                name = str(app.get("name") or app.get("type") or f"App{idx+1}")
                connected = bool(app.get("connected", True))
                status_items = self._appliance_status(token, ha_id) if ha_id else []
                primary, detail = self._pick_status_summary(status_items)
                if not connected:
                    primary = "offline"
                    detail = detail or "disconnected"

                short_name = abridge_status(name, 13)
                short_status = abridge_status(primary, 15)
                short_detail = abridge_status(detail, 15)
                block, r1, r2, r3 = abridge_note_block(short_name, short_status, short_detail)
                note_blocks.append(block)

                rows.append(
                    {
                        "index": str(idx + 1),
                        "name": short_name[:20],
                        "name_full": name[:40],
                        "ha_id": ha_id[:40],
                        "type": abridge_status(str(app.get("type") or ""), 15),
                        "connected": "YES" if connected else "NO",
                        "status": short_status[:15],
                        "status_full": primary[:80],
                        "detail": short_detail[:15],
                        "note_row1": r1,
                        "note_row2": r2,
                        "note_row3": r3,
                        "note_block": block,
                    }
                )

            # Primary Note = first appliance (or empty state)
            if rows:
                primary = rows[0]
                data = {
                    "appliance_count": str(len(rows)),
                    "name": primary["name"],
                    "status": primary["status"],
                    "detail": primary["detail"],
                    "note_row1": primary["note_row1"],
                    "note_row2": primary["note_row2"],
                    "note_row3": primary["note_row3"],
                    "note_block": primary["note_block"],
                    "appliances": rows,
                    "last_updated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                }
                # Flatten appliance 1..5
                for i in range(MAX_APPLIANCES):
                    if i < len(rows):
                        a = rows[i]
                        data[f"appliance_{i+1}_name"] = a["name"]
                        data[f"appliance_{i+1}_status"] = a["status"]
                        data[f"appliance_{i+1}_detail"] = a["detail"]
                        data[f"appliance_{i+1}_note_block"] = a["note_block"]
                        data[f"appliance_{i+1}_note_row1"] = a["note_row1"]
                        data[f"appliance_{i+1}_note_row2"] = a["note_row2"]
                        data[f"appliance_{i+1}_note_row3"] = a["note_row3"]
                    else:
                        data[f"appliance_{i+1}_name"] = ""
                        data[f"appliance_{i+1}_status"] = ""
                        data[f"appliance_{i+1}_detail"] = ""
                        data[f"appliance_{i+1}_note_block"] = ""
                        data[f"appliance_{i+1}_note_row1"] = ""
                        data[f"appliance_{i+1}_note_row2"] = ""
                        data[f"appliance_{i+1}_note_row3"] = ""
            else:
                block, r1, r2, r3 = abridge_note_block("Home", "no devices", "check login")
                data = {
                    "appliance_count": "0",
                    "name": "Home",
                    "status": "no devices",
                    "detail": "check login",
                    "note_row1": r1,
                    "note_row2": r2,
                    "note_row3": r3,
                    "note_block": block,
                    "appliances": [],
                    "last_updated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                }
                for i in range(MAX_APPLIANCES):
                    data[f"appliance_{i+1}_name"] = ""
                    data[f"appliance_{i+1}_status"] = ""
                    data[f"appliance_{i+1}_detail"] = ""
                    data[f"appliance_{i+1}_note_block"] = ""
                    data[f"appliance_{i+1}_note_row1"] = ""
                    data[f"appliance_{i+1}_note_row2"] = ""
                    data[f"appliance_{i+1}_note_row3"] = ""

            data["username"] = (self.config.get("username") or "")[:40]
            data["monitor_window_active"] = "YES" if in_window else "NO"
            data["monitor_start"] = start
            data["monitor_end"] = end
            data["run_refresh_now"] = "YES" if force else "NO"
            data["refresh_seconds"] = str(refresh_seconds)
            data["refresh_mode"] = "FORCED" if force else "ACTIVE"
            data["suggested_refresh_seconds"] = str(refresh_seconds)
            return PluginResult(available=True, data=data)
        except Exception as e:
            logger.exception("home_connect error")
            block, r1, r2, r3 = abridge_note_block("Home", "error", abridge_status(str(e), 15))
            return PluginResult(
                available=False,
                error=str(e)[:120],
                data={
                    "note_row1": r1,
                    "note_row2": r2,
                    "note_row3": r3,
                    "note_block": block,
                    "status": "error",
                },
            )

    def _demo_data(self) -> Dict[str, Any]:
        samples = [
            ("Washer", "prog run", "42m left"),
            ("Dishwasher", "done", "door shut"),
            ("Oven", "off", ""),
            ("Dryer", "ready", ""),
            ("Fridge", "on", "3C"),
        ]
        rows = []
        for i, (name, st, det) in enumerate(samples):
            block, r1, r2, r3 = abridge_note_block(name, st, det)
            rows.append(
                {
                    "index": str(i + 1),
                    "name": name,
                    "name_full": name,
                    "ha_id": f"demo-{i}",
                    "type": name,
                    "connected": "YES",
                    "status": st,
                    "status_full": st,
                    "detail": det,
                    "note_row1": r1,
                    "note_row2": r2,
                    "note_row3": r3,
                    "note_block": block,
                }
            )
        data: Dict[str, Any] = {
            "appliance_count": "5",
            "name": rows[0]["name"],
            "status": rows[0]["status"],
            "detail": rows[0]["detail"],
            "note_row1": rows[0]["note_row1"],
            "note_row2": rows[0]["note_row2"],
            "note_row3": rows[0]["note_row3"],
            "note_block": rows[0]["note_block"],
            "appliances": rows,
            "username": "demo",
            "last_updated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        }
        for i in range(MAX_APPLIANCES):
            a = rows[i]
            data[f"appliance_{i+1}_name"] = a["name"]
            data[f"appliance_{i+1}_status"] = a["status"]
            data[f"appliance_{i+1}_detail"] = a["detail"]
            data[f"appliance_{i+1}_note_block"] = a["note_block"]
            data[f"appliance_{i+1}_note_row1"] = a["note_row1"]
            data[f"appliance_{i+1}_note_row2"] = a["note_row2"]
            data[f"appliance_{i+1}_note_row3"] = a["note_row3"]
        return data
