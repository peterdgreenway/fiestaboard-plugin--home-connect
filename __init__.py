"""Home Connect — Vestaboard Note status for up to 5 appliances.

OAuth: Authorization Code Grant Flow (Home Connect developer portal default).

Portal credentials (labels match Home Connect):
  - API Web Client ID
  - Fiestaboard Client ID
  - Fiestaboard Client Secret

Also: encrypted secrets, refresh-now, 5‑minute default poll, monitor window
07:30–23:45, status abridgment, demo mode, auth status helpers.
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
MAX_APPLIANCES = 5
UA = "FiestaBoard-HomeConnect/2.1 (+https://fiestaboard.app)"

API_HOST = "https://api.home-connect.com"
AUTH_URL = "https://api.home-connect.com/security/oauth/authorize"
TOKEN_URL = "https://api.home-connect.com/security/oauth/token"
SIM_API_HOST = "https://simulator.home-connect.com"
SIM_AUTH_URL = "https://simulator.home-connect.com/security/oauth/authorize"
SIM_TOKEN_URL = "https://simulator.home-connect.com/security/oauth/token"

DEFAULT_SCOPES = "IdentifyAppliance Monitor Control Settings"
DEFAULT_REDIRECT = "http://localhost"

RED = "{63}"
ORANGE = "{64}"
YELLOW = "{65}"
GREEN = "{66}"
BLUE = "{67}"
VIOLET = "{68}"
WHITE = "{69}"

_ABBREV = [
    (r"\boperation state\b", "state"),
    (r"\boperating\b", "run"),
    (r"\brun program\b", "prog"),
    (r"\bprogram\b", "prog"),
    (r"\bfinished\b", "done"),
    (r"\bready\b", "ready"),
    (r"\binactive\b", "off"),
    (r"\bactive\b", "on"),
    (r"\bwashing machine\b", "washer"),
    (r"\bdishwasher\b", "dishwasher"),
    (r"\brefrigerator\b", "fridge"),
    (r"\btemperature\b", "temp"),
    (r"\bremaining\b", "left"),
    (r"\bminutes?\b", "m"),
    (r"\bnotification\b", "note"),
    (r"\berror\b", "err"),
]


def _tile_len(s: str) -> int:
    return len(re.sub(r"\{\d{2}\}", "", s)) + len(re.findall(r"\{\d{2}\}", s))


def _pad(s: str, width: int = NOTE_WIDTH) -> str:
    return (s or "")[:width].ljust(width)


def _parse_hhmm(value: str, default: str) -> Tuple[int, int]:
    raw = (value or default).strip().replace(".", ":")
    parts = raw.split(":")
    try:
        h, m = int(parts[0]), int(parts[1]) if len(parts) > 1 else 0
        if not (0 <= h <= 23 and 0 <= m <= 59):
            raise ValueError
        return h, m
    except (ValueError, IndexError):
        dh, dm = default.replace(".", ":").split(":")
        return int(dh), int(dm)


def _in_monitor_window(start: str, end: str, now=None) -> bool:
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
    s, e = sh * 60 + sm, eh * 60 + em
    if s <= e:
        return s <= cur <= e
    return cur >= s or cur <= e


def _fernet_key():
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
            if len(raw) == 44:
                return Fernet(raw.encode("utf-8"))
            digest = hashlib.sha256(raw.encode("utf-8")).digest()
            return Fernet(base64.urlsafe_b64encode(digest))
        except Exception:
            pass
    digest = hashlib.sha256(b"fiestaboard-home-connect-v1").digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_secret(plain: str) -> str:
    if not plain:
        return ""
    if plain.startswith(("enc:", "obf:")):
        return plain
    f = _fernet_key()
    if f is not None:
        try:
            return "enc:" + f.encrypt(plain.encode("utf-8")).decode("ascii")
        except Exception as e:
            logger.warning("encrypt failed: %s", e)
    return "obf:" + base64.urlsafe_b64encode(plain.encode("utf-8")).decode("ascii")


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
    return stored



def status_indicator(status: str, connected: bool = True) -> Dict[str, str]:
    """Colour + short label for appliance state (Vestaboard tiles).

    Running → green. Not running (including off/done/ready/offline) → red stop flap.
    """
    low = (status or "").lower()
    is_running = connected and any(
        x in low
        for x in ("run", "active", "prog", "operating", "wash", "dry", "cook", "heat")
    ) and not any(x in low for x in ("off", "inactive", "finished", "done", "ready", "idle"))

    if is_running:
        return {
            "indicator": GREEN,
            "indicator_name": "green",
            "indicator_label": "RUNNING",
            "indicator_pair": f"{GREEN}{GREEN}",
        }

    # Stop / not running → red flap
    if not connected or "offline" in low or "disconnect" in low:
        label = "OFFLINE"
    elif any(x in low for x in ("err", "error", "fault", "fail", "alarm")):
        label = "ERROR"
    elif any(x in low for x in ("done", "finished", "complete", "end")):
        label = "DONE"
    elif any(x in low for x in ("ready", "idle")):
        label = "READY"
    elif any(x in low for x in ("off", "inactive", "standby")):
        label = "OFF"
    else:
        label = "STOPPED"

    return {
        "indicator": RED,
        "indicator_name": "red",
        "indicator_label": label,
        "indicator_pair": f"{RED}{RED}",
    }

def abridge_status(text: str, max_len: int = NOTE_WIDTH) -> str:
    if not text:
        return ""
    s = re.sub(r"\s+", " ", str(text)).strip()
    s = re.sub(r"^BSH\.Common\.(Status|Event|Option)\.", "", s, flags=re.I)
    s = s.replace("_", " ").replace(".", " ")
    for pat, rep in _ABBREV:
        s = re.sub(pat, rep, s, flags=re.I)
    s = re.sub(r"\s+", " ", s).strip()
    if len(s) <= max_len:
        return s
    cut = s[: max_len + 1]
    if " " in cut:
        cut = cut.rsplit(" ", 1)[0]
    return cut[:max_len].strip()


def abridge_note_block(title: str, status: str, detail: str = "") -> Tuple[str, str, str, str]:
    t = abridge_status(title, 13).upper()
    st = abridge_status(status, 15)
    det = abridge_status(detail, 15) if detail else ""
    low = (status + " " + detail).lower()
    if any(x in low for x in ("err", "error", "fault", "fail")):
        c1, c2 = RED, ORANGE
    elif any(x in low for x in ("run", "active", "on", "prog")):
        c1, c2 = GREEN, GREEN
    elif any(x in low for x in ("done", "finished", "ready")):
        c1, c2 = YELLOW, GREEN
    elif any(x in low for x in ("off", "inactive", "idle", "auth")):
        c1, c2 = BLUE, WHITE
    else:
        c1, c2 = VIOLET, BLUE
    body = (" " + t)[:13].ljust(13)
    r1 = f"{c1}{c2}{body}"
    while _tile_len(r1) > NOTE_WIDTH and body:
        body = body[:-1]
        r1 = f"{c1}{c2}{body.ljust(13)[:13]}"
    return f"{r1}\n{_pad(st.upper() if st else '—')}\n{_pad(det.upper() if det else '')}", r1, _pad(st.upper() if st else "—"), _pad(det.upper() if det else "")


class HomeConnectPlugin(PluginBase):
    """Home Connect via Authorization Code Grant Flow."""

    @property
    def plugin_id(self) -> str:
        return "home_connect"

    def validate_config(self, config: Dict[str, Any]) -> List[str]:
        errors: List[str] = []
        refresh = config.get("refresh_seconds", 300)
        if not isinstance(refresh, int) or refresh < 60:
            errors.append("refresh_seconds must be an integer >= 60")
        for key in (
            "run_refresh_now",
            "monitor_window_enabled",
            "exchange_authorization_code",
            "clear_stored_tokens",
        ):
            if key in config and not isinstance(config[key], bool):
                errors.append(f"{key} must be a boolean")
        for key, default in (("monitor_start", "07:30"), ("monitor_end", "23:45")):
            val = config.get(key, default)
            if not isinstance(val, str):
                errors.append(f"{key} must be HH:MM")
            else:
                try:
                    _parse_hhmm(val, default)
                except Exception:
                    errors.append(f"{key} must be HH:MM")
        return errors

    def on_config_change(self, old_config: Dict[str, Any], new_config: Dict[str, Any]) -> None:
        try:
            for key in (
                "fiestaboard_client_secret",
                "client_secret",
                "stored_refresh_token",
                "stored_access_token",
            ):
                val = new_config.get(key)
                if isinstance(val, str) and val and not val.startswith(("enc:", "obf:")):
                    new_config[key] = encrypt_secret(val)
            if bool(new_config.get("clear_stored_tokens", False)):
                new_config["stored_refresh_token"] = ""
                new_config["stored_access_token"] = ""
                new_config["authorization_code"] = ""
                new_config["clear_stored_tokens"] = False
                logger.info("Home Connect: stored tokens cleared")
            self.config = dict(new_config)
            self.clear_cache()
        except Exception as e:
            logger.warning("on_config_change: %s", e)

    def _api_roots(self) -> Tuple[str, str, str]:
        if bool(self.config.get("use_simulator", False)):
            return SIM_API_HOST, SIM_AUTH_URL, SIM_TOKEN_URL
        return API_HOST, AUTH_URL, TOKEN_URL

    def _client_ids(self) -> Tuple[str, str, str]:
        api_web = (self.config.get("api_web_client_id") or self.config.get("client_id") or "").strip()
        fb_id = (
            self.config.get("fiestaboard_client_id")
            or self.config.get("client_id")
            or api_web
            or ""
        ).strip()
        fb_secret = decrypt_secret(
            str(self.config.get("fiestaboard_client_secret") or self.config.get("client_secret") or "")
        )
        return api_web, fb_id, fb_secret

    def _redirect_uri(self) -> str:
        return (self.config.get("redirect_uri") or DEFAULT_REDIRECT).strip() or DEFAULT_REDIRECT

    def _scopes(self) -> str:
        return (self.config.get("oauth_scopes") or DEFAULT_SCOPES).strip() or DEFAULT_SCOPES

    def build_authorize_url(self) -> str:
        """URL the user opens to log in and approve the app."""
        _, auth_url, _ = self._api_roots()
        _, fb_id, _ = self._client_ids()
        if not fb_id:
            return ""
        params = {
            "response_type": "code",
            "client_id": fb_id,
            "redirect_uri": self._redirect_uri(),
            "scope": self._scopes(),
        }
        return auth_url + "?" + urllib.parse.urlencode(params)

    def _token_request(self, body: Dict[str, str]) -> Dict[str, Any]:
        _, _, token_url = self._api_roots()
        data = urllib.parse.urlencode({k: v for k, v in body.items() if v}).encode("utf-8")
        req = urllib.request.Request(
            token_url,
            data=data,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": UA,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=45) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            err = e.read().decode("utf-8", errors="replace")[:400]
            raise RuntimeError(f"Token request failed: {e.code} {err}") from e

    def _persist_tokens(self, payload: Dict[str, Any]) -> str:
        access = payload.get("access_token") or ""
        refresh = payload.get("refresh_token") or ""
        if access:
            self.config["stored_access_token"] = encrypt_secret(access)
        if refresh:
            self.config["stored_refresh_token"] = encrypt_secret(refresh)
        if not access:
            raise RuntimeError(payload.get("error_description") or payload.get("error") or "no access_token")
        # Clear one-time code after success
        self.config["authorization_code"] = ""
        self.config["exchange_authorization_code"] = False
        return access

    def _exchange_authorization_code(self) -> str:
        """Authorization Code Grant — exchange ?code= for tokens."""
        _, fb_id, fb_secret = self._client_ids()
        code = (self.config.get("authorization_code") or "").strip()
        # Allow pasting full redirect URL
        if "code=" in code:
            qs = urllib.parse.urlparse(code)
            if not qs.query and code.startswith("http"):
                qs = urllib.parse.urlparse(code)
            parsed = urllib.parse.parse_qs(qs.query if qs.query else code.split("?", 1)[-1])
            code = (parsed.get("code") or [code])[0]
        if not fb_id or not code:
            raise RuntimeError(
                "Set Fiestaboard Client ID and paste the authorization code (or full redirect URL)"
            )
        body = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": fb_id,
            "redirect_uri": self._redirect_uri(),
        }
        if fb_secret:
            body["client_secret"] = fb_secret
        payload = self._token_request(body)
        return self._persist_tokens(payload)

    def _get_token(self) -> str:
        _, fb_id, fb_secret = self._client_ids()

        if bool(self.config.get("exchange_authorization_code", False)) or (
            (self.config.get("authorization_code") or "").strip()
            and not decrypt_secret(str(self.config.get("stored_refresh_token") or ""))
        ):
            if (self.config.get("authorization_code") or "").strip():
                return self._exchange_authorization_code()

        refresh = decrypt_secret(str(self.config.get("stored_refresh_token") or ""))
        if fb_id and refresh:
            body = {
                "grant_type": "refresh_token",
                "refresh_token": refresh,
                "client_id": fb_id,
            }
            if fb_secret:
                body["client_secret"] = fb_secret
            try:
                return self._persist_tokens(self._token_request(body))
            except Exception as e:
                logger.warning("refresh_token failed: %s", e)

        access = decrypt_secret(str(self.config.get("stored_access_token") or ""))
        if access:
            return access

        auth_url = self.build_authorize_url()
        raise RuntimeError(
            "Not authorized. Open authorize_url, log in, then paste the code and "
            "enable Exchange authorization code. URL: " + (auth_url or "(set Client ID first)")
        )

    def _api_get(self, path: str, token: str) -> Dict[str, Any]:
        host, _, _ = self._api_roots()
        req = urllib.request.Request(
            host.rstrip("/") + path,
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
        by_key = {str(i.get("key") or ""): i for i in items}
        primary = detail = ""
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
            detail = str(it.get("displayvalue") or it.get("value") or "")
        return str(primary), str(detail)

    def _auth_meta(self) -> Dict[str, str]:
        _, fb_id, fb_secret = self._client_ids()
        has_refresh = bool(decrypt_secret(str(self.config.get("stored_refresh_token") or "")))
        has_access = bool(decrypt_secret(str(self.config.get("stored_access_token") or "")))
        if has_refresh:
            status = "AUTHORIZED"
        elif has_access:
            status = "ACCESS_ONLY"
        elif fb_id and fb_secret:
            status = "NEEDS_CODE"
        elif fb_id:
            status = "NEEDS_SECRET_OR_CODE"
        else:
            status = "NEEDS_CLIENT_ID"
        return {
            "oauth_flow": "authorization_code",
            "auth_status": status,
            "authorize_url": self.build_authorize_url()[:500],
            "redirect_uri": self._redirect_uri()[:120],
            "has_refresh_token": "YES" if has_refresh else "NO",
            "fiestaboard_client_id": (fb_id or "")[:40],
        }

    def fetch_data(self) -> PluginResult:
        try:
            force = bool(self.config.get("run_refresh_now", False))
            start = str(self.config.get("monitor_start", "07:30") or "07:30")
            end = str(self.config.get("monitor_end", "23:45") or "23:45")
            window_enabled = bool(self.config.get("monitor_window_enabled", True))
            in_window = (not window_enabled) or _in_monitor_window(start, end)
            refresh_seconds = int(self.config.get("refresh_seconds", 300) or 300)
            meta = {
                **self._auth_meta(),
                "monitor_window_active": "YES" if in_window else "NO",
                "monitor_start": start,
                "monitor_end": end,
                "run_refresh_now": "YES" if force else "NO",
                "refresh_seconds": str(refresh_seconds),
                "suggested_refresh_seconds": str(refresh_seconds),
            }

            if not in_window and not force:
                block, r1, r2, r3 = abridge_note_block("Home", "outside hours", f"{start}-{end}")
                data = self._empty_appliances(
                    {
                        **meta,
                        "appliance_count": "0",
                        "name": "Home",
                        "status": "outside hours",
                        "detail": f"{start}-{end}",
                        "refresh_mode": "OUTSIDE",
                        "note_row1": r1,
                        "note_row2": r2,
                        "note_row3": r3,
                        "note_block": block,
                        "last_updated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                    }
                )
                return PluginResult(available=True, data=data)

            if bool(self.config.get("demo_mode", False)):
                data = self._demo_data()
                data.update(meta)
                data["refresh_mode"] = "FORCED" if force else "ACTIVE"
                return PluginResult(available=True, data=data)

            token = self._get_token()
            appliances = self._list_appliances(token)
            filt = (self.config.get("appliance_filter") or "").strip().lower()
            if filt:
                parts = [p.strip() for p in filt.split(",") if p.strip()]
                appliances = [
                    a
                    for a in appliances
                    if any(
                        p in (a.get("name") or "").lower() or p in (a.get("type") or "").lower()
                        for p in parts
                    )
                ]
            appliances = appliances[:MAX_APPLIANCES]

            rows: List[Dict[str, str]] = []
            online = 0
            for idx, app in enumerate(appliances):
                ha_id = str(app.get("haId") or app.get("id") or "")
                name = str(app.get("name") or app.get("type") or f"App{idx+1}")
                connected = bool(app.get("connected", True))
                if connected:
                    online += 1
                status_items = self._appliance_status(token, ha_id) if ha_id else []
                primary, detail = self._pick_status_summary(status_items)
                if not connected:
                    primary = "offline"
                short_name = abridge_status(name, 13)
                short_status = abridge_status(primary, 15)
                short_detail = abridge_status(detail, 15)
                ind = status_indicator(short_status + " " + primary, connected)
                block, r1, r2, r3 = abridge_note_block(short_name, short_status, short_detail)
                # Prefix Note row1 with status indicator colour pair (replace default pair)
                body = re.sub(r"^(\{\d{2}\}){1,2}", "", r1)
                r1 = f"{ind['indicator_pair']}{body}"
                while _tile_len(r1) > NOTE_WIDTH and body:
                    body = body[:-1]
                    r1 = f"{ind['indicator_pair']}{body}"
                block = f"{r1}\n{r2}\n{r3}"
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
                        "status_indicator": ind["indicator"],
                        "status_indicator_name": ind["indicator_name"],
                        "status_indicator_label": ind["indicator_label"],
                        "status_indicator_pair": ind["indicator_pair"],
                        "note_row1": r1,
                        "note_row2": r2,
                        "note_row3": r3,
                        "note_block": block,
                    }
                )

            if rows:
                p0 = rows[0]
                data = {
                    **meta,
                    "appliance_count": str(len(rows)),
                    "online_count": str(online),
                    "name": p0["name"],
                    "status": p0["status"],
                    "detail": p0["detail"],
                    "status_indicator": p0.get("status_indicator", ""),
                    "status_indicator_name": p0.get("status_indicator_name", ""),
                    "status_indicator_label": p0.get("status_indicator_label", ""),
                    "status_indicator_pair": p0.get("status_indicator_pair", ""),
                    "note_row1": p0["note_row1"],
                    "note_row2": p0["note_row2"],
                    "note_row3": p0["note_row3"],
                    "note_block": p0["note_block"],
                    "appliances": rows,
                    "refresh_mode": "FORCED" if force else "ACTIVE",
                    "last_updated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                }
            else:
                block, r1, r2, r3 = abridge_note_block("Home", "no devices", "check account")
                data = {
                    **meta,
                    "appliance_count": "0",
                    "online_count": "0",
                    "name": "Home",
                    "status": "no devices",
                    "detail": "check account",
                    "note_row1": r1,
                    "note_row2": r2,
                    "note_row3": r3,
                    "note_block": block,
                    "appliances": [],
                    "refresh_mode": "FORCED" if force else "ACTIVE",
                    "last_updated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                }

            data = self._empty_appliances(data, rows)
            return PluginResult(available=True, data=data)

        except Exception as e:
            logger.exception("home_connect error")
            msg = str(e)
            block, r1, r2, r3 = abridge_note_block("Home", "auth needed" if "Not authorized" in msg else "error", abridge_status(msg, 15))
            data = {
                **self._auth_meta(),
                "note_row1": r1,
                "note_row2": r2,
                "note_row3": r3,
                "note_block": block,
                "status": "error",
                "detail": abridge_status(msg, 40),
            }
            return PluginResult(available=False, error=msg[:200], data=data)

    def _empty_appliances(self, data: Dict[str, Any], rows: Optional[List[Dict]] = None) -> Dict[str, Any]:
        rows = rows or []
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
                data[f"appliance_{i+1}_connected"] = a.get("connected", "")
                data[f"appliance_{i+1}_status_indicator"] = a.get("status_indicator", "")
                data[f"appliance_{i+1}_status_indicator_name"] = a.get("status_indicator_name", "")
                data[f"appliance_{i+1}_status_indicator_label"] = a.get("status_indicator_label", "")
                data[f"appliance_{i+1}_status_indicator_pair"] = a.get("status_indicator_pair", "")
            else:
                for suf in (
                    "name", "status", "detail", "note_block",
                    "note_row1", "note_row2", "note_row3", "connected",
                    "status_indicator", "status_indicator_name",
                    "status_indicator_label", "status_indicator_pair",
                ):
                    data[f"appliance_{i+1}_{suf}"] = ""
        return data

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
            ind = status_indicator(st, True)
            block, r1, r2, r3 = abridge_note_block(name, st, det)
            body = re.sub(r"^(\{\d{2}\}){1,2}", "", r1)
            r1 = f"{ind['indicator_pair']}{body}"
            while _tile_len(r1) > NOTE_WIDTH and body:
                body = body[:-1]
                r1 = f"{ind['indicator_pair']}{body}"
            block = f"{r1}\n{r2}\n{r3}"
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
                    "status_indicator": ind["indicator"],
                    "status_indicator_name": ind["indicator_name"],
                    "status_indicator_label": ind["indicator_label"],
                    "status_indicator_pair": ind["indicator_pair"],
                    "note_row1": r1,
                    "note_row2": r2,
                    "note_row3": r3,
                    "note_block": block,
                }
            )
        data: Dict[str, Any] = {
            "appliance_count": "5",
            "online_count": "5",
            "name": rows[0]["name"],
            "status": rows[0]["status"],
            "detail": rows[0]["detail"],
            "status_indicator": rows[0].get("status_indicator", ""),
            "status_indicator_name": rows[0].get("status_indicator_name", ""),
            "status_indicator_label": rows[0].get("status_indicator_label", ""),
            "status_indicator_pair": rows[0].get("status_indicator_pair", ""),
            "note_row1": rows[0]["note_row1"],
            "note_row2": rows[0]["note_row2"],
            "note_row3": rows[0]["note_row3"],
            "note_block": rows[0]["note_block"],
            "appliances": rows,
            "last_updated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        }
        return self._empty_appliances(data, rows)
