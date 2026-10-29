"""Home Connect — appliance status for Vestaboard Note (up to 5 devices).

OAuth: Device Flow (as registered in the Home Connect developer portal).

Portal credentials (labels match Home Connect):
  - API Web Client ID
  - Fiestaboard Client ID
  - Fiestaboard Client Secret

Secrets are encrypted on save. Status text is abridged to Note limits.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from src.plugins.base import PluginBase, PluginResult

logger = logging.getLogger(__name__)

NOTE_WIDTH = 15
MAX_APPLIANCES = 5
UA = "FiestaBoard-HomeConnect/1.1 (+https://fiestaboard.app)"

API_HOST = "https://api.home-connect.com"
TOKEN_URL = "https://api.home-connect.com/security/oauth/token"
DEVICE_AUTH_URL = "https://api.home-connect.com/security/oauth/device_authorization"
SIM_API_HOST = "https://simulator.home-connect.com"
SIM_TOKEN_URL = "https://simulator.home-connect.com/security/oauth/token"
SIM_DEVICE_AUTH_URL = "https://simulator.home-connect.com/security/oauth/device_authorization"

DEFAULT_SCOPES = "IdentifyAppliance Monitor Control Settings"

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
    codes = re.findall(r"\{\d{2}\}", s)
    stripped = re.sub(r"\{\d{2}\}", "", s)
    return len(stripped) + len(codes)


def _pad(s: str, width: int = NOTE_WIDTH) -> str:
    return (s or "")[:width].ljust(width)


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
    return f"{r1}\n{r2}\n{r3}", r1, r2, r3


class HomeConnectPlugin(PluginBase):
    """Home Connect appliance status — Device Flow OAuth, portal-matched labels."""

    @property
    def plugin_id(self) -> str:
        return "home_connect"

    def validate_config(self, config: Dict[str, Any]) -> List[str]:
        errors: List[str] = []
        refresh = config.get("refresh_seconds", 300)
        if not isinstance(refresh, int) or refresh < 60:
            errors.append("refresh_seconds must be an integer >= 60 (default 300)")
        for key in ("run_refresh_now", "monitor_window_enabled", "start_device_flow"):
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
                "client_secret",  # legacy
                "password",
                "stored_refresh_token",
                "stored_access_token",
            ):
                val = new_config.get(key)
                if isinstance(val, str) and val and not val.startswith(("enc:", "obf:")):
                    new_config[key] = encrypt_secret(val)
            self.config = dict(new_config)
            self.clear_cache()
        except Exception as e:
            logger.warning("on_config_change: %s", e)

    def _api_roots(self) -> Tuple[str, str, str]:
        if bool(self.config.get("use_simulator", False)):
            return SIM_API_HOST, SIM_TOKEN_URL, SIM_DEVICE_AUTH_URL
        return API_HOST, TOKEN_URL, DEVICE_AUTH_URL

    def _client_ids(self) -> Tuple[str, str, str]:
        """Return (api_web_client_id, fiestaboard_client_id, fiestaboard_client_secret)."""
        # Prefer new labels; fall back to legacy keys
        api_web = (
            self.config.get("api_web_client_id")
            or self.config.get("client_id")
            or ""
        ).strip()
        fb_id = (
            self.config.get("fiestaboard_client_id")
            or self.config.get("client_id")
            or api_web
            or ""
        ).strip()
        fb_secret = decrypt_secret(
            str(
                self.config.get("fiestaboard_client_secret")
                or self.config.get("client_secret")
                or ""
            )
        )
        return api_web, fb_id, fb_secret

    def _token_request(self, body: Dict[str, str]) -> Dict[str, Any]:
        _, token_url, _ = self._api_roots()
        data = urllib.parse.urlencode({k: v for k, v in body.items() if v is not None}).encode(
            "utf-8"
        )
        req = urllib.request.Request(
            token_url,
            data=data,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": UA,
            },
        )
        with urllib.request.urlopen(req, timeout=45) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _persist_tokens(self, payload: Dict[str, Any]) -> str:
        access = payload.get("access_token") or ""
        refresh = payload.get("refresh_token") or ""
        if access:
            self.config["stored_access_token"] = encrypt_secret(access)
        if refresh:
            self.config["stored_refresh_token"] = encrypt_secret(refresh)
        if not access:
            raise RuntimeError(payload.get("error_description") or payload.get("error") or "no token")
        return access

    def _device_flow_login(self) -> str:
        """OAuth 2.0 Device Flow as registered for this Home Connect application."""
        api_web, fb_id, fb_secret = self._client_ids()
        client_id = fb_id or api_web
        if not client_id:
            raise RuntimeError(
                "Set Fiestaboard Client ID (and API Web Client ID if shown) from the portal"
            )

        _, _, device_url = self._api_roots()
        scope = (self.config.get("oauth_scopes") or DEFAULT_SCOPES).strip()
        body = {
            "client_id": client_id,
            "scope": scope,
        }
        if fb_secret:
            body["client_secret"] = fb_secret

        data = urllib.parse.urlencode(body).encode("utf-8")
        req = urllib.request.Request(
            device_url,
            data=data,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": UA,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=45) as resp:
                dev = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")[:300]
            raise RuntimeError(f"Device authorization failed: {e.code} {err_body}") from e

        device_code = dev.get("device_code")
        user_code = dev.get("user_code")
        verify_uri = (
            dev.get("verification_uri_complete")
            or dev.get("verification_uri")
            or "https://api.home-connect.com/security/oauth/device_verify"
        )
        interval = int(dev.get("interval") or 5)
        expires = int(dev.get("expires_in") or 300)

        if not device_code:
            raise RuntimeError(f"Device flow: no device_code in response: {dev}")

        # Surface codes for the operator (also returned in PluginResult data on timeout)
        self.config["_device_user_code"] = user_code or ""
        self.config["_device_verify_uri"] = verify_uri
        logger.info(
            "Home Connect Device Flow: visit %s and enter code %s",
            verify_uri,
            user_code,
        )

        deadline = time.time() + expires
        while time.time() < deadline:
            time.sleep(max(interval, 3))
            try:
                token_body = {
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code,
                    "client_id": client_id,
                }
                if fb_secret:
                    token_body["client_secret"] = fb_secret
                payload = self._token_request(token_body)
                return self._persist_tokens(payload)
            except urllib.error.HTTPError as e:
                err = e.read().decode("utf-8", errors="replace")
                try:
                    ej = json.loads(err)
                    code = ej.get("error") or ""
                except Exception:
                    code = err
                if "authorization_pending" in str(code) or e.code == 400 and "pending" in err:
                    continue
                if "slow_down" in str(code):
                    interval += 5
                    continue
                raise RuntimeError(f"Device flow token poll: {e.code} {err[:200]}") from e

        raise RuntimeError(
            f"Device flow timed out. Open {verify_uri} and enter code {user_code}, "
            "then enable Start device flow again."
        )

    def _get_token(self) -> str:
        """Access token via stored refresh, device flow, or legacy access token field."""
        api_web, fb_id, fb_secret = self._client_ids()
        client_id = fb_id or api_web

        # Explicit one-shot access token (optional)
        raw_access = decrypt_secret(str(self.config.get("stored_access_token") or ""))
        if raw_access and bool(self.config.get("prefer_stored_access_token", False)):
            return raw_access

        refresh = decrypt_secret(str(self.config.get("stored_refresh_token") or ""))
        if client_id and refresh:
            try:
                body = {
                    "grant_type": "refresh_token",
                    "refresh_token": refresh,
                    "client_id": client_id,
                }
                if fb_secret:
                    body["client_secret"] = fb_secret
                payload = self._token_request(body)
                return self._persist_tokens(payload)
            except Exception as e:
                logger.warning("refresh_token failed: %s", e)

        if bool(self.config.get("start_device_flow", False)):
            return self._device_flow_login()

        if raw_access:
            return raw_access

        raise RuntimeError(
            "Not authorized. Set API Web Client ID + Fiestaboard Client ID/Secret, "
            "then turn on 'Start Device Flow', Save, and complete login in the browser."
        )

    def _api_get(self, path: str, token: str) -> Dict[str, Any]:
        host, _, _ = self._api_roots()
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

    def fetch_data(self) -> PluginResult:
        try:
            force = bool(self.config.get("run_refresh_now", False))
            start = str(self.config.get("monitor_start", "07:30") or "07:30")
            end = str(self.config.get("monitor_end", "23:45") or "23:45")
            window_enabled = bool(self.config.get("monitor_window_enabled", True))
            in_window = (not window_enabled) or _in_monitor_window(start, end)
            refresh_seconds = int(self.config.get("refresh_seconds", 300) or 300)

            meta = {
                "monitor_window_active": "YES" if in_window else "NO",
                "monitor_start": start,
                "monitor_end": end,
                "run_refresh_now": "YES" if force else "NO",
                "refresh_seconds": str(refresh_seconds),
                "suggested_refresh_seconds": str(refresh_seconds),
                "oauth_flow": "device_flow",
                "device_user_code": str(self.config.get("_device_user_code") or "")[:32],
                "device_verify_uri": str(self.config.get("_device_verify_uri") or "")[:120],
            }

            if not in_window and not force:
                block, r1, r2, r3 = abridge_note_block("Home", "outside hours", f"{start}-{end}")
                data = {
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
                    "appliances": [],
                    "last_updated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                }
                for i in range(MAX_APPLIANCES):
                    for suf in ("name", "status", "detail", "note_block", "note_row1", "note_row2", "note_row3"):
                        data[f"appliance_{i+1}_{suf}"] = ""
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
            for idx, app in enumerate(appliances):
                ha_id = str(app.get("haId") or app.get("id") or "")
                name = str(app.get("name") or app.get("type") or f"App{idx+1}")
                connected = bool(app.get("connected", True))
                status_items = self._appliance_status(token, ha_id) if ha_id else []
                primary, detail = self._pick_status_summary(status_items)
                if not connected:
                    primary = "offline"
                short_name = abridge_status(name, 13)
                short_status = abridge_status(primary, 15)
                short_detail = abridge_status(detail, 15)
                block, r1, r2, r3 = abridge_note_block(short_name, short_status, short_detail)
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

            if rows:
                primary_row = rows[0]
                data = {
                    **meta,
                    "appliance_count": str(len(rows)),
                    "name": primary_row["name"],
                    "status": primary_row["status"],
                    "detail": primary_row["detail"],
                    "note_row1": primary_row["note_row1"],
                    "note_row2": primary_row["note_row2"],
                    "note_row3": primary_row["note_row3"],
                    "note_block": primary_row["note_block"],
                    "appliances": rows,
                    "refresh_mode": "FORCED" if force else "ACTIVE",
                    "last_updated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                }
            else:
                block, r1, r2, r3 = abridge_note_block("Home", "no devices", "check account")
                data = {
                    **meta,
                    "appliance_count": "0",
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
                    for suf in ("name", "status", "detail", "note_block", "note_row1", "note_row2", "note_row3"):
                        data[f"appliance_{i+1}_{suf}"] = ""

            _, fb_id, _ = self._client_ids()
            data["fiestaboard_client_id"] = (fb_id or "")[:40]
            return PluginResult(available=True, data=data)

        except Exception as e:
            logger.exception("home_connect error")
            block, r1, r2, r3 = abridge_note_block("Home", "error", abridge_status(str(e), 15))
            return PluginResult(
                available=False,
                error=str(e)[:160],
                data={
                    "note_row1": r1,
                    "note_row2": r2,
                    "note_row3": r3,
                    "note_block": block,
                    "status": "error",
                    "oauth_flow": "device_flow",
                    "device_user_code": str(self.config.get("_device_user_code") or "")[:32],
                    "device_verify_uri": str(self.config.get("_device_verify_uri") or "")[:120],
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
