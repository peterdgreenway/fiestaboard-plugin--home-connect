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
UA = "FiestaBoard-HomeConnect/2.5 (+https://fiestaboard.app)"

# ---- Rate limit / cache (process memory; survives within container life) ----
_RATE_LIMIT: Dict[str, Any] = {
    "suspended_until": 0.0,  # unix time
    "last_429_message": "",
}
_TOKEN_CACHE: Dict[str, Any] = {
    "access_token": "",
    "expires_at": 0.0,  # unix time
}
_DATA_CACHE: Dict[str, Any] = {
    "fetched_at": 0.0,
    "data": None,  # last successful PluginResult data dict
    "fingerprint": "",
}
_DISCOVERY_CACHE: Dict[str, Any] = {
    "fetched_at": 0.0,
    "appliances": None,  # list of appliance dicts from API
}
_API_BUDGET: Dict[str, Any] = {
    "day_key": "",  # YYYY-MM-DD UTC
    "count": 0,
}
MIN_POLL_SECONDS = 300  # max full status poll once per 5 minutes
DISCOVERY_TTL_SECONDS = 6 * 3600  # re-list appliances at most every 6 hours
DAILY_API_BUDGET = 900  # hard stop before Home Connect's ~1000/day
TOKEN_REFRESH_SKEW = 120  # refresh access token 2 min before expiry


class HomeConnectRateLimitError(Exception):
    """HTTP 429 — daily or short-term rate limit."""

    def __init__(self, message: str, retry_after: int = 3600):
        super().__init__(message)
        self.retry_after = max(60, int(retry_after))


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


# 5-char type codes (no manufacturer name)
APPLIANCE_CODES = {
    "washingmachine": "WASHM",
    "dishwasher": "DWASH",
    "tumbledryer": "DRYER",
    "microwaveoven": "MWOVN",
    "coffeemaker": "COFFE",
    "refrigerator": "FRIDG",
    "warmingdrawer": "WDRAW",
    "cooktop": "INHOB",
    "inductionhob": "INHOB",
    "induction": "INHOB",
    "microwave": "MWOVN",
    "washer": "WASHM",
    "washing": "WASHM",
    "dryer": "DRYER",
    "dish": "DWASH",
    "oven": "MOVEN",
    "stove": "MOVEN",
    "hob": "INHOB",
    "coffee": "COFFE",
    "espresso": "COFFE",
    "fridge": "FRIDG",
    "freezer": "FREEZ",
    "hood": "HOODX",
    "ventilator": "HOODX",
    "drawer": "WDRAW",
}


def appliance_type_code(name: str, type_str: str = "") -> str:
    """Map appliance name/type to a 5-character code (no manufacturer).

    Microwave → MWOVN (never MOVEN). Main oven → MOVEN.
    """
    # Name wins for microwave so it never becomes MOVEN
    name_l = (name or "").lower()
    if "microwave" in name_l or "microwave" in (type_str or "").lower():
        return "MWOVN"

    # Direct API type enum (Home Connect)
    t = (type_str or "").strip().lower().replace(" ", "").replace("_", "")
    enum_map = {
        "washingmachine": "WASHM",
        "washer": "WASHM",
        "dryer": "DRYER",
        "dishwasher": "DWASH",
        "microwave": "MWOVN",
        "microwaveoven": "MWOVN",
        "oven": "MOVEN",
        "cookprocessor": "COOKP",
        "coffeemaker": "COFFE",
        "coffeemachine": "COFFE",
        "fridgefreezer": "FRIDG",
        "refrigerator": "FRIDG",
        "freezer": "FREEZ",
        "hob": "INHOB",
        "cooktop": "INHOB",
        "hood": "HOODX",
        "warmingdrawer": "WDRAW",
    }
    if t in enum_map:
        return enum_map[t]
    raw = f"{name} {type_str}".lower()
    raw = re.sub(r"[^a-z0-9]+", " ", raw)
    for brand in (
        "bosch", "siemens", "neff", "gaggenau", "balay", "constructa",
        "profilo", "thermador", "home", "connect",
    ):
        raw = re.sub(rf"\b{brand}\b", " ", raw)
    compact = re.sub(r"\s+", "", raw)
    # Longest keys first so microwaveoven wins over oven, dishwasher over washer
    keys = sorted(APPLIANCE_CODES.keys(), key=len, reverse=True)
    for key in keys:
        if key in compact:
            return APPLIANCE_CODES[key]
    # Token match
    tokens = set(raw.split())
    for key in keys:
        if key in tokens:
            return APPLIANCE_CODES[key]
    letters = re.sub(r"[^A-Z]", "", (name or type_str or "APPL").upper())
    return (letters + "XXXXX")[:5]


def _value_to_minutes(key: str, val: Any, disp: str = "") -> Optional[int]:
    """Convert Home Connect option/status value to whole minutes (round up)."""
    key_l = (key or "").lower()
    disp = str(disp or "")

    # Explicit display strings first (e.g. "1 h 5 min", "45 min")
    m = re.search(r"(\d+)\s*h(?:ours?)?\s*(\d+)?\s*m?", disp, re.I)
    if m:
        return int(m.group(1)) * 60 + int(m.group(2) or 0)
    m = re.search(r"(\d+)\s*m(?:in(?:ute)?s?)?", disp, re.I)
    if m and "remaining" in key_l or "finish" in key_l or "duration" in key_l or not key_l:
        if m:
            return int(m.group(1))

    try:
        n = float(val)
    except (TypeError, ValueError):
        m3 = re.search(r"(\d+)", disp)
        return int(m3.group(1)) if m3 else None

    # Home Connect RemainingProgramTime is almost always SECONDS
    if "remaining" in key_l or "finishin" in key_l:
        if "minute" in key_l and "second" not in key_l:
            return max(0, int(n + 0.999))
        # seconds → minutes, round up
        return max(0, int((n + 59) // 60)) if n >= 0 else None

    if "duration" in key_l or "elapsed" in key_l:
        if "minute" in key_l:
            return max(0, int(n + 0.999))
        return max(0, int((n + 59) // 60))

    # Unknown numeric: treat large as seconds, small as minutes
    if n >= 120:
        return max(0, int((n + 59) // 60))
    return max(0, int(n + 0.999))


def extract_remaining_minutes(
    items: Optional[list] = None,
    status_text: str = "",
) -> Optional[int]:
    """Harvest remaining program time from status/options keys (minutes, rounded up)."""
    priority_keys = (
        "remainingprogramtime",
        "remainingtime",
        "finishin",
        "startinrelative",
    )
    found: List[Tuple[int, int]] = []  # (priority, minutes)

    for item in items or []:
        if not isinstance(item, dict):
            continue
        key = str(item.get("key") or "")
        key_l = key.lower().replace(".", "").replace("_", "")
        val = item.get("value")
        disp = str(item.get("displayvalue") or item.get("displayValue") or "")
        if not any(
            x in key.lower()
            for x in ("remaining", "finishin", "duration", "elapsed", "progress")
        ):
            continue
        # Prefer remaining over duration/elapsed
        mins = _value_to_minutes(key, val, disp)
        if mins is None:
            continue
        if "elapsed" in key.lower():
            continue  # elapsed is not remaining
        pri = 0
        for i, pk in enumerate(priority_keys):
            if pk in key_l:
                pri = 10 - i
                break
        if "remaining" in key.lower():
            pri = max(pri, 5)
        found.append((pri, mins))

    if found:
        found.sort(key=lambda x: -x[0])
        return found[0][1]

    blob = status_text or ""
    m = re.search(r"(\d+)\s*h(?:our)?s?\s*(\d+)?\s*m?", blob, re.I)
    if m:
        return int(m.group(1)) * 60 + int(m.group(2) or 0)
    m = re.search(r"(\d+)\s*m(?:in)?", blob, re.I)
    if m:
        return int(m.group(1))
    return None


def extract_remaining_seconds(
    items: Optional[list] = None,
    status_text: str = "",
) -> Optional[int]:
    """Remaining program time in whole seconds (from API or minutes * 60)."""
    priority_keys = (
        "remainingprogramtime",
        "remainingtime",
        "finishin",
    )
    found: List[Tuple[int, int]] = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        key = str(item.get("key") or "")
        key_l = key.lower().replace(".", "").replace("_", "")
        if "elapsed" in key.lower():
            continue
        if not any(x in key.lower() for x in ("remaining", "finishin")):
            continue
        val = item.get("value")
        disp = str(item.get("displayvalue") or item.get("displayValue") or "")
        secs: Optional[int] = None
        try:
            n = float(val)
            if "minute" in key.lower() and "second" not in key.lower():
                secs = int(n * 60 + 0.999)
            else:
                # RemainingProgramTime is seconds
                secs = int(n + 0.999)
        except (TypeError, ValueError):
            mins = _value_to_minutes(key, val, disp)
            if mins is not None:
                secs = mins * 60
        if secs is None:
            continue
        pri = 0
        for i, pk in enumerate(priority_keys):
            if pk in key_l:
                pri = 10 - i
                break
        if "remaining" in key.lower():
            pri = max(pri, 5)
        found.append((pri, max(0, secs)))
    if found:
        found.sort(key=lambda x: -x[0])
        return found[0][1]
    mins = extract_remaining_minutes(items, status_text)
    if mins is not None:
        return mins * 60
    return None


def format_appliance_summary_line(
    code: str,
    is_on: bool,
    remaining_min: Optional[int],
) -> str:
    """e.g. {66}DWASH - 35mins  or  {63}MWOVN - OFF  (Note-friendly).

    1 minute → 'min'; more than 1 minute → 'mins'.
    """
    flap = GREEN if is_on else RED
    if is_on and remaining_min is not None and remaining_min >= 0:
        unit = "min" if remaining_min == 1 else "mins"
        body = f"{code} - {remaining_min}{unit}"
    elif is_on:
        body = f"{code} - ON"
    else:
        body = f"{code} - OFF"
    # 1 colour tile + text; keep total tiles <= 22 for variable use, Note uses 15
    line = f"{flap}{body}"
    # Prefer fitting 15 tiles for Note strip
    while _tile_len(line) > 15 and len(body) > 5:
        body = body[:-1]
        line = f"{flap}{body}"
    return line


def format_focus_note(
    code: str,
    is_on: bool,
    status: str,
    detail: str,
) -> Tuple[str, str, str, str]:
    """Single-appliance Note: L1 flap+type, L2+L3 abridged status (30 chars total)."""
    flap = GREEN if is_on else RED
    r1 = f"{flap}{code}"
    # pad row1 to visual width without exceeding 15 tiles
    while _tile_len(r1) < 15:
        r1 = r1 + " "
    r1 = r1 if _tile_len(r1) <= 15 else f"{flap}{code}"[:20]
    while _tile_len(r1) > 15:
        r1 = r1[:-1]

    combined = abridge_status(f"{status} {detail}".strip(), 30)
    if len(combined) <= 15:
        r2 = _pad(combined.upper())
        r3 = _pad("")
    else:
        # split across two lines at space if possible
        cut = combined[:15]
        if " " in cut:
            left = cut.rsplit(" ", 1)[0]
            rest = combined[len(left):].strip()
        else:
            left = combined[:15]
            rest = combined[15:30]
        r2 = _pad(left.upper())
        r3 = _pad(abridge_status(rest, 15).upper())
    block = f"{r1}\n{r2}\n{r3}"
    return block, r1, r2, r3


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



def build_api_usage_dashboard(
    calls: int,
    limit: int,
    remaining: int,
    suspended: bool,
    cache_age: str = "",
    discovery_age: str = "",
) -> Dict[str, str]:
    """Note-friendly API usage dashboard fields."""
    calls = max(0, int(calls))
    limit = max(1, int(limit))
    remaining = max(0, int(remaining))
    pct = min(100, int(round(100.0 * calls / limit)))
    # Colour: green under 70%, yellow 70–89%, red 90%+ or suspended
    if suspended or pct >= 90:
        flap, flap_name = RED, "red"
    elif pct >= 70:
        flap, flap_name = YELLOW, "yellow"
    else:
        flap, flap_name = GREEN, "green"

    # Row1: flap + API + pct
    r1_body = f" API {pct}%"
    r1 = f"{flap}{r1_body}"
    while _tile_len(r1) > 15 and len(r1_body) > 4:
        r1_body = r1_body[:-1]
        r1 = f"{flap}{r1_body}"

    r2 = _pad(f"{calls}/{limit}")
    if suspended:
        r3 = _pad("SUSPENDED")
        status = "SUSPENDED"
    else:
        r3 = _pad(f"{remaining} LEFT")
        status = "OK" if pct < 90 else "HIGH"

    block = f"{r1}\n{r2}\n{r3}"
    return {
        "api_usage_note_row1": r1,
        "api_usage_note_row2": r2,
        "api_usage_note_row3": r3,
        "api_usage_note_block": block,
        "api_usage_percent": str(pct),
        "api_usage_status": status,
        "api_usage_indicator": flap,
        "api_usage_indicator_name": flap_name,
        "api_calls_today": str(calls),
        "api_budget_limit": str(limit),
        "api_budget_remaining": str(remaining),
    }

class HomeConnectPlugin(PluginBase):
    """Home Connect via Authorization Code Grant Flow."""

    @property
    def plugin_id(self) -> str:
        return "home_connect"

    def validate_config(self, config: Dict[str, Any]) -> List[str]:
        errors: List[str] = []
        refresh = config.get("refresh_seconds", 300)
        if not isinstance(refresh, int) or refresh < MIN_POLL_SECONDS:
            errors.append(
                f"refresh_seconds must be an integer >= {MIN_POLL_SECONDS} (5 minutes max frequency)"
            )
        for key in (
            "run_refresh_now",
            "monitor_window_enabled",
            "exchange_authorization_code",
            "get_oauth_tokens",
            "clear_stored_tokens",
            "debug_log_secrets",
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
                "refresh_token",
                "id_token",
                "access_token",
                "stored_refresh_token",
                "stored_access_token",
            ):
                val = new_config.get(key)
                if isinstance(val, str) and val and not val.startswith(("enc:", "obf:")):
                    new_config[key] = encrypt_secret(val)
            if bool(new_config.get("clear_stored_tokens", False)):
                new_config["stored_refresh_token"] = ""
                new_config["stored_access_token"] = ""
                new_config["refresh_token"] = ""
                new_config["id_token"] = ""
                new_config["access_token"] = ""
                new_config["authorization_code"] = ""
                new_config["clear_stored_tokens"] = False
                logger.info("Home Connect: stored tokens cleared")
            self.config = dict(new_config)
            self.clear_cache()
        except Exception as e:
            logger.warning("on_config_change: %s", e)


    @staticmethod
    def _redact_secret(value: str, keep: int = 6) -> str:
        """Safe preview for debug logs (not full token)."""
        if not value:
            return "(empty)"
        if len(value) <= keep * 2:
            return value[:2] + "…" + value[-2:] if len(value) > 4 else "****"
        return f"{value[:keep]}…{value[-keep:]} (len={len(value)})"

    def _prepare_credentials(self) -> Dict[str, str]:
        """Decrypt all secret settings for this refresh cycle (manual or automatic).

        Values are returned in plaintext for API use only; config stays encrypted at rest.
        Debug logs show redacted previews only (never full secrets).
        """
        secret_keys = (
            "fiestaboard_client_secret",
            "client_secret",
            "refresh_token",
            "id_token",
            "access_token",
            "stored_refresh_token",
            "stored_access_token",
        )
        out: Dict[str, str] = {}
        verbose = bool(self.config.get("debug_log_secrets", False))
        for key in secret_keys:
            raw = str(self.config.get(key) or "")
            if not raw:
                out[key] = ""
                logger.debug("Home Connect decrypt %s: (not set)", key)
                continue
            was_encrypted = raw.startswith(("enc:", "obf:"))
            plain = decrypt_secret(raw)
            out[key] = plain if plain is not None else ""
            if was_encrypted and not out[key]:
                logger.warning(
                    "Home Connect: failed to decrypt %s — check HOME_CONNECT_FERNET_KEY",
                    key,
                )
            elif verbose and out[key]:
                # Explicit opt-in: log more of the value for troubleshooting
                logger.debug(
                    "Home Connect decrypt %s [verbose]: stored=%s plain=%s",
                    key,
                    "encrypted" if was_encrypted else "plaintext",
                    out[key],
                )
            else:
                logger.debug(
                    "Home Connect decrypt %s: stored=%s plain=%s",
                    key,
                    "encrypted" if was_encrypted else "plaintext",
                    self._redact_secret(out[key]),
                )
        return out

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
        creds = getattr(self, "_creds", None) or self._prepare_credentials()
        fb_secret = (
            creds.get("fiestaboard_client_secret")
            or creds.get("client_secret")
            or ""
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
                payload = json.loads(resp.read().decode("utf-8"))
                # Token endpoint counts toward daily Home Connect budget
                try:
                    self._budget_consume(1)
                except Exception:
                    pass
                return payload
        except urllib.error.HTTPError as e:
            err = e.read().decode("utf-8", errors="replace")[:400]
            if e.code == 429:
                self._suspend_for_429(3600, err)
                raise HomeConnectRateLimitError(err, retry_after=3600) from e
            raise RuntimeError(f"Token request failed: {e.code} {err}") from e

    def _persist_tokens(self, payload: Dict[str, Any]) -> str:
        access = payload.get("access_token") or ""
        refresh = payload.get("refresh_token") or ""
        id_tok = payload.get("id_token") or ""
        if access:
            enc = encrypt_secret(access)
            self.config["stored_access_token"] = enc
            self.config["access_token"] = enc
        if refresh:
            enc = encrypt_secret(refresh)
            self.config["stored_refresh_token"] = enc
            self.config["refresh_token"] = enc
        if id_tok:
            self.config["id_token"] = encrypt_secret(id_tok)
        if not access:
            raise RuntimeError(
                payload.get("error_description") or payload.get("error") or "no access_token"
            )
        # Clear one-time code / button flags after success
        self.config["authorization_code"] = ""
        self.config["exchange_authorization_code"] = False
        self.config["get_oauth_tokens"] = False
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

    def _token_from_config(self, *keys: str) -> str:
        """First non-empty decrypted token among setting keys (user field then stored)."""
        creds = getattr(self, "_creds", None)
        for key in keys:
            if creds is not None and creds.get(key):
                return creds[key]
            raw = str(self.config.get(key) or "")
            plain = decrypt_secret(raw) if raw else ""
            if plain and not plain.startswith(("enc:", "obf:")):
                return plain
            if raw and not raw.startswith(("enc:", "obf:")):
                return raw.strip()
        return ""

    def _get_token(self) -> str:
        """Resolve API bearer token.

        Priority when manual tokens are set:
          1) refresh_token → exchange for access_token
          2) id_token (used as Bearer if no refresh path)
          3) access_token
        Then: authorization code exchange, stored tokens, authorize URL error.

        Always decrypts secrets first via _prepare_credentials().
        """
        self._creds = self._prepare_credentials()
        _, fb_id, fb_secret = self._client_ids()

        # --- 1) refresh_token (user-entered or stored) ---
        refresh = self._token_from_config("refresh_token", "stored_refresh_token")
        if refresh:
            body = {
                "grant_type": "refresh_token",
                "refresh_token": refresh,
                "client_id": fb_id or "",
            }
            if fb_secret:
                body["client_secret"] = fb_secret
            if fb_id:
                try:
                    access = self._persist_tokens(self._token_request(body))
                    # Keep user refresh_token field in sync if rotated
                    return access
                except Exception as e:
                    logger.warning("refresh_token exchange failed: %s", e)
            else:
                logger.warning("refresh_token set but Fiestaboard Client ID missing")

        # --- authorization code / Get tokens via OAuth button ---
        get_tokens = bool(self.config.get("get_oauth_tokens", False))
        exchange = bool(self.config.get("exchange_authorization_code", False))
        has_code = bool((self.config.get("authorization_code") or "").strip())
        if (get_tokens or exchange) and has_code:
            return self._exchange_authorization_code()
        if has_code and not refresh:
            return self._exchange_authorization_code()

        # --- 2) id_token ---
        id_tok = self._token_from_config("id_token")
        if id_tok:
            logger.info("Home Connect: using id_token as Bearer (priority 2)")
            return id_tok

        # --- 3) access_token (user-entered or stored) ---
        access = self._token_from_config("access_token", "stored_access_token")
        if access:
            return access

        auth_url = self.build_authorize_url()
        if bool(self.config.get("get_oauth_tokens", False)):
            raise RuntimeError(
                "Get tokens via OAuth: open authorize_url, log in, paste code into "
                "Authorization code, then Save again with Get tokens ON. "
                + (auth_url or "Set Fiestaboard Client ID first.")
            )
        raise RuntimeError(
            "Not authorized. Enter refresh_token, id_token, or access_token, "
            "or use Get tokens via OAuth. "
            + (auth_url or "(set Client ID first)")
        )

    def _rate_limit_active(self) -> bool:
        return time.time() < float(_RATE_LIMIT.get("suspended_until") or 0)

    def _suspend_for_429(self, retry_after: int, message: str = "") -> None:
        wait = max(60, int(retry_after))
        # Daily limit: back off until next UTC midnight + small buffer if message says 1 day
        low = (message or "").lower()
        if "1 day" in low or "1000" in low or "daily" in low:
            # Suspend until next UTC midnight
            now = time.time()
            # seconds until next UTC midnight
            gm = time.gmtime(now)
            elapsed = gm.tm_hour * 3600 + gm.tm_min * 60 + gm.tm_sec
            wait = max(wait, 86400 - elapsed + 60)
        _RATE_LIMIT["suspended_until"] = time.time() + wait
        _RATE_LIMIT["last_429_message"] = (message or "")[:200]
        logger.warning(
            "Home Connect rate limited — suspending API calls for %ss until %s",
            wait,
            time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(_RATE_LIMIT["suspended_until"])),
        )

    def _budget_day_key(self) -> str:
        return time.strftime("%Y-%m-%d", time.gmtime())

    def _budget_remaining(self) -> int:
        key = self._budget_day_key()
        if _API_BUDGET.get("day_key") != key:
            _API_BUDGET["day_key"] = key
            _API_BUDGET["count"] = 0
        return max(0, DAILY_API_BUDGET - int(_API_BUDGET.get("count") or 0))

    def _budget_consume(self, n: int = 1) -> None:
        key = self._budget_day_key()
        if _API_BUDGET.get("day_key") != key:
            _API_BUDGET["day_key"] = key
            _API_BUDGET["count"] = 0
        _API_BUDGET["count"] = int(_API_BUDGET.get("count") or 0) + n
        logger.debug(
            "Home Connect API budget: %s/%s used (UTC day %s)",
            _API_BUDGET["count"],
            DAILY_API_BUDGET,
            key,
        )

    def _api_get(self, path: str, token: str) -> Dict[str, Any]:
        if self._rate_limit_active():
            raise HomeConnectRateLimitError(
                _RATE_LIMIT.get("last_429_message") or "rate limit suspension active",
                retry_after=max(1, int(_RATE_LIMIT["suspended_until"] - time.time())),
            )
        if self._budget_remaining() <= 0:
            # Suspend until next UTC midnight
            self._suspend_for_429(3600, "local daily API budget exhausted (900/day)")
            raise HomeConnectRateLimitError(
                "local daily API budget exhausted",
                retry_after=max(1, int(_RATE_LIMIT["suspended_until"] - time.time())),
            )
        host, _, _ = self._api_roots()
        req = urllib.request.Request(
            host.rstrip("/") + path,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.bsh.sdk.v1+json",
                "User-Agent": UA,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                self._budget_consume(1)
                return body
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")[:500]
            if e.code == 429:
                retry_after = 3600
                if e.headers and e.headers.get("Retry-After"):
                    try:
                        retry_after = int(e.headers.get("Retry-After"))
                    except ValueError:
                        pass
                self._suspend_for_429(retry_after, body)
                raise HomeConnectRateLimitError(body or "HTTP 429", retry_after=retry_after) from e
            raise RuntimeError(f"API {path} HTTP {e.code}: {body}") from e

    def _list_appliances(self, token: str, force: bool = False) -> List[Dict[str, Any]]:
        """Return appliances; cache discovery for DISCOVERY_TTL_SECONDS (default 6h)."""
        age = time.time() - float(_DISCOVERY_CACHE.get("fetched_at") or 0)
        cached = _DISCOVERY_CACHE.get("appliances")
        if (
            not force
            and cached is not None
            and age < DISCOVERY_TTL_SECONDS
        ):
            logger.debug(
                "Home Connect: discovery cache hit (%s appliances, age %ss)",
                len(cached),
                int(age),
            )
            return list(cached)
        data = self._api_get("/api/homeappliances", token)
        apps = list((data.get("data") or {}).get("homeappliances") or [])
        _DISCOVERY_CACHE["appliances"] = apps
        _DISCOVERY_CACHE["fetched_at"] = time.time()
        return list(apps)

    def _appliance_status(self, token: str, ha_id: str) -> List[Dict[str, Any]]:
        try:
            data = self._api_get(f"/api/homeappliances/{ha_id}/status", token)
            return list((data.get("data") or {}).get("status") or [])
        except Exception as e:
            logger.warning("status %s: %s", ha_id, e)
            return []

    def _operation_looks_active(self, status_items: List[Dict[str, Any]]) -> bool:
        for it in status_items or []:
            key = str(it.get("key") or "")
            val = str(it.get("displayvalue") or it.get("value") or "").lower()
            val = val.replace(" ", "").replace("_", "").replace(".", "")
            if "OperationState" in key or "operationstate" in key.lower():
                # Exact-ish state tokens (avoid "action" matching inside "Inactive")
                active_tokens = (
                    "run",
                    "running",
                    "active",
                    "delayedstart",
                    "pause",
                    "paused",
                    "actionrequired",
                    "hold",
                )
                inactive_tokens = (
                    "ready",
                    "inactive",
                    "idle",
                    "finished",
                    "finalize",
                    "off",
                )
                if any(t == val or val.endswith(t) or t in val for t in inactive_tokens):
                    if not any(t == val or val.endswith("." + t) for t in active_tokens):
                        # e.g. BSH.Common.EnumType.OperationState.Inactive
                        if "inactive" in val or "ready" in val or "finished" in val:
                            return False
                if any(
                    t in val
                    for t in (
                        "operationstate.run",
                        "operationstate.running",
                        "operationstate.active",
                        "operationstate.delayedstart",
                        "operationstate.pause",
                        "operationstate.actionrequired",
                        ".run",
                        ".running",
                        ".active",
                        ".delayedstart",
                        ".pause",
                        ".actionrequired",
                    )
                ):
                    return True
                if val in active_tokens or any(val.endswith(t) for t in active_tokens):
                    return True
                return False
        return False

    def _status_already_has_remaining(self, status_items: List[Dict[str, Any]]) -> bool:
        for it in status_items or []:
            key = str(it.get("key") or "").lower()
            if "remaining" in key:
                return True
        return False

    def _appliance_time_items(
        self,
        token: str,
        ha_id: str,
        status_items: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """Attach active-program options only when needed for remaining time.

        - Idle → status only (0 extra calls)
        - Active but remaining already on status → no program calls
        - Active and need remaining → 1× /programs/active (options embedded when present)
        """
        items: List[Dict[str, Any]] = []
        if status_items is None:
            status_items = self._appliance_status(token, ha_id)
        items.extend(status_items)
        if not self._operation_looks_active(status_items):
            return items
        if self._status_already_has_remaining(status_items):
            return items
        if self._budget_remaining() < 1:
            return items
        try:
            data = self._api_get(f"/api/homeappliances/{ha_id}/programs/active", token)
            prog = (data.get("data") or {}) if isinstance(data, dict) else {}
            opts = prog.get("options") or []
            if isinstance(opts, list):
                items.extend(opts)
            # Do NOT call /programs/active/options separately — avoids double call;
            # remaining time is almost always in active.options when present.
        except Exception as e:
            logger.debug("active program %s: %s", ha_id, e)
        return items

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
        has_refresh = bool(
            self._token_from_config("refresh_token", "stored_refresh_token")
        )
        has_id = bool(self._token_from_config("id_token"))
        has_access = bool(
            self._token_from_config("access_token", "stored_access_token")
        )
        if has_refresh:
            status = "AUTHORIZED"
        elif has_id:
            status = "ID_TOKEN"
        elif has_access:
            status = "ACCESS_ONLY"
        elif fb_id and fb_secret:
            status = "NEEDS_CODE"
        elif fb_id:
            status = "NEEDS_SECRET_OR_CODE"
        else:
            status = "NEEDS_CLIENT_ID"
        auth_url = self.build_authorize_url()
        if status in ("NEEDS_CODE", "NEEDS_SECRET_OR_CODE", "NEEDS_CLIENT_ID"):
            hint = "Open authorize_url, then paste code and use Get tokens via OAuth"
        elif status == "AUTHORIZED":
            hint = "Tokens stored — refresh_token active"
        else:
            hint = "Using token priority refresh > id > access"
        return {
            "oauth_flow": "authorization_code",
            "auth_status": status,
            "authorize_url": (auth_url or "")[:500],
            "redirect_uri": self._redirect_uri()[:120],
            "has_refresh_token": "YES" if has_refresh else "NO",
            "has_id_token": "YES" if has_id else "NO",
            "has_access_token": "YES" if has_access else "NO",
            "oauth_hint": hint[:80],
            "fiestaboard_client_id": (fb_id or "")[:40],
        }

    def fetch_data(self) -> PluginResult:
        try:
            # Decrypt secrets before manual refresh (run_refresh_now) or automated poll
            self._creds = self._prepare_credentials()

            force = bool(self.config.get("run_refresh_now", False))
            start = str(self.config.get("monitor_start", "07:30") or "07:30")
            end = str(self.config.get("monitor_end", "23:45") or "23:45")
            window_enabled = bool(self.config.get("monitor_window_enabled", True))
            in_window = (not window_enabled) or _in_monitor_window(start, end)
            refresh_seconds = int(self.config.get("refresh_seconds", 300) or 300)
            # Enforce maximum poll frequency: once per 5 minutes (unless forced)
            min_poll = max(MIN_POLL_SECONDS, refresh_seconds)
            refresh_seconds = max(refresh_seconds, MIN_POLL_SECONDS)

            meta = {
                **self._auth_meta(),
                "monitor_window_active": "YES" if in_window else "NO",
                "monitor_start": start,
                "monitor_end": end,
                "run_refresh_now": "YES" if force else "NO",
                "refresh_seconds": str(refresh_seconds),
                "suggested_refresh_seconds": str(refresh_seconds),
                "min_poll_seconds": str(MIN_POLL_SECONDS),
                "rate_limit_suspended": "YES" if self._rate_limit_active() else "NO",
                "discovery_cache_age": str(
                    int(time.time() - float(_DISCOVERY_CACHE.get("fetched_at") or 0))
                    if _DISCOVERY_CACHE.get("fetched_at")
                    else ""
                ),
                "cache_age_seconds": str(
                    int(time.time() - float(_DATA_CACHE.get("fetched_at") or 0))
                    if _DATA_CACHE.get("fetched_at")
                    else ""
                ),
            }
            meta.update(
                build_api_usage_dashboard(
                    calls=int(_API_BUDGET.get("count") or 0),
                    limit=DAILY_API_BUDGET,
                    remaining=self._budget_remaining(),
                    suspended=self._rate_limit_active(),
                )
            )

            def _with_cache_flags(data: Dict[str, Any], *, from_cache: bool, stale: bool = False) -> Dict[str, Any]:
                data = dict(data)
                data.update(meta)
                data["data_from_cache"] = "YES" if from_cache else "NO"
                data["data_stale"] = "YES" if stale else "NO"
                if _DATA_CACHE.get("fetched_at"):
                    data["cache_fetched_at"] = time.strftime(
                        "%Y-%m-%d %H:%M:%S UTC",
                        time.gmtime(float(_DATA_CACHE["fetched_at"])),
                    )
                return data

            def _serve_cache(stale: bool = False, error: str = "") -> Optional[PluginResult]:
                cached = _DATA_CACHE.get("data")
                if not cached:
                    return None
                data = _with_cache_flags(cached, from_cache=True, stale=stale)
                if error:
                    data["api_warning"] = error[:120]
                return PluginResult(available=True, data=data)

            # Rate-limit suspension: never hit the API; show last good values
            if self._rate_limit_active() and not bool(self.config.get("get_oauth_tokens")):
                remaining = int(_RATE_LIMIT["suspended_until"] - time.time())
                msg = f"rate limited; retry in {remaining}s"
                cached = _serve_cache(stale=True, error=msg)
                if cached:
                    return cached
                block, r1, r2, r3 = abridge_note_block("Home", "rate limit", f"{remaining}s")
                return PluginResult(
                    available=True,
                    data={
                        **meta,
                        "name": "Home",
                        "status": "rate limit",
                        "detail": f"{remaining}s",
                        "note_row1": r1,
                        "note_row2": r2,
                        "note_row3": r3,
                        "note_block": block,
                        "data_from_cache": "NO",
                        "data_stale": "YES",
                        "api_warning": msg,
                    },
                )

            # Fresh cache within min_poll (skip network) unless Run refresh now / OAuth
            cache_age = time.time() - float(_DATA_CACHE.get("fetched_at") or 0)
            oauth_force = bool(
                self.config.get("get_oauth_tokens")
                or self.config.get("exchange_authorization_code")
            )
            if (
                not force
                and not oauth_force
                and _DATA_CACHE.get("data")
                and cache_age < min_poll
            ):
                logger.debug(
                    "Home Connect: serving cache (age %ss < min_poll %ss)",
                    int(cache_age),
                    min_poll,
                )
                return _serve_cache(stale=False)

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
            appliances = self._list_appliances(token, force=force)
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
                time_items = (
                    self._appliance_time_items(token, ha_id, status_items)
                    if ha_id
                    else list(status_items)
                )
                primary, detail = self._pick_status_summary(status_items)
                if not connected:
                    primary = "offline"
                type_raw = str(app.get("type") or "")
                # Prefer Home Connect type enum for coding (Microwave, Oven, …)
                code = appliance_type_code(name, type_raw)
                short_name = abridge_status(name, 13)
                short_status = abridge_status(primary, 15)
                short_detail = abridge_status(detail, 15)
                ind = status_indicator(short_status + " " + primary, connected)
                is_on = ind["indicator_label"] == "RUNNING" or (
                    connected
                    and ind["indicator"] == GREEN
                )
                # Treat RUNNING green as on; also active operation keywords
                low_st = (primary + " " + short_status).lower()
                is_on = connected and any(
                    x in low_st
                    for x in ("run", "active", "prog", "operating", "wash", "dry", "cook", "heat", "on")
                ) and not any(
                    x in low_st for x in ("off", "inactive", "ready", "idle", "finished", "done")
                )

                blob = f"{primary} {detail} {short_status} {short_detail}"
                remaining = extract_remaining_minutes(time_items, blob)
                if remaining is None:
                    remaining = extract_remaining_minutes(status_items, blob)
                remaining_secs = extract_remaining_seconds(time_items, blob)
                if remaining_secs is None:
                    remaining_secs = extract_remaining_seconds(status_items, blob)
                if remaining_secs is None and remaining is not None:
                    remaining_secs = remaining * 60

                summary_line = format_appliance_summary_line(code, is_on, remaining)
                focus_block, fr1, fr2, fr3 = format_focus_note(
                    code, is_on, short_status, short_detail
                )

                # Default note_block = focus (single appliance layout)
                r1, r2, r3, block = fr1, fr2, fr3, focus_block

                rows.append(
                    {
                        "index": str(idx + 1),
                        "name": short_name[:20],
                        "name_full": name[:40],
                        "code": code,
                        "ha_id": ha_id[:40],
                        "type": abridge_status(type_raw, 15),
                        "connected": "YES" if connected else "NO",
                        "is_on": "YES" if is_on else "NO",
                        "remaining_minutes": str(remaining) if remaining is not None else "",
                        "remaining_seconds": str(remaining_secs) if remaining_secs is not None else "",
                        "status": short_status[:15],
                        "status_full": primary[:80],
                        "detail": short_detail[:15],
                        "status_indicator": GREEN if is_on else RED,
                        "status_indicator_name": "green" if is_on else "red",
                        "status_indicator_label": "ON" if is_on else "OFF",
                        "status_indicator_pair": f"{GREEN}{GREEN}" if is_on else f"{RED}{RED}",
                        "summary_line": summary_line,
                        "note_row1": r1,
                        "note_row2": r2,
                        "note_row3": r3,
                        "note_block": block,
                        "focus_note_block": focus_block,
                        "focus_note_row1": fr1,
                        "focus_note_row2": fr2,
                        "focus_note_row3": fr3,
                    }
                )

            if rows:
                p0 = rows[0]
                # Multi-appliance summary strip (one line per device, joined)
                summaries = [r.get("summary_line") or "" for r in rows]
                board_summary = " | ".join(s for s in summaries if s)
                data = {
                    **meta,
                    "appliance_count": str(len(rows)),
                    "online_count": str(online),
                    "name": p0["name"],
                    "code": p0.get("code", ""),
                    "status": p0["status"],
                    "detail": p0["detail"],
                    "is_on": p0.get("is_on", ""),
                    "remaining_minutes": p0.get("remaining_minutes", ""),
                    "remaining_seconds": p0.get("remaining_seconds", ""),
                    "summary_line": p0.get("summary_line", ""),
                    "board_summary": board_summary[:200],
                    "status_indicator": p0.get("status_indicator", ""),
                    "status_indicator_name": p0.get("status_indicator_name", ""),
                    "status_indicator_label": p0.get("status_indicator_label", ""),
                    "status_indicator_pair": p0.get("status_indicator_pair", ""),
                    "note_row1": p0["note_row1"],
                    "note_row2": p0["note_row2"],
                    "note_row3": p0["note_row3"],
                    "note_block": p0["note_block"],
                    "focus_note_block": p0.get("focus_note_block", p0["note_block"]),
                    "focus_note_row1": p0.get("focus_note_row1", p0["note_row1"]),
                    "focus_note_row2": p0.get("focus_note_row2", p0["note_row2"]),
                    "focus_note_row3": p0.get("focus_note_row3", p0["note_row3"]),
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
            data = _with_cache_flags(data, from_cache=False, stale=False)
            _DATA_CACHE["data"] = dict(data)
            _DATA_CACHE["fetched_at"] = time.time()
            return PluginResult(available=True, data=data)

        except HomeConnectRateLimitError as e:
            logger.warning("Home Connect rate limit: %s", e)
            cached = _DATA_CACHE.get("data")
            if cached:
                data = dict(cached)
                data["data_from_cache"] = "YES"
                data["data_stale"] = "YES"
                data["api_warning"] = str(e)[:120]
                data["rate_limit_suspended"] = "YES"
                return PluginResult(available=True, data=data)
            block, r1, r2, r3 = abridge_note_block("Home", "rate limit", abridge_status(str(e), 15))
            return PluginResult(
                available=True,
                error=str(e)[:160],
                data={
                    "note_row1": r1,
                    "note_row2": r2,
                    "note_row3": r3,
                    "note_block": block,
                    "status": "rate limit",
                    "data_stale": "YES",
                },
            )
        except Exception as e:
            logger.exception("home_connect error")
            # Prefer last good appliance snapshot over hard failure
            cached = _DATA_CACHE.get("data")
            if cached and "Not authorized" not in str(e):
                data = dict(cached)
                data["data_from_cache"] = "YES"
                data["data_stale"] = "YES"
                data["api_warning"] = str(e)[:120]
                return PluginResult(available=True, data=data)
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
                data[f"appliance_{i+1}_code"] = a.get("code", "")
                data[f"appliance_{i+1}_status"] = a["status"]
                data[f"appliance_{i+1}_detail"] = a["detail"]
                data[f"appliance_{i+1}_is_on"] = a.get("is_on", "")
                data[f"appliance_{i+1}_remaining_minutes"] = a.get("remaining_minutes", "")
                data[f"appliance_{i+1}_remaining_seconds"] = a.get("remaining_seconds", "")
                data[f"appliance_{i+1}_summary_line"] = a.get("summary_line", "")
                data[f"appliance_{i+1}_note_block"] = a["note_block"]
                data[f"appliance_{i+1}_note_row1"] = a["note_row1"]
                data[f"appliance_{i+1}_note_row2"] = a["note_row2"]
                data[f"appliance_{i+1}_note_row3"] = a["note_row3"]
                data[f"appliance_{i+1}_focus_note_block"] = a.get("focus_note_block", a["note_block"])
                data[f"appliance_{i+1}_connected"] = a.get("connected", "")
                data[f"appliance_{i+1}_status_indicator"] = a.get("status_indicator", "")
                data[f"appliance_{i+1}_status_indicator_name"] = a.get("status_indicator_name", "")
                data[f"appliance_{i+1}_status_indicator_label"] = a.get("status_indicator_label", "")
                data[f"appliance_{i+1}_status_indicator_pair"] = a.get("status_indicator_pair", "")
            else:
                for suf in (
                    "name", "code", "status", "detail", "is_on", "remaining_minutes", "remaining_seconds",
                    "summary_line", "note_block", "note_row1", "note_row2", "note_row3",
                    "focus_note_block", "connected",
                    "status_indicator", "status_indicator_name",
                    "status_indicator_label", "status_indicator_pair",
                ):
                    data[f"appliance_{i+1}_{suf}"] = ""
        return data

    def _demo_data(self) -> Dict[str, Any]:
        samples = [
            ("Washing Machine", "Washer", "prog run", "42m left", True, 42),
            ("Dishwasher", "Dishwasher", "done", "door shut", False, None),
            ("Oven", "Oven", "off", "", False, None),
            ("Microwave Oven", "Microwave", "ready", "", False, None),
            ("Coffee Machine", "CoffeeMaker", "run", "3m left", True, 3),
        ]
        rows = []
        for i, (name, typ, st, det, is_on, mins) in enumerate(samples):
            code = appliance_type_code(name, typ)
            summary_line = format_appliance_summary_line(code, is_on, mins)
            focus_block, fr1, fr2, fr3 = format_focus_note(code, is_on, st, det)
            rows.append(
                {
                    "index": str(i + 1),
                    "name": abridge_status(name, 13),
                    "name_full": name,
                    "code": code,
                    "ha_id": f"demo-{i}",
                    "type": typ,
                    "connected": "YES",
                    "is_on": "YES" if is_on else "NO",
                    "remaining_minutes": str(mins) if mins is not None else "",
                    "remaining_seconds": str(mins * 60) if mins is not None else "",
                    "status": st,
                    "status_full": st,
                    "detail": det,
                    "status_indicator": GREEN if is_on else RED,
                    "status_indicator_name": "green" if is_on else "red",
                    "status_indicator_label": "ON" if is_on else "OFF",
                    "status_indicator_pair": f"{GREEN}{GREEN}" if is_on else f"{RED}{RED}",
                    "summary_line": summary_line,
                    "note_row1": fr1,
                    "note_row2": fr2,
                    "note_row3": fr3,
                    "note_block": focus_block,
                    "focus_note_block": focus_block,
                    "focus_note_row1": fr1,
                    "focus_note_row2": fr2,
                    "focus_note_row3": fr3,
                }
            )
        summaries = [r.get("summary_line") or "" for r in rows]
        data: Dict[str, Any] = {
            "appliance_count": "5",
            "online_count": "5",
            "name": rows[0]["name"],
            "code": rows[0].get("code", ""),
            "status": rows[0]["status"],
            "detail": rows[0]["detail"],
            "is_on": rows[0].get("is_on", ""),
            "remaining_minutes": rows[0].get("remaining_minutes", ""),
            "remaining_seconds": rows[0].get("remaining_seconds", ""),
            "summary_line": rows[0].get("summary_line", ""),
            "board_summary": " | ".join(summaries)[:200],
            "status_indicator": rows[0].get("status_indicator", ""),
            "status_indicator_name": rows[0].get("status_indicator_name", ""),
            "status_indicator_label": rows[0].get("status_indicator_label", ""),
            "status_indicator_pair": rows[0].get("status_indicator_pair", ""),
            "note_row1": rows[0]["note_row1"],
            "note_row2": rows[0]["note_row2"],
            "note_row3": rows[0]["note_row3"],
            "note_block": rows[0]["note_block"],
            "focus_note_block": rows[0].get("focus_note_block", ""),
            "focus_note_row1": rows[0].get("focus_note_row1", ""),
            "focus_note_row2": rows[0].get("focus_note_row2", ""),
            "focus_note_row3": rows[0].get("focus_note_row3", ""),
            "appliances": rows,
            "last_updated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        }
        return self._empty_appliances(data, rows)
