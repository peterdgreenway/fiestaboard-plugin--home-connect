import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from datetime import datetime
from zoneinfo import ZoneInfo

fake = ModuleType("src.plugins.base")


class PluginBase:
    def __init__(self, manifest=None):
        self.manifest = manifest or {}
        self.config = {}

    def clear_cache(self):
        pass


class PluginResult:
    def __init__(self, available=True, data=None, error=None):
        self.available = available
        self.data = data or {}
        self.error = error


fake.PluginBase = PluginBase
fake.PluginResult = PluginResult
sys.modules.setdefault("src", ModuleType("src"))
sys.modules.setdefault("src.plugins", ModuleType("src.plugins"))
sys.modules["src.plugins.base"] = fake

spec = importlib.util.spec_from_file_location(
    "home_connect", Path(__file__).resolve().parent.parent / "__init__.py"
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def test_plugin_id():
    assert mod.HomeConnectPlugin({}).plugin_id == "home_connect"


def test_encrypt_roundtrip():
    enc = mod.encrypt_secret("secret")
    assert mod.decrypt_secret(enc) == "secret"


def test_abridge_and_note():
    assert len(mod.abridge_status("Operation State Run Program", 15)) <= 15
    _, r1, r2, r3 = mod.abridge_note_block("Washer", "prog run", "42m")
    assert mod._tile_len(r1) <= 15


def test_demo():
    p = mod.HomeConnectPlugin({})
    p.config = {"demo_mode": True, "refresh_seconds": 300}
    r = p.fetch_data()
    assert r.available and r.data["appliance_count"] == "5"


def test_monitor_window():
    tz = ZoneInfo("Europe/London")
    assert mod._in_monitor_window("07:30", "23:45", datetime(2026, 10, 29, 12, 0, tzinfo=tz))
    assert not mod._in_monitor_window("07:30", "23:45", datetime(2026, 10, 29, 7, 0, tzinfo=tz))


def test_client_id_labels():
    p = mod.HomeConnectPlugin({})
    p.config = {
        "api_web_client_id": "WEB123",
        "fiestaboard_client_id": "FB456",
        "fiestaboard_client_secret": mod.encrypt_secret("sec"),
    }
    api_web, fb_id, secret = p._client_ids()
    assert api_web == "WEB123"
    assert fb_id == "FB456"
    assert secret == "sec"
