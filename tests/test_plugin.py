import importlib.util
import sys
from pathlib import Path
from types import ModuleType

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
    plain = "s3cret-password"
    enc = mod.encrypt_secret(plain)
    assert enc.startswith("enc:") or enc.startswith("obf:")
    assert mod.decrypt_secret(enc) == plain


def test_abridge():
    s = mod.abridge_status("BSH.Common.Status.OperationState Run Program", 15)
    assert len(s) <= 15
    assert s


def test_note_rows():
    block, r1, r2, r3 = mod.abridge_note_block("Washer", "prog run", "42m left")
    assert mod._tile_len(r1) <= 15
    assert len(r2) == 15
    assert len(r3) == 15


def test_demo_mode():
    p = mod.HomeConnectPlugin({})
    p.config = {"demo_mode": True, "refresh_seconds": 120}
    r = p.fetch_data()
    assert r.available
    assert r.data["appliance_count"] == "5"
    assert r.data["appliance_1_name"]
    assert mod._tile_len(r.data["note_row1"]) <= 15


def test_monitor_window():
    from datetime import datetime
    from zoneinfo import ZoneInfo
    tz = ZoneInfo("Europe/London")
    assert mod._in_monitor_window("07:30", "23:45", datetime(2026, 10, 29, 12, 0, tzinfo=tz))
    assert not mod._in_monitor_window("07:30", "23:45", datetime(2026, 10, 29, 7, 29, tzinfo=tz))
    assert mod._in_monitor_window("07:30", "23:45", datetime(2026, 10, 29, 23, 45, tzinfo=tz))
    assert not mod._in_monitor_window("07:30", "23:45", datetime(2026, 10, 29, 23, 46, tzinfo=tz))


def test_default_refresh_is_5_min():
    p = mod.HomeConnectPlugin({})
    assert p.validate_config({"refresh_seconds": 300}) == []
