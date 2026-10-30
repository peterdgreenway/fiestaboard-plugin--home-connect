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


def test_id():
    assert mod.HomeConnectPlugin({}).plugin_id == "home_connect"


def test_encrypt():
    assert mod.decrypt_secret(mod.encrypt_secret("x")) == "x"


def test_authorize_url():
    p = mod.HomeConnectPlugin({})
    p.config = {
        "fiestaboard_client_id": "ABC",
        "redirect_uri": "http://localhost",
    }
    url = p.build_authorize_url()
    assert "response_type=code" in url
    assert "client_id=ABC" in url
    assert "redirect_uri=" in url


def test_demo():
    p = mod.HomeConnectPlugin({})
    p.config = {"demo_mode": True}
    r = p.fetch_data()
    assert r.available and r.data["appliance_count"] == "5"
    assert r.data["oauth_flow"] == "authorization_code"


def test_window():
    tz = ZoneInfo("Europe/London")
    assert mod._in_monitor_window("07:30", "23:45", datetime(2026, 10, 29, 12, 0, tzinfo=tz))
