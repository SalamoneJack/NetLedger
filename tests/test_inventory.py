from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from netledger.config import ConfigError, InventorySource, settings_from_dict
from netledger.inventory import (
    DeviceFilter,
    device_dir,
    load_csv_inventory,
    load_netbox_inventory,
    load_yaml_inventory,
    resolve_credentials,
)


def write(path: Path, data: Any) -> Path:
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def test_group_inheritance_and_merge(tmp_path: Path) -> None:
    path = write(tmp_path / "inv.yaml", {
        "defaults": {"credentials": "tacacs", "optional_args": {"global_delay_factor": 2}},
        "groups": {
            "cisco": {"platform": "cisco_ios", "tags": ["cisco"], "optional_args": {"secret": "en"}},
            "core": {"groups": ["cisco"], "role": "core", "tags": ["critical"]},
        },
        "devices": [
            {"name": "sw1", "host": "10.0.0.1", "groups": ["core"], "tags": ["hq"], "optional_args": {"secret": "override"}},
            {"name": "fw1", "platform": "fortigate"},
            {"name": "off", "platform": "ios", "enabled": False},
        ],
    })
    devices = {d.name: d for d in load_yaml_inventory(path)}
    assert set(devices) == {"sw1", "fw1"}
    sw1 = devices["sw1"]
    assert sw1.platform == "ios"
    assert sw1.role == "core"
    assert sw1.groups == ["cisco", "core"]
    assert sw1.tags == ["cisco", "critical", "hq"]
    assert sw1.credentials == ["tacacs"]
    assert sw1.optional_args == {"global_delay_factor": 2, "secret": "override"}
    fw1 = devices["fw1"]
    assert fw1.platform == "fortios" and fw1.host == "fw1"


def test_devices_as_mapping_and_health_settings(tmp_path: Path) -> None:
    path = write(tmp_path / "inv.yaml", {"devices": {
        "r1": {"host": "r1.example.com", "platform": "junos", "health": {"thresholds": {"cpu": {"warning": 90}}}},
        "r2": {"platform": "eos", "health": False, "backup": "yes"},
    }})
    devices = {d.name: d for d in load_yaml_inventory(path)}
    assert devices["r1"].health is True
    assert devices["r1"].health_settings == {"thresholds": {"cpu": {"warning": 90}}}
    assert devices["r2"].health is False and devices["r2"].backup is True


@pytest.mark.parametrize(
    ("device", "message"),
    [
        ({"name": "x", "platform": "ios", "hots": "1.1.1.1"}, "unknown field"),
        ({"name": "x", "platform": "nonsense-os"}, "unknown platform 'nonsense-os'"),
        ({"name": "x"}, "missing 'platform'"),
        ({"platform": "ios"}, "missing 'name'"),
        ({"name": "x", "platform": "ios", "groups": ["missing"]}, "unknown group 'missing'"),
        ({"name": "x", "platform": "ios", "retrieve": ["running", "everything"]}, "retrieve accepts"),
        ({"name": "x", "platform": "ios", "port": "ssh"}, "'port' must be an integer"),
    ],
)
def test_invalid_devices(tmp_path: Path, device: dict[str, Any], message: str) -> None:
    path = write(tmp_path / "inv.yaml", {"devices": [device]})
    with pytest.raises(ConfigError, match=message):
        load_yaml_inventory(path)


def test_group_loop_detected(tmp_path: Path) -> None:
    path = write(tmp_path / "inv.yaml", {
        "groups": {"a": {"groups": ["b"]}, "b": {"groups": ["a"]}},
        "devices": [{"name": "x", "platform": "ios", "groups": ["a"]}],
    })
    with pytest.raises(ConfigError, match="inheritance loop"):
        load_yaml_inventory(path)


def test_unknown_platform_allowed_with_explicit_driver(tmp_path: Path) -> None:
    path = write(tmp_path / "inv.yaml", {"devices": [{"name": "s1", "platform": "sros", "driver": "sros"}]})
    device = load_yaml_inventory(path)[0]
    assert device.platform == "sros"
    assert device.driver_spec == "sros"
    assert device.platform_info.secrets == ()


def test_csv_inventory(tmp_path: Path) -> None:
    path = tmp_path / "devices.csv"
    path.write_text(
        "name,host,platform,site,tags,port,optional_args.secret,enabled\n"
        "core1,10.0.0.1,ios,hq,core;critical,2222,en,\n"
        "fw1,10.0.0.2,fortinet,dc1,,,,\n"
        "old,10.0.0.3,ios,hq,,,,false\n",
        encoding="utf-8",
    )
    devices = {d.name: d for d in load_csv_inventory(path, defaults={"credentials": "csv"})}
    assert set(devices) == {"core1", "fw1"}
    assert devices["core1"].tags == ["core", "critical"]
    assert devices["core1"].port == 2222
    assert devices["core1"].optional_args == {"secret": "en"}
    assert devices["fw1"].platform == "fortios"
    assert devices["fw1"].credentials == ["csv"]


def test_filters(tmp_path: Path) -> None:
    path = write(tmp_path / "inv.yaml", {"devices": [
        {"name": "hq-core1", "host": "10.0.0.1", "platform": "ios", "site": "hq", "tags": ["core"]},
        {"name": "hq-fw1", "host": "10.0.0.2", "platform": "fortios", "site": "hq"},
        {"name": "dc-leaf1", "host": "10.1.0.1", "platform": "eos", "site": "dc1", "tags": ["leaf"]},
    ]})
    devices = load_yaml_inventory(path)
    names = lambda f: [d.name for d in f.apply(devices)]  # noqa: E731
    assert names(DeviceFilter(names=["hq-*"])) == ["hq-core1", "hq-fw1"]
    assert names(DeviceFilter(names=["10.1.*"])) == ["dc-leaf1"]
    assert names(DeviceFilter(sites=["HQ"], platforms=["fortigate"])) == ["hq-fw1"]
    assert names(DeviceFilter(tags=["core", "leaf"])) == ["hq-core1", "dc-leaf1"]
    assert not DeviceFilter()
    assert len(DeviceFilter().apply(devices)) == 3


def test_device_dir_templates_and_sanitizing(tmp_path: Path) -> None:
    path = write(tmp_path / "inv.yaml", {"devices": [
        {"name": "sw:1?", "platform": "ios", "site": "New York", "groups": []},
        {"name": "con", "platform": "fortios"},
    ]})
    devices = load_yaml_inventory(path)
    git = settings_from_dict({"git": {"backend": "local", "path": "{site}/{vendor}/{name}"}}).git
    assert device_dir(devices[0], git) == "configs/New York/cisco/sw_1_"
    assert device_dir(devices[1], git) == "configs/unassigned/fortinet/_con"
    flat = settings_from_dict({"git": {"backend": "local", "base_dir": "", "path": "{name}"}}).git
    assert device_dir(devices[1], flat) == "_con"


def test_resolve_credentials_order_and_errors(tmp_path: Path) -> None:
    settings = settings_from_dict({"credentials": {
        "tacacs": {"username": "t", "password": "tp"},
        "local": {"username": "l", "password": "lp", "secret": "en"},
    }})
    path = write(tmp_path / "inv.yaml", {"devices": [
        {"name": "a", "platform": "ios", "credentials": ["tacacs", "local"], "secret": "dev-enable"},
        {"name": "b", "platform": "ios", "username": "inline", "password": "x", "credentials": "missing"},
        {"name": "c", "platform": "ios", "credentials": "missing"},
    ]})
    a, b, c = load_yaml_inventory(path)
    creds = resolve_credentials(a, settings)
    assert [cr.username for cr in creds] == ["t", "l"]
    assert creds[0].secret == "dev-enable" and creds[1].secret == "en"
    assert [cr.username for cr in resolve_credentials(b, settings)] == ["inline"]
    with pytest.raises(ConfigError, match="credential set 'missing' is not defined"):
        resolve_credentials(c, settings)


def test_netbox_source(monkeypatch: pytest.MonkeyPatch) -> None:
    pages = {
        "https://netbox.example.com/api/dcim/devices/": {
            "next": "https://netbox.example.com/api/dcim/devices/?offset=2",
            "results": [
                {"name": "nb-core1", "primary_ip": {"address": "10.9.0.1/24"}, "platform": {"slug": "cisco-ios-xe"},
                 "site": {"slug": "hq", "name": "HQ"}, "role": {"slug": "core"}, "tags": [{"slug": "backup"}],
                 "config_context": {"netledger": {"port": 2222}}},
                {"name": "nb-unknown", "platform": {"slug": "toaster"}},
            ],
        },
        "https://netbox.example.com/api/dcim/devices/?offset=2": {
            "next": None,
            "results": [{"name": "nb-fw1", "primary_ip4": {"address": "10.9.0.2/32"}, "platform": {"slug": "fortios"},
                         "site": {"slug": "dc1"}, "device_role": {"slug": "firewall"}, "tags": []}],
        },
    }
    calls = []

    class FakeResponse:
        def __init__(self, data: dict[str, Any]):
            self.data = data

        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict[str, Any]:
            return self.data

    def fake_get(self: Any, url: str, params: Any = None, timeout: Any = None, verify: Any = None) -> FakeResponse:
        calls.append((url, params, self.headers.get("Authorization")))
        return FakeResponse(pages[url])

    monkeypatch.setattr("requests.Session.get", fake_get)
    source = InventorySource(
        type="netbox", url="https://netbox.example.com/", token="t0ken",
        platform_map={"cisco-ios-xe": "ios"}, defaults={"credentials": "nb", "tags": ["netbox"]},
    )
    devices = {d.name: d for d in load_netbox_inventory(source)}
    assert set(devices) == {"nb-core1", "nb-fw1"}
    core = devices["nb-core1"]
    assert (core.host, core.platform, core.site, core.role, core.port) == ("10.9.0.1", "ios", "hq", "core", 2222)
    assert core.tags == ["netbox", "backup"] and core.credentials == ["nb"]
    assert devices["nb-fw1"].role == "firewall"
    assert calls[0][1]["status"] == "active" and calls[0][2] == "Token t0ken"
    assert calls[1][1] is None
