from __future__ import annotations

from typing import Any

import pytest

from netledger.config import settings_from_dict
from netledger.health import HealthCollected, HealthRunner, evaluate, memory_usage
from netledger.inventory import build_device, load_inventory
from netledger.state import StateStore

from .conftest import simulated


def device(**extra: Any):  # noqa: ANN201
    return build_device({"name": "sw1", "platform": "ios", **extra}, "test")


def env(**overrides: Any) -> dict[str, Any]:
    base = {
        "cpu": {0: {"%usage": 12.0}, 1: {"%usage": 30.0}},
        "memory": {"available_ram": 1000, "used_ram": 400},
        "temperature": {"Inlet": {"temperature": 31.0, "is_alert": False, "is_critical": False}},
        "fans": {"FAN 1": {"status": True}, "FAN 2": {"status": True}},
        "power": {"PS1": {"status": True, "capacity": -1, "output": -1}},
    }
    base.update(overrides)
    return base


def collected(**overrides: Any) -> HealthCollected:
    return HealthCollected(reachable=True, facts={"uptime": 86400.0}, env=env(**overrides), duration=0.4)


def test_all_ok() -> None:
    health = evaluate(device(), collected(), settings_from_dict({}))
    assert health.status == "ok"
    assert health.cpu == 30.0 and health.memory_pct == 40.0 and health.max_temperature == 31.0
    assert [c.name for c in health.checks] == ["reachability", "cpu", "memory", "temperature", "fans", "power"]


def test_thresholds_and_hardware_failures() -> None:
    settings = settings_from_dict({"health": {"thresholds": {"temperature": {"warning": 60, "critical": 80}}, "psu_failure": "critical"}})
    health = evaluate(device(), collected(
        cpu={0: {"%usage": 97.0}},
        memory={"available_ram": 1000, "used_ram": 870},
        temperature={"Inlet": {"temperature": 65.0, "is_alert": False, "is_critical": False}},
        fans={"FAN 1": {"status": True}, "2": {"status": False}},
        power={"PS1": {"status": True}, "PS2": {"status": False}},
    ), settings)
    checks = {c.name: c for c in health.checks}
    assert checks["cpu"].status == "critical" and "(>= 95%)" in checks["cpu"].message
    assert checks["memory"].status == "warning"
    assert checks["temperature"].status == "warning"
    assert checks["fans"].status == "warning" and checks["fans"].message == "Fan 2 failed (1 of 2 OK)"
    assert checks["power"].status == "critical" and checks["power"].message.startswith("PS2 failed")
    assert health.status == "critical"


def test_device_flags_overrides_and_ignored_sensors() -> None:
    dev = device(health={"thresholds": {"cpu": {"warning": 99, "critical": 100}}, "ignore_sensors": ["^PS2"]})
    health = evaluate(dev, collected(
        cpu={0: {"%usage": 97.0}},
        temperature={"HotSpot": {"temperature": 44.0, "is_alert": True, "is_critical": False}},
        power={"PS1": {"status": True}, "PS2": {"status": False}},
    ), settings_from_dict({}))
    checks = {c.name: c for c in health.checks}
    assert checks["cpu"].status == "ok"
    assert checks["temperature"].status == "warning"
    assert checks["power"].status == "ok"


def test_memory_semantics() -> None:
    assert memory_usage({"available_ram": 1000, "used_ram": 250}) == (25.0, 250, 1000)
    assert memory_usage({"available_ram": 250, "used_ram": 750}) == (75.0, 750, 1000)  # 'available' was free memory
    assert memory_usage({"available_ram": 600, "used_ram": 400}, free_semantics=True) == (40.0, 400, 1000)
    assert memory_usage({"available_ram": -1, "used_ram": -1, "%usage": 33}) == (33.0, None, None)
    assert memory_usage({"available_ram": -1, "used_ram": -1}) == (None, None, None)


def test_environment_not_supported_is_still_ok() -> None:
    health = evaluate(device(), HealthCollected(reachable=True, facts={}, env=None, supported=False), settings_from_dict({}))
    assert health.status == "ok" and [c.name for c in health.checks] == ["reachability"]


def test_runner_transitions_unreachable_and_reboot(make_env, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
    settings = make_env([simulated("sw1", "ios", cpu=10), simulated("fw1", "fortios", unreachable=True)])
    state = StateStore(settings.data_path / "state.json")
    devices = {d.name: d for d in load_inventory(settings)}
    runner = HealthRunner(settings, state)

    first = runner.run(list(devices.values()))
    statuses = {r.device.name: r.status for r in first.results}
    assert statuses == {"sw1": "ok", "fw1": "unknown"}  # unreachable_after defaults to 2
    assert [e.type for e in first.events] == []

    second = runner.run(list(devices.values()))
    assert {r.device.name: r.status for r in second.results}["fw1"] == "critical"
    assert [(e.type, e.device) for e in second.events] == [("health_critical", "fw1")]

    third = runner.run(list(devices.values()))
    assert third.events == []  # still critical: no repeat alert

    # sw1 overheats, then recovers
    devices["sw1"].optional_args["cpu"] = 90
    warn = runner.run([devices["sw1"]])
    assert [(e.type, e.severity) for e in warn.events] == [("health_warning", "warning")]
    devices["sw1"].optional_args["cpu"] = 10
    recovered = runner.run([devices["sw1"]])
    assert [e.type for e in recovered.events] == ["health_recovered"]

    # reboot: uptime now shorter than time since the last check
    saved = state.section("sw1", "health")
    state.update("sw1", "health", {"uptime_at": saved["uptime_at"] - 10 * 86400})
    devices["sw1"].optional_args["uptime_days"] = 1
    rebooted = runner.run([devices["sw1"]])
    assert [e.type for e in rebooted.events] == ["device_rebooted"]
    assert state.section("sw1", "health")["last_reboot"] > 0
