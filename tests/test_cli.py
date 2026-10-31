from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from netledger.cli import main

from .conftest import git, needs_git, simulated


def test_platforms_and_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["platforms"]) == 0
    out = capsys.readouterr().out
    assert "fortios" in out and "routeros" in out and "asa" in out
    assert main(["version"]) == 0


def test_init_writes_templates_that_validate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert main(["init", str(tmp_path)]) == 0
    for name in ("netledger.yaml", "inventory.yaml", "netledger.env"):
        assert (tmp_path / name).is_file()
    monkeypatch.setenv("NETLEDGER_USERNAME", "u")
    monkeypatch.setenv("NETLEDGER_PASSWORD", "p")
    monkeypatch.setenv("GIT_TOKEN", "t")
    assert main(["-c", str(tmp_path / "netledger.yaml"), "validate"]) == 0
    assert main(["init", str(tmp_path)]) == 0  # second run skips existing files


def test_missing_env_var_is_a_config_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    main(["init", str(tmp_path)])
    monkeypatch.delenv("NETLEDGER_USERNAME", raising=False)
    assert main(["-c", str(tmp_path / "netledger.yaml"), "validate"]) == 2
    assert main(["-c", str(tmp_path / "netledger.yaml"), "health"]) == 3


@needs_git
def test_backup_health_inventory_and_search(make_env, capsys: pytest.CaptureFixture[str]) -> None:  # noqa: ANN001
    settings = make_env([simulated("core1", "ios"), simulated("fw1", "fortios", cpu=97), simulated("x9", "eos", unreachable=True)],
                        health={"unreachable_after": 1}, backup={"retries": 0})
    config = str(settings.config_path)
    assert main(["-c", config, "inventory", "--format", "json"]) == 0
    assert {d["name"] for d in json.loads(capsys.readouterr().out)} == {"core1", "fw1", "x9"}
    assert main(["-c", config, "backup", "-d", "core1", "--dry-run"]) == 0
    assert main(["-c", config, "backup"]) == 1  # x9 is unreachable
    capsys.readouterr()
    assert main(["-c", config, "backup", "-d", "core1", "-d", "fw1", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert {d["name"]: d["status"] for d in report["devices"]} == {"core1": "ok", "fw1": "ok"}
    assert main(["-c", config, "health", "-d", "core1"]) == 0
    assert main(["-c", config, "health", "-d", "fw1"]) == 2  # CPU critical -> Nagios CRITICAL
    capsys.readouterr()
    assert main(["-c", config, "health", "--json", "-p", "eos"]) == 2
    assert json.loads(capsys.readouterr().out)["devices"][0]["reachable"] is False
    assert main(["-c", config, "search", "ip ssh version", "-l"]) == 0
    assert "core1" in capsys.readouterr().out
    assert main(["-c", config, "search", "this-does-not-exist-anywhere"]) == 1
    capsys.readouterr()
    assert main(["-c", config, "search", "10.10.99.250"]) == 0  # an address: IP-aware search
    out = capsys.readouterr().out
    assert "lives in 10.10.99.0/24" in out and "core1" in out and "fw1" in out
    assert main(["-c", config, "search", "--regex", "10.10.99.250"]) == 1


@needs_git
def test_demo_tour(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from netledger.drivers.simulated import SimulatedDriver
    from netledger.history import MetricsHistory
    from netledger.state import StateStore
    from netledger.windows import ChangeCalendar

    monkeypatch.setattr(SimulatedDriver, "latency_scale", 0)
    started = time.time()
    assert main(["demo", "--dir", str(tmp_path / "demo"), "--no-serve"]) == 0
    data = tmp_path / "demo" / "data"
    assert (data / "repo" / "configs" / "hq" / "hq-fw01" / "running-config.conf").is_file()
    state = StateStore(data / "state.json")
    changes = state.changes()
    assert len(changes) >= 20 and {c["risk"] for c in changes} == {"low", "medium", "high"}
    live = sorted(c["device"] for c in changes if c["ts"] >= started - 60)
    assert live == ["dc1-spine01", "hq-core-sw01", "hq-fw01"]
    if not ChangeCalendar(["daily 01:00-04:00"]).overlaps(started - 15 * 60, time.time()):  # the demo's change window
        assert sorted(c["device"] for c in changes if c["unplanned"]) == live
    assert state.section("dc1-ext-asa01", "health")["forecast"]["memory"]["threshold"] == 95
    assert state.section("lon-fw01", "health")["status_since"] < state.section("lon-fw01", "health")["checked_at"] - 3 * 3600
    history = MetricsHistory(data / "history.db")
    assert history._query("SELECT count(*) FROM samples WHERE device = 'hq-fw02'", ())[0][0] > 600
    history.close()
    log = git(data / "repo", "log", "--format=%an|%s")
    assert "hq-core-sw01: running config changed" in log and len(log.splitlines()) > 30
    assert main(["demo", "--dir", str(tmp_path / "demo"), "--no-serve"]) == 0  # rerun resets cleanly
