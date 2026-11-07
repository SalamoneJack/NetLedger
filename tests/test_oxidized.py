"""Oxidized as the configuration source: its git output and its web API."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest
import yaml

from netledger.backup import BackupRunner
from netledger.config import ConfigError, Settings, load_settings
from netledger.inventory import load_inventory, validate_inventory
from netledger.oxidized import guess_platform, map_model
from netledger.scheduler import IntervalSchedule, Scheduler
from netledger.state import StateStore

from .conftest import git, needs_git

T0 = 1_793_000_000  # 2026-10-26
IOS_V1 = (
    "hostname core1\n!\ninterface Vlan10\n ip address 10.10.10.2 255.255.255.0\n!\n"
    "ip access-list extended WEB\n permit tcp 10.20.0.0 0.0.0.255 host 10.0.0.5 eq 443\n!\nend\n"
)
IOS_V2 = IOS_V1.replace("10.20.0.0 0.0.0.255", "any")
FORTI_V1 = (
    'config system global\n    set hostname "fw1"\nend\nconfig firewall policy\n    edit 1\n        set srcaddr "LAN"\n'
    '        set dstaddr "all"\n        set action accept\n        set service "HTTPS"\n    next\nend\n'
)
FORTI_V2 = FORTI_V1.replace('"HTTPS"', '"HTTPS" "SSH"')
FORTI_V3 = FORTI_V2.replace('set srcaddr "LAN"', 'set srcaddr "all"')


class Recorder:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def dispatch(self, events: list[Any]) -> dict[str, int]:
        self.events.extend(events)
        return {}


def new_repo(path: Path) -> Path:
    path.mkdir(parents=True)
    git(path, "init", "-q")
    return path


def commit(repo: Path, files: dict[str, str], author: str = "Oxidized", email: str = "o@example.com", when: int = T0) -> None:
    for rel, text in files.items():
        target = repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    env = {**os.environ, "GIT_AUTHOR_NAME": author, "GIT_AUTHOR_EMAIL": email, "GIT_COMMITTER_NAME": author,
           "GIT_COMMITTER_EMAIL": email, "GIT_AUTHOR_DATE": f"{when} +0000", "GIT_COMMITTER_DATE": f"{when} +0000"}
    for args in (["add", "-A"], ["commit", "-q", "-m", f"update {', '.join(files)}"]):
        subprocess.run(["git", "-c", "commit.gpgsign=false", *args], cwd=str(repo), env=env, check=True, capture_output=True)


def configure(tmp_path: Path, source: dict[str, Any], **extra: Any) -> Settings:
    config = {"inventory": [{"type": "oxidized", **source}], "git": {"backend": "local"}, **extra}
    (tmp_path / "netledger.yaml").write_text(yaml.safe_dump(config), encoding="utf-8")
    return load_settings(tmp_path / "netledger.yaml")


def run(settings: Settings, state: StateStore, recorder: Recorder | None = None) -> Any:
    devices = load_inventory(settings)
    return BackupRunner(settings, state, recorder).run(devices, inventory=devices)


def test_models_map_to_platforms_and_unknown_models_are_guessed() -> None:
    assert [map_model(m) for m in ("IOS", "JunOS", "FortiOS", "fortigate", "PanOS", "panos_api", "IronWare", "VRP", "XOS")] == [
        "ios", "junos", "fortios", "fortios", "panos", "panos", "fastiron", "huawei_vrp", "exos",
    ]
    assert map_model("ScreenOS") is None and map_model("ScreenOS", {"screenos": "generic"}) == "generic"
    assert map_model("IOS", {"ios": "nxos"}) == "nxos"  # the mapping can be overridden
    assert guess_platform(IOS_V1) == "ios" and guess_platform(FORTI_V1) == "fortios"
    assert guess_platform("set deviceconfig system hostname fw1\nset address A ip-netmask 10.0.0.0/8\n") == "panos"
    assert guess_platform("system {\n    host-name r1;\n}\ninterfaces {\n    ge-0/0/0 {\n        mtu 9216;\n    }\n}\n") == "junos"
    assert guess_platform("# 2026-10-30 by RouterOS 7.14\n/system identity set name=r1\n") == "routeros"


@needs_git
def test_repo_mode_turns_every_commit_into_one_change(tmp_path: Path) -> None:
    repo = new_repo(tmp_path / "oxidized" / "configs.git")
    commit(repo, {"core1": IOS_V1, "edge/fw1": FORTI_V1})
    (tmp_path / "router.db").write_text("fw1:fortigate\n", encoding="utf-8")
    settings = configure(tmp_path, {"path": "oxidized/configs.git", "router_db": "router.db"})
    devices = {d.name: d for d in load_inventory(settings)}
    assert devices["core1"].platform == "ios"  # no model in router.db: recognized from the configuration
    assert devices["fw1"].platform == "fortios" and devices["fw1"].groups == ["edge"]
    assert devices["core1"].collector == "oxidized" and not devices["core1"].health
    assert validate_inventory(list(devices.values()), settings) == []  # NetLedger never logs in: no credentials needed

    state, recorder = StateStore(settings.data_path / "state.json"), Recorder()
    report = run(settings, state, recorder)
    assert {r.device.name for r in report.results if r.initial} == {"core1", "fw1"}
    assert recorder.events == [] and state.changes() == []

    commit(repo, {"core1": IOS_V2}, author="jsmith", email="jsmith@example.com", when=T0 + 3600)
    commit(repo, {"edge/fw1": FORTI_V2}, when=T0 + 7200)  # Oxidized's own identity says nothing about who
    commit(repo, {"edge/fw1": FORTI_V3}, author="ana", email="ana@example.com", when=T0 + 7300)
    report = run(settings, state, recorder)
    ledger = list(reversed(state.changes()))
    assert [(c["device"], c["changed_by"], c["ts"]) for c in ledger] == [
        ("core1", "jsmith", T0 + 3600), ("fw1", None, T0 + 7200), ("fw1", "ana", T0 + 7300),
    ]
    assert ledger[0]["risk"] == "high" and [e.type for e in recorder.events] == ["config_changed"] * 3
    fw1 = next(r for r in report.results if r.device.name == "fw1")
    assert fw1.analysis is not None and fw1.analysis.syntax == "fortios"
    history = git(settings.data_path / "repo", "log", "--format=%s%n%b")
    assert "core1: running config changed" in history and "Changed by: jsmith" in history

    report = run(settings, state, recorder)  # nothing new: every change is processed exactly once
    assert len(state.changes()) == 3 and not any(r.config_changed for r in report.results)
    assert git(repo, "status", "--porcelain") == "" and git(repo, "rev-list", "--count", "HEAD").strip() == "4"  # read only

    key = settings.inventory_sources[0].key
    state.set_cursor(key, {"repos": {str(repo.resolve()): "0" * 40}})  # history rewritten: start over quietly
    run(settings, state, recorder)
    assert len(state.changes()) == 3


@needs_git
def test_per_group_repositories_and_overrides(tmp_path: Path) -> None:
    root = tmp_path / "oxidized"
    commit(new_repo(root / "lab.git"), {"lab-sw1": IOS_V1})
    commit(new_repo(root / "core.git"), {"core1": IOS_V1})
    settings = configure(
        tmp_path,
        {"path": "oxidized", "groups": ["lab"], "devices": {"lab-sw1": {"platform": "eos", "site": "lab", "health": True}}},
        credentials={"default": {"username": "u", "password": "p"}},
    )
    devices = load_inventory(settings)
    assert [(d.name, d.groups, d.platform, d.site, d.health) for d in devices] == [("lab-sw1", ["lab"], "eos", "lab", True)]
    state = StateStore(settings.data_path / "state.json")
    assert run(settings, state).results[0].initial


@needs_git
def test_api_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import requests

    nodes = [
        {"name": "sw1", "full_name": "branch/sw1", "ip": "192.0.2.10", "group": "branch", "model": "IOS",
         "last": {"status": "success", "end": "2026-10-30 10:00:00 UTC"}, "mtime": "2026-10-30 10:00:00 UTC"},
        {"name": "fw2", "full_name": "fw2", "ip": "192.0.2.11", "group": "default", "model": "FortiOS",
         "last": {"status": "no_connection"}, "mtime": "2026-10-30 09:00:00 UTC"},
    ]
    configs = {"branch/sw1": IOS_V1}
    versions: dict[str, Any] = {}
    calls: list[tuple[str, Any]] = []

    class Response:
        def __init__(self, status: int, data: Any = None, text: str = "") -> None:
            self.status_code, self._data, self.text = status, data, text

        def raise_for_status(self) -> None:
            if self.status_code >= 400:
                raise requests.HTTPError(f"{self.status_code}")

        def json(self) -> Any:
            return self._data

    def get(session: Any, url: str, params: Any = None, **kwargs: Any) -> Response:
        path = url.split(":8888", 1)[1]
        calls.append((path, session.auth))
        if path == "/nodes.json":
            return Response(200, nodes)
        if path.startswith("/node/fetch/"):
            name = path[len("/node/fetch/"):]
            return Response(200, text=configs[name]) if name in configs else Response(404)
        if path == "/node/version.json":
            return Response(200, versions.get(params["node_full"], []))
        return Response(404)

    monkeypatch.setattr("requests.Session.get", get)
    settings = configure(tmp_path, {"mode": "api", "url": "http://oxidized:8888", "username": "u", "password": "p"},
                         backup={"failure_alert_after": 1})
    devices = {d.name: d for d in load_inventory(settings)}
    assert (devices["sw1"].platform, devices["sw1"].host, devices["sw1"].groups) == ("ios", "192.0.2.10", ["branch"])
    assert devices["fw2"].platform == "fortios" and devices["fw2"].groups == []

    state, recorder = StateStore(settings.data_path / "state.json"), Recorder()
    report = run(settings, state, recorder)
    results = {r.device.name: r for r in report.results}
    assert results["sw1"].initial and results["fw2"].status == "failed" and "no_connection" in (results["fw2"].error or "")
    assert [e.type for e in recorder.events] == ["backup_failed"] and all(auth == ("u", "p") for _, auth in calls)

    calls.clear()
    run(settings, state, recorder)  # nothing changed in Oxidized: no configuration is fetched
    assert not any(path.startswith("/node/fetch/") for path, _ in calls)

    configs["branch/sw1"] = IOS_V2
    nodes[0]["mtime"] = "2026-10-30 11:00:00 UTC"
    versions["branch/sw1"] = [
        {"oid": "a1", "time": "2026-10-30 10:00:00 UTC", "author": {"name": "Oxidized", "email": "o@example.com"}},
        {"oid": "b2", "time": "2026-10-30 11:00:00 UTC", "author": {"name": "jsmith", "email": "jsmith@example.com"}},
    ]
    run(settings, state, recorder)
    change = state.changes()[0]
    assert change["device"] == "sw1" and change["changed_by"] == "jsmith" and change["ts"] == 1793358000.0
    assert change["risk"] == "high"


def test_source_validation(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="needs the 'path'"):
        configure(tmp_path, {"mode": "repo"})
    with pytest.raises(ConfigError, match="needs the 'url'"):
        configure(tmp_path, {"mode": "api"})
    with pytest.raises(ConfigError, match="poll"):
        configure(tmp_path, {"mode": "api", "url": "http://x", "poll": "whenever"})
    settings = configure(tmp_path, {"path": "missing"})
    with pytest.raises(ConfigError, match="does not exist"):
        load_inventory(settings)


@needs_git
def test_risk_settings_and_outages(tmp_path: Path) -> None:
    import shutil

    from netledger.oxidized import _NODES

    repo = new_repo(tmp_path / "oxidized" / "configs.git")
    commit(repo, {"core1": IOS_V1, "sw2": IOS_V1})
    settings = configure(tmp_path, {
        "path": "oxidized/configs.git",
        "defaults": {"risk": {"multiplier": 0.5}},
        "devices": {"core1": {"risk": {"multiplier": 1.5}}},
    })
    devices = {d.name: d for d in load_inventory(settings)}
    assert settings.risk.resolve(devices["core1"].risk, devices["core1"].risk_origin).origin == "core1"
    assert settings.risk.resolve(devices["sw2"].risk, devices["sw2"].risk_origin).origin == "defaults"

    shutil.rmtree(tmp_path / "oxidized", ignore_errors=True)
    if (tmp_path / "oxidized").exists():  # Windows keeps read-only git objects: move the repository aside instead
        (tmp_path / "oxidized").rename(tmp_path / "gone")
    assert sorted(d.name for d in load_inventory(settings)) == ["core1", "sw2"]  # an outage keeps the known devices
    _NODES.clear()
    with pytest.raises(ConfigError, match="does not exist"):  # but nothing to fall back on fails loudly
        load_inventory(settings)


@needs_git
def test_serve_backup_job_still_prunes_with_an_oxidized_source(tmp_path: Path) -> None:
    from .conftest import simulated

    commit(new_repo(tmp_path / "oxidized" / "configs.git"), {"core1": IOS_V1})
    inventory = tmp_path / "inventory.yaml"
    inventory.write_text(yaml.safe_dump({"devices": [simulated("keep1", "ios"), simulated("gone1", "eos")]}), encoding="utf-8")
    config = {
        "inventory": ["inventory.yaml", {"type": "oxidized", "path": "oxidized/configs.git"}],
        "git": {"backend": "local", "prune": True},
        "credentials": {"default": {"username": "u", "password": "p"}},
    }
    (tmp_path / "netledger.yaml").write_text(yaml.safe_dump(config), encoding="utf-8")
    settings = load_settings(tmp_path / "netledger.yaml")
    state = StateStore(settings.data_path / "state.json")
    run(settings, state)  # everything, as 'netledger backup' does
    inventory.write_text(yaml.safe_dump({"devices": [simulated("keep1", "ios")]}), encoding="utf-8")
    devices = load_inventory(settings)
    BackupRunner(settings, state).run([d for d in devices if d.collector != "oxidized"], inventory=devices)  # as 'serve' does
    repo = settings.data_path / "repo" / "configs"
    assert not (repo / "gone1").exists() and (repo / "keep1").exists() and (repo / "core1").exists()


def test_queued_trigger_runs_once_more() -> None:
    scheduler = Scheduler()
    started, release, runs = threading.Event(), threading.Event(), []

    def job() -> None:
        runs.append(time.time())
        started.set()
        release.wait(5)

    scheduler.add("oxidized", IntervalSchedule(3600), job)
    assert scheduler.trigger("oxidized", queue=True) is True
    started.wait(5)
    assert scheduler.trigger("oxidized", queue=True) is False and scheduler.trigger("oxidized", queue=True) is False
    release.set()
    deadline = time.time() + 5
    while (len(runs) < 2 or scheduler.jobs["oxidized"].running) and time.time() < deadline:
        time.sleep(0.02)
    assert len(runs) == 2 and not scheduler.jobs["oxidized"].running  # two triggers while busy: one more run


def post(url: str, body: bytes, headers: dict[str, str]) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(url, data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=20) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def test_webhook_triggers_processing(tmp_path: Path) -> None:
    from netledger.server import App, DashboardServer

    (tmp_path / "oxidized").mkdir()
    settings = configure(tmp_path, {"path": "oxidized", "hook_token": "tok", "hook_secret": "s3cret"})
    triggered: list[str] = []
    scheduler = Scheduler()
    scheduler.add("oxidized", IntervalSchedule(3600), lambda: triggered.append("oxidized"))
    server = DashboardServer(App(settings, StateStore.in_memory(), scheduler), "127.0.0.1", 0)
    server.start()
    try:
        url = f"http://127.0.0.1:{server.port}/api/hooks/oxidized"
        body = json.dumps({"node": "core1", "group": "core", "event": "post_store"}).encode()
        assert post(url, body, {"Content-Type": "application/json"})[0] == 401
        assert post(url, body, {"Authorization": "Bearer wrong"})[0] == 401
        status, data = post(url, body, {"Authorization": "Bearer tok"})
        assert status == 202 and data["job"] == "oxidized"
        signature = "sha256=" + hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
        assert post(url, body, {"X-NetLedger-Signature": signature})[0] == 202
        assert post(url, body + b" ", {"X-NetLedger-Signature": signature})[0] == 401  # signed a different body
    finally:
        server.stop()
    deadline = time.time() + 5
    while not triggered and time.time() < deadline:
        time.sleep(0.02)
    assert triggered

    plain = configure(tmp_path, {"path": "oxidized"})
    server = DashboardServer(App(plain, StateStore.in_memory(), Scheduler()), "127.0.0.1", 0)
    server.start()
    try:
        assert post(f"http://127.0.0.1:{server.port}/api/hooks/oxidized", b"{}", {})[0] == 403  # no token or secret configured
    finally:
        server.stop()
