from __future__ import annotations

import json
from typing import Any

import pytest

from netledger.backup import BackupRunner, build_commit_message
from netledger.drivers.simulated import SimulatedDriver
from netledger.inventory import load_inventory
from netledger.state import StateStore
from netledger.storage.gitcli import GitCLIStore

from .conftest import git, needs_git, simulated

pytestmark = needs_git


class Recorder:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def dispatch(self, events: list[Any]) -> dict[str, int]:
        self.events.extend(events)
        return {}


def run(settings, state=None, revision=1, dispatcher=None, **kwargs):  # noqa: ANN001, ANN201
    SimulatedDriver.revision = revision
    devices = load_inventory(settings)
    state = state or StateStore(settings.data_path / "state.json")
    return BackupRunner(settings, state, dispatcher).run(devices, inventory=devices, **kwargs), state


def repo_log(settings) -> list[str]:  # noqa: ANN001
    return git(settings.data_path / "repo", "log", "--format=%s").splitlines()


def test_initial_then_noop_then_change(make_env) -> None:  # noqa: ANN001
    settings = make_env(
        [
            simulated("core1", "ios", change=True, changed_by="jsmith", unsaved=True),
            simulated("fw1", "fortios"),
            simulated("leaf1", "eos"),
        ],
        backup={"retrieve": ["running", "startup"], "commands": {"ios": ["show inventory"]}},
        git={"backend": "local", "path": "{name}"},
    )
    report, state = run(settings)
    assert len(report.ok) == 3 and report.commits == 3
    assert sorted(repo_log(settings)) == ["core1: initial backup", "fw1: initial backup", "leaf1: initial backup"]
    repo = settings.data_path / "repo"
    assert (repo / "configs/core1/running-config.cfg").is_file()
    assert (repo / "configs/core1/startup-config.cfg").is_file()
    assert (repo / "configs/core1/commands/show-inventory.txt").is_file()
    assert not (repo / "configs/fw1/startup-config.conf").exists()
    meta = json.loads((repo / "configs/core1/device.json").read_text())
    assert meta["model"] == "C9500-48Y4C" and meta["platform"] == "ios" and meta["last_changed"]
    index = (repo / "README.md").read_text()
    assert "netledger:index" in index and "[core1](configs/core1)" in index

    # second run with identical device state: FortiOS re-encrypted secrets must not create a commit
    report, state = run(settings, state)
    assert report.commits == 0 and not report.changed
    assert len(repo_log(settings)) == 3

    # third run: core1 changes (and the change is not saved to startup)
    recorder = Recorder()
    report, state = run(settings, state, revision=2, dispatcher=recorder)
    changed = {r.device.name for r in report.results if r.config_changed}
    assert changed == {"core1"}
    core1 = next(r for r in report.results if r.device.name == "core1")
    assert core1.unsaved is True and core1.meta["changed_by"] == "jsmith"
    subject = repo_log(settings)[0]
    assert subject.startswith("core1: running config changed (+")
    body = git(repo, "log", "-1", "--format=%B")
    assert "Changed by: jsmith" in body and "M configs/core1/running-config.cfg" in body
    events = [e for e in recorder.events if e.type == "config_changed"]
    assert len(events) == 1 and "+ip access-list extended GUEST-ISOLATION" in events[0].diff
    assert "netops-RO" not in events[0].diff or "<removed>" in events[0].diff
    backup_state = state.section("core1", "backup")
    assert backup_state["unsaved_changes"] is True and backup_state["changes_total"] == 1
    assert backup_state["last_change_by"] == "jsmith"


def test_failures_alerts_and_recovery(make_env) -> None:  # noqa: ANN001
    settings = make_env([simulated("fw9", "fortios", unreachable=True)], backup={"failure_alert_after": 2, "retries": 0})
    recorder = Recorder()
    report, state = run(settings, dispatcher=recorder)
    assert report.failed and "timed out" in (report.failed[0].error or "")
    assert recorder.events == []
    run(settings, state, dispatcher=recorder)
    assert [e.type for e in recorder.events] == ["backup_failed"]
    run(settings, state, dispatcher=recorder)
    assert len(recorder.events) == 1  # no repeat
    inventory = settings.config_path.parent / "inventory.yaml"
    inventory.write_text(inventory.read_text().replace("unreachable: true", "unreachable: false"))
    run(settings, state, dispatcher=recorder)
    assert [e.type for e in recorder.events] == ["backup_failed", "backup_recovered"]


def test_dry_run_commits_nothing(make_env) -> None:  # noqa: ANN001
    settings = make_env([simulated("core1", "ios")])
    report, _ = run(settings, dry_run=True)
    assert report.ok and report.results[0].initial and report.commits == 0
    repo = settings.data_path / "repo"
    assert not (repo / "configs").exists()


def test_per_run_commit_mode(make_env) -> None:  # noqa: ANN001
    settings = make_env([simulated("a1", "ios"), simulated("b1", "eos")], git={"backend": "local", "commit_mode": "per-run"})
    report, _ = run(settings)
    assert report.commits == 1
    log = repo_log(settings)
    assert log == ["Backup: 2 devices changed"]


def test_compliance_and_events(make_env) -> None:  # noqa: ANN001
    settings = make_env(
        [simulated("sw-ok", "ios"), simulated("sw-bad", "ios", legacy_vty=True)],
        compliance=[{"name": "ssh-only", "platforms": ["ios"], "must_not_match": r"^\s*transport input .*telnet"}],
    )
    recorder = Recorder()
    report, state = run(settings, dispatcher=recorder)
    results = {r.device.name: r.compliance for r in report.results}
    assert results["sw-ok"][0].passed is True
    assert results["sw-bad"][0].passed is False and "transport input telnet ssh" in results["sw-bad"][0].findings[0]
    assert [(e.type, e.device) for e in recorder.events] == [("compliance_failed", "sw-bad")]
    run(settings, state, dispatcher=recorder)
    assert len(recorder.events) == 1


def test_shrink_guard_and_empty_config(make_env, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
    settings = make_env([simulated("core1", "ios")])
    run(settings)
    monkeypatch.setattr(SimulatedDriver, "get_config", lambda self, **kw: {"running": "hostname core1\nend\n", "startup": "", "candidate": ""})
    report, _ = run(settings)
    assert report.failed and "shrank from" in report.failed[0].error
    monkeypatch.setattr(SimulatedDriver, "get_config", lambda self, **kw: {"running": "  \n", "startup": "", "candidate": ""})
    report, _ = run(settings)
    assert report.failed and "empty running configuration" in report.failed[0].error


def test_stale_command_files_are_removed(make_env) -> None:  # noqa: ANN001
    settings = make_env([simulated("core1", "ios")], backup={"commands": {"ios": ["show inventory"]}})
    run(settings)
    repo = settings.data_path / "repo"
    assert (repo / "configs/core1/commands/show-inventory.txt").exists()
    settings.backup.commands = {}
    report, _ = run(settings)
    assert not (repo / "configs/core1/commands/show-inventory.txt").exists()
    assert repo_log(settings)[0] == "core1: removed files no longer collected"


def test_prune_removed_devices(make_env) -> None:  # noqa: ANN001
    settings = make_env([simulated("keep1", "ios"), simulated("gone1", "eos")], git={"backend": "local", "prune": True})
    run(settings)
    inventory = settings.config_path.parent / "inventory.yaml"
    import yaml

    data = yaml.safe_load(inventory.read_text())
    data["devices"] = [d for d in data["devices"] if d["name"] == "keep1"]
    inventory.write_text(yaml.safe_dump(data))
    run(settings)
    repo = settings.data_path / "repo"
    assert not (repo / "configs/gone1").exists() and (repo / "configs/keep1").exists()
    assert repo_log(settings)[0] == "Remove 1 device(s) no longer in inventory"
    assert "gone1" not in (repo / "README.md").read_text()


def test_push_to_remote_and_replay_when_remote_moves(make_env, bare_remote: str, tmp_path) -> None:  # noqa: ANN001
    settings = make_env([simulated("core1", "ios", change=True)], git={"backend": "git", "url": bare_remote})
    report, state = run(settings)
    assert report.pushed and report.commits == 1
    # someone else pushes an unrelated commit to the backup repository
    other = tmp_path / "other"
    git(tmp_path, "clone", "-q", "-b", "main", bare_remote, str(other))
    (other / "NOTES.md").write_text("hello\n")
    git(other, "add", ".")
    git(other, "commit", "-qm", "human edit")
    git(other, "push", "-q", "origin", "HEAD:main")
    # NetLedger's next run must not lose that commit
    report, _ = run(settings, state, revision=2)
    assert report.pushed and report.commits == 1, report.error
    git(other, "pull", "-q", "origin", "main")
    subjects = git(other, "log", "--format=%s").splitlines()
    assert subjects[0].startswith("core1: running config changed") and "human edit" in subjects


def test_commit_message_shape(make_env) -> None:  # noqa: ANN001
    settings = make_env([simulated("core1", "ios", change=True, changed_by="ana")])
    run(settings)
    report, _ = run(settings, revision=2)
    result = report.results[0]
    message = build_commit_message(result.device, result)
    lines = message.splitlines()
    assert lines[0].startswith("core1: running config changed (+") and lines[1] == ""
    assert "Platform:   Cisco IOS / IOS-XE" in message and "Changed by: ana at" in message


def test_git_store_never_touches_a_parent_repository(tmp_path) -> None:  # noqa: ANN001
    from netledger.config import settings_from_dict

    parent = tmp_path / "parent"
    parent.mkdir()
    git(parent, "init", "-q")
    (parent / "work.txt").write_text("precious\n")
    git(parent, "add", ".")
    git(parent, "commit", "-qm", "init")
    (parent / "work.txt").write_text("uncommitted\n")
    workdir = parent / "data" / "repo"
    workdir.mkdir(parents=True)
    (workdir / ".git").mkdir()  # damaged clone (empty .git)
    settings = settings_from_dict({"git": {"backend": "local"}}, base_dir=parent)
    store = GitCLIStore(settings.git, workdir)
    from netledger.storage import StoreError

    with pytest.raises(StoreError, match="damaged"):
        store.prepare()
    assert (parent / "work.txt").read_text() == "uncommitted\n"
    assert git(parent, "log", "--format=%s").splitlines() == ["init"]


def test_change_intelligence_ledger_and_change_windows(make_env, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
    from datetime import datetime, timezone

    import netledger.backup as backup_module

    noon = datetime(2026, 10, 29, 12, 0, tzinfo=timezone.utc).timestamp()
    settings = make_env(
        [simulated("core1", "ios", change=True, changed_by="jsmith")],
        changes={"windows": ["daily 01:00-04:00"], "timezone": "UTC"},
        git={"backend": "local", "path": "{name}"},
    )
    recorder = Recorder()
    monkeypatch.setattr(backup_module, "now", lambda: noon)
    _, state = run(settings, dispatcher=recorder)
    monkeypatch.setattr(backup_module, "now", lambda: noon + 600)
    report, state = run(settings, state=state, revision=2, dispatcher=recorder)

    result = report.results[0]
    assert result.analysis is not None and result.analysis.risk == "high" and result.unplanned is True
    body = git(settings.data_path / "repo", "log", "-1", "--format=%B")
    assert "Window:     outside the approved change windows" in body
    assert "Risk:       high (" in body and "  - Added ACL GUEST-ISOLATION" in body
    opened = "ACL GUEST-ISOLATION entry 20: new rule allows any source, any destination and any service"
    assert body.index("Risk:") < body.index("Why:") < body.index("Summary:") and f"  - {opened}" in body

    change = [e for e in recorder.events if e.type == "config_changed"][0]
    assert change.severity == "warning" and change.title == "core1: unplanned configuration change"
    assert change.details["risk"] == "high" and "• Added VLAN 40 (GUEST-WIFI)" in change.message and change.timestamp == noon + 600
    assert opened in change.details["reasons"]

    ledger = state.changes()
    assert len(ledger) == 1 and ledger[0]["unplanned"] is True and ledger[0]["commit"] == result.commit
    assert ledger[0]["reasons"] == change.details["reasons"] == result.analysis.reasons[:6]
    assert ledger[0]["since"] == noon and "Added ACL GUEST-ISOLATION" in ledger[0]["highlights"] and ledger[0]["diff"]
    assert state.section("core1", "backup")["last_analysis"]["risk"] == "high"
    assert state.activity(limit=1)[0]["title"] == "core1: unplanned configuration change"


def test_changes_inside_a_window_are_planned(make_env, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
    from datetime import datetime, timezone

    import netledger.backup as backup_module

    two_am = datetime(2026, 10, 29, 2, 0, tzinfo=timezone.utc).timestamp()
    settings = make_env([simulated("core1", "ios", change=True)], changes={"windows": ["daily 01:00-04:00"], "timezone": "UTC"})
    monkeypatch.setattr(backup_module, "now", lambda: two_am)
    _, state = run(settings)
    monkeypatch.setattr(backup_module, "now", lambda: two_am + 900)
    report, state = run(settings, state=state, revision=2)
    assert report.results[0].unplanned is False and state.changes()[0]["unplanned"] is False


def test_dry_run_still_explains_the_change(make_env) -> None:  # noqa: ANN001
    settings = make_env([simulated("fw1", "fortios", change=True)])
    _, state = run(settings)
    report, state = run(settings, state=state, revision=2, dry_run=True)
    result = report.results[0]
    assert result.analysis is not None and "Added firewall policy 4 (Guest-to-Internet)" in result.analysis.highlights
    assert state.changes() == []
