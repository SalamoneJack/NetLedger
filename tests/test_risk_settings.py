"""Configurable risk scoring: category levels, weights and multipliers, globally and per device or group."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from netledger.config import ConfigError, load_settings, settings_from_dict
from netledger.intel import RISK_WEIGHT, RiskProfile, analyze
from netledger.inventory import load_inventory

from .conftest import git, needs_git
from .test_intel import IOS_BEFORE, ios_after
from .test_reasons import forti_policy, ios_acl, junos_term, panos_rule

NTP_BEFORE = "hostname r1\nntp server 10.0.0.1\n"
NTP_AFTER = "hostname r1\nntp server 10.0.0.2\n"
VLANS = "".join(f"vlan {n}\n name V{n}\n!\n" for n in range(100, 180))
CORPUS = [
    (IOS_BEFORE, ios_after(), "ios"),
    (NTP_BEFORE, NTP_AFTER, "ios"),
    (ios_acl("permit tcp any host 10.0.0.5 eq 443"), ios_acl("permit ip any host 10.0.0.5"), "ios"),
    (forti_policy(), forti_policy(srcaddr='"all"'), "fortios"),
    (panos_rule(), panos_rule(source="any"), "panos"),
    (junos_term(), junos_term(source=None), "junos"),
    ("hostname r1\n", "hostname r1\n" + VLANS, "ios"),
]


def test_without_settings_scoring_is_the_built_in_one() -> None:
    profile = settings_from_dict({}).risk.resolve()
    assert profile == RiskProfile() and profile.weights == RISK_WEIGHT == {"low": 6, "medium": 15, "high": 34}
    for old, new, platform in CORPUS:
        assert analyze(old, new, platform, risk=profile).to_dict(max_items=50) == analyze(old, new, platform).to_dict(max_items=50)
    # the built-in scores, pinned
    assert [(a.risk, a.score) for a in (analyze(old, new, platform) for old, new, platform in CORPUS)] == [
        ("high", 89), ("low", 6), ("high", 34), ("high", 34), ("high", 34), ("high", 34), ("high", 100),
    ]
    assert analyze(NTP_BEFORE, NTP_AFTER, "ios").reasons == ["Management services change (low risk by default): ntp server"]


def test_category_levels_and_weights_from_settings() -> None:
    settings = settings_from_dict({"risk": {"categories": {"services": "medium", "docs": "low"}, "weights": {"medium": 20}}})
    analysis = analyze(NTP_BEFORE, NTP_AFTER, "ios", risk=settings.risk.resolve())
    assert (analysis.risk, analysis.score) == ("medium", 20)
    assert analysis.reasons == [
        "Risk weights from your settings: medium 20 (default 15)",
        "Management services change (medium risk in your settings, low by default): ntp server",
    ]
    assert analysis.categories()[0] == {"key": "services", "label": "Management services", "count": 1, "risk": "medium"}

    lowered = RiskProfile(categories={"firewall": "medium"})
    entry = ios_acl("permit tcp any host 10.0.0.5 eq 443")
    analysis = analyze(entry, entry.replace("eq 443", "eq 8443"), "ios", risk=lowered)
    assert analysis.risk == "medium"
    assert analysis.reasons == ["Firewall & ACLs change (medium risk in your settings, high by default): ACL WEB"]
    # what a change does still raises the level, whatever the category is set to
    widened = analyze(entry, entry.replace("any host", "any 10.0.0.0 0.0.0.255"), "ios", risk=lowered)
    assert widened.risk == "high" and widened.reasons[0].startswith("ACL WEB now allows a wider destination")


def test_multiplier_scales_the_score_but_not_the_level() -> None:
    assert analyze(NTP_BEFORE, NTP_AFTER, "ios", risk=RiskProfile(multiplier=0.5, origin="lab")).score == 3
    edge = analyze(IOS_BEFORE, ios_after(), "ios", risk=RiskProfile(multiplier=1.5, origin="edge"))
    assert (edge.risk, edge.score) == ("high", 100)  # 89 x 1.5, capped at 100
    assert "Device multiplier 1.5 (edge)" in edge.reasons
    doubled = analyze(NTP_BEFORE, NTP_AFTER, "ios", risk=RiskProfile(multiplier=2))
    assert (doubled.risk, doubled.score) == ("low", 12) and "Risk multiplier 2 (global setting)" in doubled.reasons
    # a multiplier that does not change the score adds no reason (this change already scores 100)
    huge = analyze("hostname r1\n", "hostname r1\n" + VLANS, "ios", risk=RiskProfile(multiplier=1.5, origin="edge"))
    assert huge.score == 100 and not any("multiplier" in reason for reason in huge.reasons)


def write(tmp_path: Path, config: dict[str, Any], inventory: Any, name: str = "inventory.yaml") -> Path:
    config = {"inventory": [name], "git": {"backend": "local"}, "credentials": {"default": {"username": "u", "password": "p"}}, **config}
    (tmp_path / "netledger.yaml").write_text(yaml.safe_dump(config), encoding="utf-8")
    target = tmp_path / name
    target.write_text(inventory if isinstance(inventory, str) else yaml.safe_dump(inventory), encoding="utf-8")
    return tmp_path / "netledger.yaml"


def test_inventory_overrides_follow_group_inheritance(tmp_path: Path) -> None:
    inventory = {
        "groups": {
            "lab": {"risk": {"multiplier": 0.5}},
            "edge": {"risk": {"multiplier": 1.5, "categories": {"docs": "medium"}}},
            "dmz": {"groups": ["edge"], "risk": {"weights": {"high": 40}}},
        },
        "devices": [
            {"name": "lab-sw1", "host": "192.0.2.1", "platform": "ios", "groups": ["lab"]},
            {"name": "fw-edge1", "host": "192.0.2.2", "platform": "fortios", "groups": ["dmz"]},
            {"name": "fw-edge2", "host": "192.0.2.3", "platform": "fortios", "groups": ["dmz"], "risk": {"multiplier": 2}},
            {"name": "core1", "host": "192.0.2.4", "platform": "ios"},
        ],
    }
    settings = load_settings(write(tmp_path, {"risk": {"categories": {"services": "medium"}, "weights": {"low": 5}}}, inventory))
    devices = {d.name: d for d in load_inventory(settings)}

    def profile(name: str) -> RiskProfile:
        return settings.risk.resolve(devices[name].risk, devices[name].risk_origin)

    assert profile("lab-sw1") == RiskProfile({"services": "medium"}, {"low": 5, "medium": 15, "high": 34}, 0.5, "lab")
    assert profile("fw-edge1") == RiskProfile({"services": "medium", "docs": "medium"}, {"low": 5, "medium": 15, "high": 40}, 1.5, "edge")
    assert profile("fw-edge2").multiplier == 2 and profile("fw-edge2").origin == "fw-edge2"
    assert devices["core1"].risk is None and profile("core1") == RiskProfile({"services": "medium"}, {"low": 5, "medium": 15, "high": 34})
    summary = devices["fw-edge1"].summary()
    assert summary["risk"] == {"multiplier": 1.5, "categories": {"docs": "medium"}, "weights": {"high": 40}} and summary["risk_origin"] == "edge"
    assert "risk" not in devices["core1"].summary()


def test_csv_inventory_risk_columns(tmp_path: Path) -> None:
    csv = "name,host,platform,risk.multiplier,risk.categories.services\nlab1,192.0.2.9,ios,0.5,medium\n"
    settings = load_settings(write(tmp_path, {}, csv, "devices.csv"))
    device = load_inventory(settings)[0]
    assert settings.risk.resolve(device.risk, device.risk_origin) == RiskProfile({"services": "medium"}, dict(RISK_WEIGHT), 0.5, "lab1")


@pytest.mark.parametrize(("risk", "message"), [
    ({"categories": {"firewal": "high"}}, "unknown change category"),
    ({"categories": {"firewall": "critical"}}, "risk.categories.firewall"),
    ({"multiplier": -1}, "risk.multiplier"),
    ({"weights": {"high": 500}}, "risk.weights.high"),
    ({"weight": {"high": 40}}, "unknown setting"),
])
def test_invalid_settings_are_rejected(risk: dict[str, Any], message: str, tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match=message):
        settings_from_dict({"risk": risk})
    inventory = {"devices": [{"name": "r1", "host": "192.0.2.1", "platform": "ios", "risk": risk}]}
    settings = load_settings(write(tmp_path, {}, inventory))
    with pytest.raises(ConfigError, match=r"r1\): risk"):
        load_inventory(settings)


def test_the_console_scores_like_the_backup(tmp_path: Path) -> None:
    from netledger.server import App
    from netledger.state import StateStore

    settings = settings_from_dict({"risk": {"weights": {"high": 40}}}, base_dir=tmp_path)
    app = App(settings, StateStore.in_memory())
    try:
        row = {"info": {"risk": {"multiplier": 0.5}, "risk_origin": "lab"}}
        assert app.risk_profile(row) == RiskProfile({}, {"low": 6, "medium": 15, "high": 40}, 0.5, "lab")
        assert app.risk_profile({"info": {"risk": {"multiplier": "bogus"}}}) == settings.risk.resolve()
    finally:
        app.close()


@needs_git
def test_backup_uses_the_device_risk(tmp_path: Path) -> None:
    from netledger.backup import BackupRunner
    from netledger.drivers.simulated import SimulatedDriver
    from netledger.state import StateStore

    device = {"name": "edge1", "host": "192.0.2.20", "platform": "ios", "driver": "simulated", "groups": ["edge"],
              "optional_args": {"latency": 0, "change": True}}
    settings = load_settings(write(tmp_path, {}, {"groups": {"edge": {"risk": {"multiplier": 1.5}}}, "devices": [device]}))
    devices = load_inventory(settings)
    state = StateStore(settings.data_path / "state.json")
    BackupRunner(settings, state).run(devices, inventory=devices)
    SimulatedDriver.revision = 2
    report = BackupRunner(settings, state).run(devices, inventory=devices)
    analysis = report.results[0].analysis
    assert analysis is not None and "Device multiplier 1.5 (edge)" in analysis.reasons
    body = git(settings.data_path / "repo", "log", "-1", "--format=%B")
    assert "  - Device multiplier 1.5 (edge)" in body
    assert state.changes()[0]["score"] == analysis.score
