"""Network map from LLDP neighbors."""

from __future__ import annotations

from typing import Any

from netledger.topology import build_topology, device_kind, norm_port, normalize_lldp


def row(name: str, status: str = "ok", site: str = "hq", neighbors: list[dict[str, str]] | None = None, **info: Any) -> dict[str, Any]:
    return {
        "name": name,
        "info": {"site": site, "platform": info.pop("platform", "ios"), **info},
        "facts": {"hostname": name},
        "backup": {},
        "health": {"status": status, "neighbors": neighbors or []},
        "last_change": None,
    }


def test_links_are_deduplicated_and_unknown_neighbors_become_hosts() -> None:
    rows = [
        row("sw1", neighbors=normalize_lldp({
            "TwentyFiveGigE1/0/1": [{"hostname": "sw2.corp.example.net", "port": "Twe1/0/1"}],
            "Gi1/0/9": [{"hostname": "esx-01", "port": "vmnic0"}],
        })),
        row("sw2", status="critical", neighbors=[{"port": "Twe1/0/1", "remote": "sw1", "remote_port": "TwentyFiveGigE1/0/1"}]),
        row("fw1", site="dc", platform="fortios"),
    ]
    topology = build_topology(rows, lambda r: r["health"]["status"])
    links = {(link["source"], link["target"]): link for link in topology["links"]}
    assert set(links) == {("sw1", "ext:esx-01"), ("sw1", "sw2")}
    assert links[("sw1", "sw2")]["seen"] == 2 and links[("sw1", "sw2")]["status"] == "down"
    nodes = {n["id"]: n for n in topology["nodes"]}
    assert nodes["ext:esx-01"]["external"] and nodes["ext:esx-01"]["site"] == "hq"
    assert nodes["fw1"]["kind"] == "firewall" and nodes["sw1"]["degree"] == 2 and nodes["fw1"]["degree"] == 0
    assert topology["sites"] == ["dc", "hq"] and topology["lldp"] is True


def test_external_neighbors_are_capped_and_helpers() -> None:
    many = [{"port": f"Gi1/0/{i}", "remote": f"phone-{i}", "remote_port": "eth0"} for i in range(10)]
    topology = build_topology([row("access1", neighbors=many)], lambda r: "ok", max_external=4)
    assert sum(1 for n in topology["nodes"] if n["external"]) == 4
    assert norm_port("TenGigabitEthernet1/1/1") == norm_port("te1/1/1") == "te1/1/1"
    assert device_kind({"role": "edge router", "platform": "ios"}) == "router"
    assert device_kind({"platform": "panos"}) == "firewall" and device_kind({"platform": "eos"}) == "switch"
    assert normalize_lldp({"Gi1": [{"hostname": ""}], "Gi2": [{"hostname": "x", "port": "p"}]}) == [{"port": "Gi2", "remote": "x", "remote_port": "p"}]
