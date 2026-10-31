"""'Where is' search: address tokens in every notation, ranking, text/regex modes, safety limits."""

from __future__ import annotations

import ipaddress
import time
from pathlib import Path

import pytest

from netledger.search import (
    Document,
    DocumentCache,
    QueryError,
    as_network,
    match_token,
    parse_query,
    search,
    tokens,
)


def nets(line: str) -> list[tuple[str, str | None]]:
    return [(str(t.network), str(t.host) if t.host else None) for t in tokens(line)]


def test_address_notations() -> None:
    assert nets(" ip address 10.10.20.2 255.255.255.0") == [("10.10.20.0/24", "10.10.20.2")]
    assert nets(" 10 deny ip 10.10.40.0 0.0.0.255 10.0.0.0 0.255.255.255") == [("10.10.40.0/24", None), ("10.0.0.0/8", None)]
    assert nets("route outside 0.0.0.0 0.0.0.0 198.51.100.25 1") == [("0.0.0.0/0", None), ("198.51.100.25/32", "198.51.100.25")]
    assert nets("ip name-server 10.10.0.53 10.20.0.53") == [("10.10.0.53/32", "10.10.0.53"), ("10.20.0.53/32", "10.20.0.53")]
    assert nets("/ip address add address=192.0.2.2/30 interface=ether1") == [("192.0.2.0/30", "192.0.2.2")]
    assert nets("                address 10.255.1.4/31;") == [("10.255.1.4/31", "10.255.1.4")]
    assert nets(" permit 10.1.1.1 0.0.0.0") == [("10.1.1.1/32", "10.1.1.1")]
    assert nets("version 17.9.4") == []
    assert nets(" ipv6 address 2001:db8:10::1/64") == [("2001:db8:10::/64", "2001:db8:10::1")]


def test_query_parsing_and_safety() -> None:
    assert parse_query("10.1.1.7").is_host and parse_query("10.1.0.0/16").network == ipaddress.ip_network("10.1.0.0/16")
    assert parse_query("10.1.0.0 255.255.0.0").network == ipaddress.ip_network("10.1.0.0/16")
    assert parse_query("snmp-server community").mode == "text"
    assert parse_query("/ntp server \\d+/").mode == "regex" and parse_query("re:^hostname").mode == "regex"
    assert as_network("deadbeef") is None and as_network("17") is None
    for bad in ("/(a+)+$/", "/" + "a" * 300 + "/", "/[unclosed/", "   "):
        with pytest.raises(QueryError):
            parse_query(bad)


def test_ranking_prefers_the_interface_subnet() -> None:
    core = Document("core1", "configs/core1/running-config.cfg", (
        "interface Vlan40\n ip address 10.10.40.2 255.255.255.0\n!\n"
        "router ospf 1\n network 10.10.0.0 0.0.255.255 area 0\n!\n"
        "ip access-list extended GUEST\n 10 deny ip 10.10.40.0 0.0.0.255 10.0.0.0 0.255.255.255\n"
        "ip route 0.0.0.0 0.0.0.0 10.10.0.1\n"
    ), "ios")
    fw = Document("fw1", "configs/fw1/running-config.conf", (
        'config system interface\n    edit "port4"\n        set ip 10.10.40.1 255.255.255.0\n    next\nend\n'
        'config firewall address\n    edit "NET-GUEST"\n        set subnet 10.10.40.0 255.255.255.0\n    next\nend\n'
    ), "fortios")
    other = Document("lon1", "configs/lon1/running-config.cfg", "interface Vlan10\n ip address 10.40.10.2 255.255.255.0\n", "ios")
    result = search([other, fw, core], parse_query("10.10.40.57"))
    assert [h.device for h in result.hits] == ["core1", "fw1"]
    first = result.hits[0].matches[0]
    assert first.role == "interface" and first.kind == "subnet" and first.network == "10.10.40.0/24" and first.section == ["interface Vlan40"]
    assert {m.role for m in result.hits[0].matches} >= {"interface", "route", "acl"}
    assert all(m.network != "0.0.0.0/0" for h in result.hits for m in h.matches)  # default routes are not "where" an IP is
    assert {h.device for h, _ in result.best()} == {"core1", "fw1"}
    assert result.hits[1].matches[0].section == ["system interface", "port4"]

    owned = search([core, fw], parse_query("10.10.40.1"))
    assert [(h.device, m.kind) for h, m in owned.best()] == [("fw1", "exact")]
    wide = search([core, fw, other], parse_query("10.10.0.0/16"))
    assert {h.device for h in wide.hits} == {"core1", "fw1"} and not wide.best()
    assert match_token(ipaddress.ip_network("10.0.0.0/8"), tokens(" ip address 10.10.40.2 255.255.255.0")[0]) == ("within", 64)

    text = search([core, fw], parse_query("guest"))
    assert text.total == 2 and all(m.spans for h in text.hits for m in h.matches)
    regex = search([core], parse_query("/^ ip address /"))
    assert regex.total == 1 and regex.hits[0].matches[0].line_no == 2


def test_document_cache_follows_file_changes(tmp_path: Path) -> None:
    folder = tmp_path / "configs" / "a"
    folder.mkdir(parents=True)
    target = folder / "running-config.cfg"
    target.write_text("hostname a\nsnmp-server community secret123 RO\n", encoding="utf-8")
    cache = DocumentCache()
    entry = [("a", "configs/a/running-config.cfg", "ios", {"site": "x"})]
    masked = cache.load(tmp_path, entry, lambda text, platform: text.replace("secret123", "<removed>"))
    assert "<removed>" in masked[0].text and masked[0].info == {"site": "x"}
    assert cache.load(tmp_path, entry, lambda text, platform: "unused")[0] is masked[0]  # unchanged file: cached
    time.sleep(0.01)
    target.write_text("hostname b\n", encoding="utf-8")
    import os

    os.utime(target, (time.time() + 5, time.time() + 5))
    assert cache.load(tmp_path, entry, lambda text, platform: text)[0].text == "hostname b\n"
    assert cache.load(tmp_path, [("gone", "configs/gone/x.cfg", None, {})], lambda t, p: t) == []
