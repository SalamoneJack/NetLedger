"""Risk reasons: why a change got its level, per vendor syntax, and where the reasons are shown."""

from __future__ import annotations

import pytest

from netledger.intel import Analysis, ChangeItem, analyze, commit_summary

WIDER = ("now allows any", "now allows a wider", "new rule allows any")


def why(old: str, new: str, platform: str) -> list[str]:
    return analyze(old, new, platform).reasons


def widened(reasons: list[str]) -> bool:
    return any(marker in reason for reason in reasons for marker in WIDER)


# --------------------------------------------------------------------------- IOS-style access lists


def ios_acl(*entries: str) -> str:
    return "hostname r1\n!\nip access-list extended WEB\n" + "".join(f" {entry}\n" for entry in entries) + "!\nend\n"


IOS_WIDENING = [
    ("permit tcp 10.20.0.0 0.0.0.255 host 10.0.0.5 eq 443", "permit tcp any host 10.0.0.5 eq 443",
     "ACL WEB now allows any source (was 10.20.0.0/24)"),
    ("permit ip host 10.1.1.5 any", "permit ip 10.1.1.0 0.0.0.255 any",
     "ACL WEB now allows a wider source: 10.1.1.0/24 (was 10.1.1.5)"),
    ("permit ip 10.1.1.0 0.0.0.255 any", "permit ip 10.1.0.0 0.0.255.255 any",
     "ACL WEB now allows a wider source: 10.1.0.0/16 (was 10.1.1.0/24)"),
    ("permit tcp any host 10.0.0.5 eq 443", "permit tcp any 10.0.0.0 0.0.0.255 eq 443",
     "ACL WEB now allows a wider destination: 10.0.0.0/24 (was 10.0.0.5)"),
    ("permit tcp any host 10.0.0.5 eq 443", "permit ip any host 10.0.0.5",
     "ACL WEB now allows any service (was tcp/443)"),
    ("permit tcp any host 10.0.0.5 eq 443", "permit tcp any host 10.0.0.5 range 1 1024",
     "ACL WEB now allows a wider service: tcp/1-1024 (was tcp/443)"),
]


@pytest.mark.parametrize(("old", "new", "expected"), IOS_WIDENING)
def test_ios_acl_widening_is_high_risk_and_explained(old: str, new: str, expected: str) -> None:
    analysis = analyze(ios_acl("permit icmp any any", old), ios_acl("permit icmp any any", new), "ios")
    assert analysis.risk == "high" and expected in analysis.reasons
    item = analysis.items[0]
    assert item.explained and item.reasons[0] == expected and item.risk == "high"


@pytest.mark.parametrize(("old", "new", "expected"), IOS_WIDENING)
def test_ios_acl_narrowing_is_not_widening(old: str, new: str, expected: str) -> None:
    reasons = why(ios_acl(new), ios_acl(old), "ios")
    assert not widened(reasons), reasons
    assert any("now allows a narrower" in reason for reason in reasons)


def test_sequence_numbered_acls_and_prefix_notation() -> None:
    before = "ip access-list MGMT\n  10 permit ip 10.1.0.0/16 any\n  20 deny ip any any\n"
    after = "ip access-list MGMT\n  10 permit ip 10.0.0.0/8 any\n  20 deny ip any any\n"
    assert why(before, after, "nxos") == ["ACL MGMT entry 10 now allows a wider source: 10.0.0.0/8 (was 10.1.0.0/16)"]
    assert why(after, before, "nxos") == ["ACL MGMT entry 10 now allows a narrower source: 10.1.0.0/16 (was 10.0.0.0/8)"]


def test_asa_netmask_notation() -> None:
    old = "access-list OUTSIDE_IN extended permit tcp any host 203.0.113.10 eq https\n"
    new = "access-list OUTSIDE_IN extended permit tcp any 203.0.113.0 255.255.255.0 eq https\n"
    assert "ACL OUTSIDE_IN now allows a wider destination: 203.0.113.0/24 (was 203.0.113.10)" in why(old, new, "asa")
    assert not widened(why(new, old, "asa"))
    old = "access-list OUTSIDE_IN extended permit tcp 198.51.100.0 255.255.255.0 host 203.0.113.10 eq https\n"
    new = "access-list OUTSIDE_IN extended permit tcp 0.0.0.0 0.0.0.0 host 203.0.113.10 eq https\n"
    assert "ACL OUTSIDE_IN now allows any source (was 198.51.100.0/24)" in why(old, new, "asa")


def test_access_lists_attached_to_and_removed_from_interfaces() -> None:
    plain = "interface Vlan40\n ip address 10.10.40.1 255.255.255.0\n!\n"
    filtered = plain.replace("255.255.255.0\n", "255.255.255.0\n ip access-group GUEST in\n")
    assert why(plain, filtered, "ios") == ["ACL GUEST now filters inbound traffic on interface Vlan40"]
    analysis = analyze(filtered, plain, "ios")
    assert analysis.risk == "high" and analysis.reasons == ["ACL GUEST removed from interface Vlan40: inbound traffic there is no longer filtered"]
    asa = "hostname fw1\naccess-group OUTSIDE_IN in interface outside\n"
    assert why(asa, "hostname fw1\n", "asa") == ["ACL OUTSIDE_IN removed from interface outside: inbound traffic there is no longer filtered"]


def test_new_and_removed_rules_read_as_opening_or_tightening() -> None:
    base = ios_acl("permit tcp any host 10.0.0.5 eq 443")
    opened = why(base, ios_acl("permit tcp any host 10.0.0.5 eq 443", "permit ip any any"), "ios")
    assert opened == ["ACL WEB: new rule allows any source, any destination and any service"]
    tightened = why(base, ios_acl("deny ip 10.9.0.0 0.0.255.255 any", "permit tcp any host 10.0.0.5 eq 443"), "ios")
    assert tightened == ["ACL WEB: new deny rule tightens access (10.9.0.0/16 → any, any)"]
    loosened = why(ios_acl("deny ip 10.9.0.0 0.0.255.255 any", "permit tcp any host 10.0.0.5 eq 443"), base, "ios")
    assert loosened == ["ACL WEB: deny rule removed, so traffic it blocked may now be allowed"]
    flipped = why(ios_acl("deny tcp any host 10.0.0.5 eq 23"), ios_acl("permit tcp any host 10.0.0.5 eq 23"), "ios")
    assert flipped == ["ACL WEB now permits traffic it used to deny"]


# --------------------------------------------------------------------------- FortiOS policies


def forti_policy(srcaddr: str = '"10.20.0.0/24"', dstaddr: str = '"WEB"', service: str = '"HTTPS"', action: str = "accept", number: int = 12) -> str:
    return (
        "config firewall policy\n"
        f"    edit {number}\n"
        '        set name "Web"\n'
        '        set srcintf "port2"\n'
        '        set dstintf "port1"\n'
        f"        set srcaddr {srcaddr}\n"
        f"        set dstaddr {dstaddr}\n"
        f"        set action {action}\n"
        '        set schedule "always"\n'
        f"        set service {service}\n"
        "    next\n"
        "end\n"
    )


FORTI_WIDENING = [
    ({}, {"srcaddr": '"all"'}, "Policy 12 now allows any source (was 10.20.0.0/24)"),
    ({}, {"dstaddr": '"all"'}, "Policy 12 now allows any destination (was WEB)"),
    ({}, {"service": '"ALL"'}, "Policy 12 now allows any service (was HTTPS)"),
    ({"srcaddr": '"LAN"'}, {"srcaddr": '"LAN" "DMZ"'}, "Policy 12 now allows a wider source: LAN, DMZ (was LAN)"),
    ({}, {"srcaddr": '"10.20.0.0/16"'}, "Policy 12 now allows a wider source: 10.20.0.0/16 (was 10.20.0.0/24)"),
]


@pytest.mark.parametrize(("old", "new", "expected"), FORTI_WIDENING)
def test_fortios_policy_widening(old: dict[str, str], new: dict[str, str], expected: str) -> None:
    before, after = forti_policy(**old), forti_policy(**{**old, **new})
    analysis = analyze(before, after, "fortios")
    assert analysis.risk == "high" and analysis.reasons == [expected]
    assert not widened(why(after, before, "fortios"))


def test_fortios_deny_policies_and_new_policies() -> None:
    deny_before, deny_after = forti_policy(action="deny"), forti_policy(action="deny", srcaddr='"all"')
    reasons = why(deny_before, deny_after, "fortios")
    assert reasons == ["Policy 12 now blocks any source (was 10.20.0.0/24)"] and not widened(reasons)
    empty = "config firewall policy\nend\n"
    assert why(empty, forti_policy(dstaddr='"all"', number=4), "fortios") == ["Policy 4: new rule allows any destination"]
    assert why(empty, forti_policy(action="deny", number=5), "fortios")[0].startswith("Policy 5: new deny rule tightens access")


# --------------------------------------------------------------------------- PAN-OS


def panos_rule(source: str = "[ 10.1.1.0/24 ]", service: str = "service-https", application: str = "ssl", action: str = "allow") -> str:
    lines = ("from trust", "to untrust", f"source {source}", "destination any", f"service {service}", f"application {application}", f"action {action}")
    return "set deviceconfig system hostname fw1\n" + "".join(f"set rulebase security rules web {line}\n" for line in lines)


PANOS_WIDENING = [
    ({}, {"source": "any"}, "Security rule web now allows any source (was 10.1.1.0/24)"),
    ({}, {"source": "[ 10.1.0.0/16 ]"}, "Security rule web now allows a wider source: 10.1.0.0/16 (was 10.1.1.0/24)"),
    ({}, {"service": "any"}, "Security rule web now allows any service (was service-https)"),
    ({}, {"application": "any"}, "Security rule web now allows any application (was ssl)"),
]


@pytest.mark.parametrize(("old", "new", "expected"), PANOS_WIDENING)
def test_panos_rule_widening(old: dict[str, str], new: dict[str, str], expected: str) -> None:
    before, after = panos_rule(**old), panos_rule(**{**old, **new})
    assert why(before, after, "panos") == [expected]
    assert not widened(why(after, before, "panos"))


def test_panos_deny_rule_is_not_widening() -> None:
    reasons = why(panos_rule(action="deny"), panos_rule(action="deny", source="any"), "panos")
    assert reasons and not widened(reasons)


# --------------------------------------------------------------------------- Junos


def junos_term(source: str | None = "10.0.0.0/8", port: str | None = "ssh", action: str = "accept") -> str:
    match = "".join([
        f"                    source-address {{\n                        {source};\n                    }}\n" if source else "",
        "                    protocol tcp;\n",
        f"                    destination-port {port};\n" if port else "",
    ])
    return (
        "firewall {\n    family inet {\n        filter PROTECT-RE {\n            term SSH {\n"
        f"                from {{\n{match}                }}\n"
        f"                then {action};\n"
        "            }\n        }\n    }\n}\n"
    )


JUNOS_WIDENING = [
    ({}, {"source": "0.0.0.0/0"}, "Filter PROTECT-RE term SSH now allows any source (was 10.0.0.0/8)"),
    ({"source": "10.1.0.0/16"}, {"source": "10.0.0.0/8"}, "Filter PROTECT-RE term SSH now allows a wider source: 10.0.0.0/8 (was 10.1.0.0/16)"),
    ({}, {"source": None}, "Filter PROTECT-RE term SSH now allows any source (was 10.0.0.0/8)"),
    ({}, {"port": None}, "Filter PROTECT-RE term SSH now allows a wider service: tcp (was tcp/22)"),
]


@pytest.mark.parametrize(("old", "new", "expected"), JUNOS_WIDENING)
def test_junos_filter_term_widening(old: dict[str, str], new: dict[str, str], expected: str) -> None:
    before, after = junos_term(**old), junos_term(**{**old, **new})
    assert why(before, after, "junos") == [expected]
    assert not widened(why(after, before, "junos"))


def test_junos_discard_terms_and_srx_policies() -> None:
    reasons = why(junos_term(action="discard"), junos_term(source="0.0.0.0/0", action="discard"), "junos")
    assert reasons and not widened(reasons)

    def policy(source: str) -> str:
        return (
            "security {\n    policies {\n        from-zone trust to-zone untrust {\n            policy ALLOW-WEB {\n"
            f"                match {{\n                    source-address {source};\n                    destination-address any;\n"
            "                    application junos-https;\n                }\n                then {\n                    permit;\n"
            "                }\n            }\n        }\n    }\n}\n"
        )

    assert why(policy("web-servers"), policy("any"), "junos") == ["Policy ALLOW-WEB (trust to untrust) now allows any source (was web-servers)"]
    assert not widened(why(policy("any"), policy("web-servers"), "junos"))


# --------------------------------------------------------------------------- everything else that explains a risk


IOS_INTERFACE = "interface GigabitEthernet1/0/8\n description printer\n switchport access vlan 10\n!\n"


def test_shutdowns() -> None:
    analysis = analyze(IOS_INTERFACE, IOS_INTERFACE.replace(" switchport access vlan 10\n", " switchport access vlan 10\n shutdown\n"), "ios")
    assert analysis.risk == "high" and analysis.reasons == ["Interface GigabitEthernet1/0/8 shut down: traffic through it stops"]
    forti = 'config system interface\n    edit "port3"\n        set ip 10.3.3.1 255.255.255.0\n    next\nend\n'
    assert why(forti, forti.replace("        set ip", "        set status down\n        set ip"), "fortios") == ["Interface port3 shut down: traffic through it stops"]
    junos = "interfaces {\n    ge-0/0/1 {\n        description uplink;\n        mtu 9216;\n    }\n}\n"
    assert why(junos, junos.replace("        mtu 9216;\n", "        disable;\n        mtu 9216;\n"), "junos") == ["Interface ge-0/0/1 shut down: traffic through it stops"]


BGP = (
    "router bgp 65010\n bgp router-id 10.255.0.1\n neighbor 10.255.1.1 remote-as 65020\n neighbor 10.255.1.1 description leaf1\n"
    " neighbor 10.255.1.5 remote-as 65020\n neighbor 10.255.1.5 description leaf2\n!\n"
)


def test_routing_neighbors_redistribution_and_default_routes() -> None:
    without = BGP.replace(" neighbor 10.255.1.5 remote-as 65020\n neighbor 10.255.1.5 description leaf2\n", "")
    analysis = analyze(BGP, without, "ios")
    assert analysis.risk == "high" and analysis.reasons == ["BGP neighbor 10.255.1.5 removed: routes learned from it are withdrawn"]
    assert why(without, BGP, "ios") == ["New BGP neighbor 10.255.1.5 (AS 65020)"]
    renamed = why(BGP, BGP.replace("description leaf1", "description leaf-1"), "ios")
    assert not any("removed" in reason for reason in renamed)  # only a neighbor attribute changed

    junos = "protocols {\n    bgp {\n        group LEAFS {\n            neighbor 10.255.1.1;\n            neighbor 10.255.1.5;\n        }\n    }\n}\n"
    assert why(junos, junos.replace("            neighbor 10.255.1.5;\n", ""), "junos") == ["BGP neighbor 10.255.1.5 removed: routes learned from it are withdrawn"]

    ospf = "router ospf 1\n router-id 10.255.0.1\n network 10.0.0.0 0.255.255.255 area 0\n!\n"
    added = why(ospf, ospf.replace(" network", " redistribute static subnets\n network"), "ios")
    assert added == ["Redistribution added in OSPF 1: redistribute static subnets, so more routes are advertised"]
    assert why(ospf.replace(" network", " redistribute static subnets\n network"), ospf, "ios")[0].startswith("Redistribution removed in OSPF 1")

    routes = "hostname r1\nip route 0.0.0.0 0.0.0.0 10.1.1.1\nip route 10.50.0.0 255.255.0.0 10.1.1.2\n"
    analysis = analyze(routes, "hostname r1\nip route 10.50.0.0 255.255.0.0 10.1.1.2\n", "ios")
    assert analysis.risk == "high" and analysis.reasons[0] == "Default route removed: traffic with no more specific route has nowhere to go"
    changed = why(routes, routes.replace("0.0.0.0 0.0.0.0 10.1.1.1", "0.0.0.0 0.0.0.0 10.1.1.9"), "ios")
    assert changed[0] == "Default route changed: traffic with no more specific route takes a new path"


def test_accounts_and_aaa() -> None:
    base = "hostname r1\nusername ops privilege 1 secret 9 <removed>\n"
    analysis = analyze(base, base + "username jdoe privilege 15 secret 9 <removed>\n", "ios")
    assert analysis.risk == "high" and analysis.reasons == ["New admin account 'jdoe' (privilege 15)"]
    assert why(base, base.replace("privilege 1 ", "privilege 15 "), "ios") == ["Account 'ops' rights changed: privilege 1 → privilege 15"]
    assert why(base, "hostname r1\n", "ios") == ["Account 'ops' removed"]

    forti = 'config system admin\n    edit "jdoe"\n        set accprofile "super_admin"\n        set vdom "root"\n    next\nend\n'
    assert why("config system admin\nend\n", forti, "fortios") == ["New admin account 'jdoe' (profile super_admin)"]
    trusted = forti.replace('        set vdom "root"\n', '        set trusthost1 10.0.0.0 255.0.0.0\n        set vdom "root"\n')
    assert "Admin 'jdoe' can now log in from anywhere (was 10.0.0.0/8)" in why(trusted, forti, "fortios")

    junos = "system {\n    login {\n        user jdoe {\n            uid 2001;\n            class operator;\n        }\n    }\n}\n"
    assert why(junos, junos.replace("class operator", "class super-user"), "junos") == [
        "Account 'jdoe' rights changed: class operator → class super-user"
    ]

    aaa = "hostname r1\naaa new-model\naaa authentication login default local\n"
    changed = why(aaa, aaa.replace("default local", "default group tacacs+ local"), "ios")
    assert changed == ["AAA authentication changed: aaa authentication login default group tacacs+ local"]
    server = "tacacs server ISE-2\n address ipv4 10.10.0.41\n key 7 <removed>\n!\n"
    assert why("hostname r1\n", "hostname r1\n" + server, "ios") == ["TACACS+ server ISE-2 added: logins are checked against it"]


def test_management_access() -> None:
    forti = 'config system interface\n    edit "wan1"\n        set ip 203.0.113.2 255.255.255.0\n        set allowaccess ping\n    next\nend\n'
    analysis = analyze(forti, forti.replace("set allowaccess ping", "set allowaccess ping https telnet"), "fortios")
    assert analysis.risk == "high"
    assert analysis.reasons == ["Interface wan1 now accepts https and telnet management access (unencrypted)"]
    vty = "line vty 0 4\n access-class MGMT in\n transport input ssh\n!\n"
    reasons = why(vty, vty.replace(" access-class MGMT in\n", "").replace("input ssh", "input telnet ssh"), "ios")
    assert reasons == [
        "Line vty 0 4 now accepts telnet logins (unencrypted)",
        "Line vty 0 4 lost its access-class: logins are allowed from any address",
    ]


def test_nat() -> None:
    base = "hostname r1\n"
    published = analyze(base, base + "ip nat inside source static 10.1.1.10 203.0.113.10\n", "ios")
    assert published.risk == "high"
    assert published.reasons == ["Static NAT added: ip nat inside source static 10.1.1.10 203.0.113.10, which exposes an inside host"]
    pat = why(base, base + "ip nat inside source list NAT interface GigabitEthernet0/0 overload\n", "ios")
    assert pat == ["Source NAT added: ip nat inside source list NAT interface GigabitEthernet0/0 overload"]
    vip = 'config firewall vip\n    edit "WEB-VIP"\n        set extip 203.0.113.10\n        set mappedip "10.1.1.10"\n        set extintf "wan1"\n    next\nend\n'
    assert why("config firewall vip\nend\n", vip, "fortios") == ["Static NAT added: WEB-VIP maps 203.0.113.10 to 10.1.1.10, which exposes an inside host"]
    interface = "interface GigabitEthernet0/0\n ip address 203.0.113.2 255.255.255.0\n!\n"
    assert why(interface, interface.replace("255.255.255.0\n", "255.255.255.0\n ip nat outside\n"), "ios") == [
        "NAT turned on in interface GigabitEthernet0/0: ip nat outside"
    ]


def test_address_objects_that_widen_every_rule() -> None:
    forti = 'config firewall address\n    edit "LAN-NET"\n        set subnet 10.20.0.0 255.255.255.0\n    next\nend\n'
    wider = forti.replace("10.20.0.0 255.255.255.0", "10.20.0.0 255.255.0.0")
    analysis = analyze(forti, wider, "fortios")
    assert analysis.risk == "high"
    assert analysis.reasons == ["Address object LAN-NET now covers 10.20.0.0/16 (was 10.20.0.0/24), so every rule that uses it allows more"]
    assert why(wider, forti, "fortios") == ["Address object LAN-NET now covers less: 10.20.0.0/24 (was 10.20.0.0/16)"]


# --------------------------------------------------------------------------- aggregation, size and output


def test_size_reason_category_defaults_and_ordering() -> None:
    vlans = "".join(f"vlan {n}\n name V{n}\n!\n" for n in range(100, 180))  # 160 changed lines
    analysis = analyze("hostname r1\n", "hostname r1\n" + vlans, "ios")
    assert analysis.risk == "high"  # medium, raised one level by the size
    assert analysis.reasons[0].startswith("Large change: ") and analysis.reasons[0].endswith(" lines")
    assert "VLANs & switching change (medium risk by default): VLAN 100" in analysis.reasons

    docs = analyze(IOS_INTERFACE, IOS_INTERFACE.replace("printer", "printer (2nd floor)"), "ios")
    assert docs.risk == "low" and docs.reasons == ["Only descriptions or names changed: interface GigabitEthernet1/0/8"]

    mixed = analyze(IOS_INTERFACE + "ntp server 10.0.0.1\n", IOS_INTERFACE.replace("vlan 10\n", "vlan 10\n shutdown\n") + "ntp server 10.0.0.2\n", "ios")
    assert mixed.reasons == [
        "Interface GigabitEthernet1/0/8 shut down: traffic through it stops",
        "Management services change (low risk by default): ntp server",
    ]


def test_reasons_are_deduplicated_and_serialized() -> None:
    items = [
        ChangeItem(("a",), "a", "modified", "firewall", "high", "a changed", reasons=["Same reason", "Explains"], reason_ranks=[0, 1]),
        ChangeItem(("b",), "b", "modified", "firewall", "high", "b changed", reasons=["Same reason", "Raised it"], reason_ranks=[0, 0], order=1),
        ChangeItem(("c",), "c", "modified", "routing", "high", "c changed", reasons=["Category default"], reason_ranks=[2], order=2),
    ]
    analysis = Analysis("high", 68, 2, 2, items, notes=[("high", "Large change: 200 lines")])
    assert analysis.reasons == ["Same reason", "Raised it", "Large change: 200 lines", "Explains", "Category default"]
    assert items[0].explained and not items[2].explained
    data = analysis.to_dict()
    assert data["reasons"] == analysis.reasons and data["items"][1]["reasons"] == ["Same reason", "Raised it"]

    reasons = [f"reason {n}" for n in range(6)]
    many = Analysis("high", 50, 1, 1, [ChangeItem(("c",), "c", "modified", "routing", "high", "c changed", reasons=reasons)])
    summary = commit_summary(many)
    assert summary[1] == "Why:" and summary[2:6] == [f"  - reason {n}" for n in range(4)]
    assert summary[6] == "  - ... and 2 more" and summary[7] == "Summary:"


def test_reasons_in_the_console() -> None:
    from netledger.web.pages import change_entry
    from netledger.web.ui import intel_card

    change = {"device": "fw1", "risk": "high", "reasons": ["Policy 12 now allows any source (was <lab>)", "Second"], "highlights": ["a", "b"]}
    html = change_entry(change, 0.0)
    assert 'class="why" title="Policy 12 now allows any source (was &lt;lab&gt;)' in html
    assert "<lab>" not in html and '<div class="why-block"><span>Why</span>' in html
    assert "policy 12 now allows any source" in html  # searchable in the ledger
    card = intel_card({"risk": "high", "score": 40, "reasons": ["Interface Gi1 shut down"], "categories": [], "items": []})
    assert '<ul class="intel-why" aria-label="Why"><li>Interface Gi1 shut down</li></ul>' in card
