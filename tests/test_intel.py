"""Change intelligence: section detection per syntax, classification, risk and summaries."""

from __future__ import annotations

from netledger.intel import analyze, classify, commit_summary, detect_syntax, parse

IOS_BEFORE = """\
hostname core1
!
vlan 10
 name USERS
!
interface Vlan10
 description USERS
 ip address 10.10.10.2 255.255.255.0
!
interface GigabitEthernet1/0/8
 description printer
 switchport access vlan 10
!
router ospf 1
 network 10.10.0.0 0.0.255.255 area 0
!
snmp-server location Rack A3
ntp server 10.0.0.1
line vty 0 4
 transport input ssh
"""


def ios_after() -> str:
    return (
        IOS_BEFORE.replace("vlan 10\n name USERS\n!\n", "vlan 10\n name USERS\n!\nvlan 40\n name GUEST-WIFI\n!\n")
        .replace(" switchport access vlan 10\n", " switchport access vlan 40\n shutdown\n")
        .replace("snmp-server location Rack A3", "snmp-server location Rack A4")
        + "ip access-list extended GUEST\n 10 deny ip any 10.0.0.0 0.255.255.255\n"
    )


def test_ios_changes_are_grouped_classified_and_scored() -> None:
    analysis = analyze(IOS_BEFORE, ios_after(), "ios")
    assert analysis.syntax == "indent" and analysis.risk == "high"
    texts = analysis.highlights
    assert "Added VLAN 40 (GUEST-WIFI)" in texts
    assert "Added ACL GUEST" in texts
    assert "interface GigabitEthernet1/0/8: switchport access vlan 10 → 40, shut down" in texts
    assert "snmp-server location: Rack A3 → Rack A4" in texts
    by_label = {item.label: item for item in analysis.items}
    assert by_label["interface GigabitEthernet1/0/8"].risk == "high"  # shutting a port down
    assert by_label["VLAN 40"].category == "switching" and by_label["VLAN 40"].risk == "medium"
    assert by_label["snmp-server location"].category == "services" and by_label["snmp-server location"].risk == "low"
    categories = {c["key"] for c in analysis.categories()}
    assert {"firewall", "interfaces", "switching", "services"} <= categories
    assert texts[0] in ("Added ACL GUEST", "interface GigabitEthernet1/0/8: switchport access vlan 10 → 40, shut down")  # high risk first
    assert 0 < analysis.score <= 100
    summary = commit_summary(analysis)
    assert summary[0].startswith("Risk:       high (") and summary[1] == "Summary:" and summary[2].startswith("  - ")


def test_descriptions_are_low_risk_and_names_are_free_text() -> None:
    before = "interface Ethernet3\n   description esxi-03 vmnic0\n!\nvlan 10\n   name USERS\n!\n"
    after = "interface Ethernet3\n   description esxi-03 vmnic0 (moved to 25G)\n!\nvlan 10\n   name ADMIN-USERS\n!\n"
    analysis = analyze(before, after, "eos")
    assert analysis.risk == "low"
    assert {i.category for i in analysis.items} == {"docs"}
    assert "interface Ethernet3: description esxi-03 vmnic0 → …(moved to 25G)" in analysis.highlights
    # "USERS" inside a name must not be mistaken for an access/AAA change
    assert classify(("vlan 10",), "   name USERS") == "switching"


def test_fortios_blocks_use_policy_names() -> None:
    before = (
        'config firewall policy\n    edit 2\n        set name "Servers"\n        set service "HTTPS"\n    next\nend\n'
        "config system dns\n    set primary 10.0.0.53\nend\n"
    )
    after = (
        'config firewall policy\n    edit 2\n        set name "Servers"\n        set service "HTTPS" "SSH"\n    next\n'
        '    edit 4\n        set name "Guest"\n        set action accept\n        set nat enable\n    next\nend\n'
        "config system dns\n    set primary 10.0.0.54\nend\n"
    )
    analysis = analyze(before, after, "fortios")
    assert analysis.syntax == "fortios"
    assert 'firewall policy 2 (Servers): service "HTTPS" → …"SSH"' in analysis.highlights
    assert "Added firewall policy 4 (Guest)" in analysis.highlights
    assert "dns: primary 10.0.0.53 → 10.0.0.54" in analysis.highlights
    added = next(i for i in analysis.items if i.action == "added")
    assert added.category == "firewall" and "nat" in added.categories and added.risk == "high"


def test_junos_braces_and_nested_sections() -> None:
    before = "protocols {\n    bgp {\n        group LEAFS {\n            neighbor 10.255.1.1;\n        }\n    }\n}\n"
    after = "protocols {\n    bgp {\n        group LEAFS {\n            neighbor 10.255.1.1;\n            neighbor 10.255.1.5;\n        }\n    }\n}\n"
    analysis = analyze(before, after, "junos")
    assert analysis.syntax == "braces" and analysis.risk == "high"
    assert analysis.highlights == ["bgp group LEAFS: added neighbor 10.255.1.5"]
    assert analysis.items[0].category == "routing"


def test_set_style_and_routeros() -> None:
    panos_before = "set deviceconfig system hostname fw1\nset rulebase security rules web from trust\n"
    panos_after = panos_before + "set rulebase security rules o365 from trust\nset rulebase security rules o365 action allow\n"
    analysis = analyze(panos_before, panos_after, "panos")
    assert analysis.syntax == "set" and analysis.highlights == ["Added security rule o365"] and analysis.risk == "high"

    ros_before = "/ip address add address=10.30.0.1/24 interface=bridge\n/ip firewall filter add action=drop chain=input\n"
    ros_after = ros_before.replace(
        "/ip firewall filter add action=drop chain=input\n",
        '/ip firewall filter add action=accept chain=input comment="WireGuard" dst-port=13231 protocol=udp\n/ip firewall filter add action=drop chain=input\n',
    )
    analysis = analyze(ros_before, ros_after, "routeros")
    assert analysis.syntax == "routeros" and analysis.highlights == ['Added firewall filter rule "WireGuard"']


def test_initial_and_unchanged() -> None:
    initial = analyze(None, IOS_BEFORE, "ios")
    assert initial.initial and initial.risk is None and initial.summary() == "initial backup"
    same = analyze(IOS_BEFORE, IOS_BEFORE + "!\n", "ios")
    assert same.items == [] and same.risk == "low"
    assert analyze(IOS_BEFORE, IOS_BEFORE.replace("!", "! comment"), "ios").items == []  # comments are not changes


def test_syntax_detection_and_folding_blocks() -> None:
    assert detect_syntax(IOS_BEFORE) == "indent"
    assert detect_syntax("config system global\n    set hostname a\nend\n") == "fortios"
    assert detect_syntax("system {\n    host-name a;\n}\ninterfaces {\n    ge-0/0/0 {\n        mtu 9216;\n    }\n}\n") == "braces"
    assert detect_syntax("set a b\nset c d\nset e f\n") == "set"
    assert detect_syntax("/ip address add address=10.0.0.1/24\n/system identity set name=r1\n") == "routeros"
    parsed = parse(IOS_BEFORE, platform="ios")
    blocks = parsed.blocks()
    vlan10 = parsed.lines.index("vlan 10")
    assert blocks[vlan10] == vlan10 + 1  # "vlan 10" folds its " name USERS" child
    assert parsed.paths[vlan10 + 1] == ("vlan 10",)
