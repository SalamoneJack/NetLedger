"""netledger sanitize: output that is safe to share and still parses like the original."""

from __future__ import annotations

import io
import ipaddress
import re
from pathlib import Path

import pytest

from netledger.cli import main
from netledger.intel import detect_syntax, parse
from netledger.platforms import get_platform
from netledger.sanitize import Sanitizer, sanitize

from .conftest import needs_git, simulated

KEY = b"a fixed key for tests"

IOS = """\
! Last configuration change at 14:02:11 UTC Fri Oct 30 2026 by jsmith
version 17.9
hostname hq-core-sw01
!
ip domain name corp.acme.com
ip name-server 10.10.0.53
!
username jsmith privilege 15 secret 9 $9$abcdefghijklmn$opqrstuvwxyz0123456789ABCDEFGHI
enable secret 9 $9$aaaaaaaaaaaaaa$bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
!
license udi pid C9500-48Y4C sn FOC2233X1AB
!
banner motd ^CCC
ACME Corp - authorized access only. Call 555-0100.
^C
!
interface Vlan10
 description Users floor 3 - ticket CHG0042
 ip address 10.10.10.2 255.255.255.0
 mac-address 0011.2233.4455
!
interface GigabitEthernet1/0/1
 description Uplink to isp-edge01.corp.acme.com
 ip address 203.0.114.2 255.255.255.252
!
router bgp 65010
 neighbor 203.0.114.1 remote-as 3356
 neighbor 203.0.114.1 description Lumen circuit 12345
 network 10.10.0.0 mask 255.255.0.0
!
ip route 0.0.0.0 0.0.0.0 203.0.114.1
ip access-list extended MGMT
 remark allow the NOC
 10 permit tcp 10.10.99.0 0.0.0.255 host 10.10.10.2 eq 22
!
ip as-path access-list 10 permit ^3356_
route-map ISP-IN permit 10
 set community 65010:100 3356:70
!
snmp-server community ACME-netops-RO RO
snmp-server location HQ Data Room, 1 Main St
snmp-server contact noc@acme.com
ntp server time1.acme.com
crypto pki certificate chain TP-self-signed-1234
 certificate self-signed 01
  3082022B 30820194 A0030201 02020101 300D0609 2A864886 F70D0101 05050030
  quit
ipv6 address 2001:470:1f0b:1a2::1/64
end
"""

FORTIOS = """\
#config-version=FG100F-7.2.8-FW-build1639-240313:opmode=0:vdom=0:user=jdoe
config system global
    set hostname "fw-branch-17"
end
config system admin
    edit "jdoe"
        set accprofile "super_admin"
        set password ENC SH2abcdefghijklmnopqrstuvwxyz0123456789
    next
end
config system interface
    edit "wan1"
        set ip 198.51.99.2 255.255.255.248
        set description "ISP circuit 4471"
    next
    edit "internal"
        set ip 192.168.10.1 255.255.255.0
    next
end
config firewall address
    edit "LAN"
        set subnet 192.168.10.0 255.255.255.0
        set comment "Branch 17 users"
    next
end
config router bgp
    set as 65010
    config neighbor
        edit "198.51.99.1"
            set remote-as 7018
        next
    end
end
config system snmp community
    edit 1
        set name "acme-public"
    next
end
config vpn certificate local
    edit "Branch_Cert"
        set certificate "-----BEGIN CERTIFICATE-----
MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ
RTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYD
-----END CERTIFICATE-----"
    next
end
"""

JUNOS = """\
## Last commit: 2026-10-30 14:02:11 UTC by jdoe
system {
    host-name spine-atl-01;
    domain-name dc.acme.net;
    login {
        user jdoe {
            uid 2001;
            class super-user;
            authentication {
                encrypted-password "$6$abc$defghijklmnop"; ## SECRET-DATA
                ssh-rsa "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 jdoe@laptop.acme.net"; ## SECRET-DATA
            }
        }
    }
    ntp {
        server ntp1.dc.acme.net;
    }
}
interfaces {
    xe-0/0/0 {
        description "to leaf-atl-03 xe-0/0/48";
        unit 0 {
            family inet {
                address 172.20.1.1/31;
            }
            family inet6 {
                address 2001:470:1f0b:1a2::1/64;
            }
        }
    }
}
protocols {
    bgp {
        group LEAFS {
            local-as 65100;
            neighbor 172.20.1.0 {
                peer-as 65201;
            }
        }
    }
}
snmp {
    location "Atlanta DC1 cage 4";
    community atl-secret {
        authorization read-only;
    }
}
"""

PANOS = """\
set deviceconfig system hostname pa-edge-01
set deviceconfig system domain acme.net
set deviceconfig system ip-address 10.40.0.5
set deviceconfig system netmask 255.255.255.0
set mgt-config users jdoe phash $1$abcdefgh$ijklmnopqrstuvwxyz0123
set mgt-config users jdoe permissions role-based superuser yes
set network interface ethernet ethernet1/1 layer3 ip 198.51.99.20/29
set address WEB-01 ip-netmask 10.40.10.21/32
set address WEB-01 description "Web server for orders.acme.net"
set rulebase security rules allow-web source [ 10.40.0.0/16 ]
set rulebase security rules allow-web description "Ticket CHG-1234 by jdoe"
set network virtual-router default protocol bgp local-as 65300
"""

ROUTEROS = """\
# 2026-10-30 14:02:11 by RouterOS 7.14.3
# software id = AB12-CD34
# model = CCR2004-1G-12S+2XS
# serial number = HEZ08ABCDEF
/interface ethernet set [ find default-name=ether1 ] comment="Uplink to ISP 4471" mac-address=4C:5E:0C:12:34:56
/ip address add address=10.30.0.1/24 interface=bridge network=10.30.0.0
/ip firewall filter add action=accept chain=input src-address=10.30.0.0/24 comment="Office LAN"
/routing bgp connection add as=65400 local.role=ebgp name=isp remote.address=198.51.99.1 remote.as=7018
/system identity set name=rtr-branch-09
/user add group=full name=jdoe password="hunter2"
/snmp set contact="noc@acme.net" location="Branch 9"
"""

SAMPLES = {
    "ios": (IOS, [
        "hq-core-sw01", "jsmith", "acme", "10.10.10.2", "203.0.114", "FOC2233X1AB", "3356", "65010", "CHG0042", "Lumen",
        "Main St", "2233.4455", "$9$", "3082022B", "555-0100", "2001:470:1f0b", "time1",
    ]),
    "fortios": (FORTIOS, [
        "fw-branch-17", "jdoe", "SH2abc", "198.51.99.2", "192.168.10", "ISP circuit", "Branch 17", "65010", "7018", "acme",
        "MIIDdzCC", "RTESMBAGA1",
    ]),
    "junos": (JUNOS, [
        "spine-atl-01", "jdoe", "acme", "AAAAB3", "$6$abc", "172.20.1", "leaf-atl-03", "65100", "65201", "Atlanta",
        "atl-secret", "2001:470",
    ]),
    "panos": (PANOS, ["pa-edge-01", "acme", "10.40.", "jdoe", "$1$abc", "198.51.99.20", "orders", "CHG-1234", "65300"]),
    "routeros": (ROUTEROS, [
        "AB12-CD34", "HEZ08ABCDEF", "Uplink to ISP", "0C:12:34:56", "10.30.0", "Office LAN", "65400", "7018", "198.51.99.1",
        "rtr-branch-09", "jdoe", "hunter2", "acme", "Branch 9",
    ]),
}


def shape(text: str, platform: str | None) -> tuple[str, list[int | None], set[int]]:
    parsed = parse(text, platform=platform)
    return parsed.syntax, [len(p) if p is not None else None for p in parsed.paths], parsed.headers


@pytest.mark.parametrize("platform", [*SAMPLES, None])
def test_output_parses_like_the_original(platform: str | None) -> None:
    for name, (text, _) in SAMPLES.items():
        if platform not in (None, name):
            continue
        result = Sanitizer(get_platform(name) if platform else None, key=KEY).sanitize(text)
        assert result.count("\n") == text.count("\n")
        assert detect_syntax(result) == detect_syntax(text)
        assert shape(result, platform) == shape(text, platform), name


@pytest.mark.parametrize("name", list(SAMPLES))
def test_nothing_identifying_survives(name: str) -> None:
    text, sensitive = SAMPLES[name]
    sanitizer = Sanitizer(get_platform(name), key=KEY)
    result = sanitizer.sanitize(text)
    leaked = [token for token in sensitive if token.lower() in result.lower()]
    assert not leaked, f"{name} leaked {leaked}:\n{result}"
    assert sanitizer.counts["secrets"] and sanitizer.counts["addresses"] and sanitizer.counts["names"]


SUBNETS = """\
interface Vlan10
 ip address 10.10.10.2 255.255.255.0
interface Vlan20
 ip address 10.10.20.1 255.255.255.0
router ospf 1
 network 10.10.0.0 0.0.255.255 area 0
ip route 172.16.5.0 255.255.255.0 10.10.10.254
ip access-list extended X
 permit ip host 10.10.10.2 any
 permit ip 10.10.20.0 0.0.0.255 any
ntp server 8.8.8.8
ipv6 route 2001:470:1f0b:1a2::/64 2001:470:1f0b:1a2::1
"""


def addresses(line: str) -> list[str]:
    return re.findall(r"\d+\.\d+\.\d+\.\d+|[0-9a-f]*:[0-9a-f:]+", line)


def test_addresses_are_consistent_and_keep_their_subnets() -> None:
    lines = sanitize(SUBNETS, "ios", key=KEY).splitlines()
    vlan10, vlan20 = addresses(lines[1])[0], addresses(lines[3])[0]
    assert addresses(lines[1])[1] == addresses(lines[3])[1] == "255.255.255.0"  # masks and wildcards are kept
    ospf_net, ospf_wildcard = addresses(lines[5])
    assert ospf_wildcard == "0.0.255.255" and ipaddress.ip_address(vlan10) in ipaddress.ip_network(f"{ospf_net}/16")
    route_net, route_mask, next_hop = addresses(lines[6])
    assert route_mask == "255.255.255.0" and route_net.endswith(".0") and ipaddress.ip_address(route_net) in ipaddress.ip_network("172.16.0.0/12")
    assert ipaddress.ip_address(next_hop) in ipaddress.ip_network(f"{vlan10}/24", strict=False)
    assert addresses(lines[8])[0] == vlan10  # the same address, the same replacement
    acl_net = addresses(lines[9])[0]
    assert ipaddress.ip_address(vlan20) in ipaddress.ip_network(f"{acl_net}/24")  # a network stays a network
    assert all(ipaddress.ip_address(a) in ipaddress.ip_network("10.0.0.0/8") for a in (vlan10, vlan20, ospf_net))
    ntp = addresses(lines[10])[0]
    assert ntp != "8.8.8.8" and ntp.startswith("8.")
    v6_net, v6_hop = addresses(lines[11])
    assert ipaddress.ip_address(v6_hop) in ipaddress.ip_network(f"{v6_net}/64") and not v6_net.startswith("2001:470:1f0b")

    private = sanitize(SUBNETS, "ios", keep_private=True, key=KEY)
    assert "10.10.10.2" in private and "172.16.5.0" in private and "8.8.8.8" not in private
    assert sanitize(SUBNETS, "ios", key=KEY) == "\n".join(lines) + "\n"
    assert sanitize(SUBNETS, "ios", key=b"another key") != "\n".join(lines) + "\n"


def test_as_numbers_map_into_the_private_range() -> None:
    result = sanitize(IOS, "ios", key=KEY)
    assert "router bgp 64512" in result and "remote-as 64513" in result
    assert "set community 64512:100 64513:70" in result and "permit ^64513_" in result


def test_cli_file_stdin_and_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    source, target = tmp_path / "running.cfg", tmp_path / "clean.cfg"
    source.write_text(IOS, encoding="utf-8")
    assert main(["sanitize", str(source), "--platform", "ios", "-o", str(target)]) == 0
    written = target.read_text(encoding="utf-8")
    assert "hq-core-sw01" not in written and "hostname device1" in written
    monkeypatch.setattr("sys.stdin", io.StringIO(ROUTEROS))
    assert main(["sanitize", "--keep-private"]) == 0
    out = capsys.readouterr().out
    assert "10.30.0.1/24" in out and "rtr-branch-09" not in out
    assert main(["sanitize", str(source), "--platform", "no-such-os"]) == 2
    assert main(["sanitize", str(tmp_path / "missing.cfg")]) == 2


@needs_git
def test_cli_sanitizes_a_stored_configuration(make_env, capsys: pytest.CaptureFixture[str]) -> None:  # noqa: ANN001
    from netledger.backup import BackupRunner
    from netledger.inventory import load_inventory
    from netledger.state import StateStore

    settings = make_env([simulated("core1", "ios")])
    devices = load_inventory(settings)
    BackupRunner(settings, StateStore(settings.data_path / "state.json")).run(devices, inventory=devices)
    config = str(settings.config_path)
    assert main(["--config", config, "sanitize", "--device", "core1"]) == 0
    out = capsys.readouterr().out
    stored = (settings.data_path / "repo/configs/core1/running-config.cfg").read_text(encoding="utf-8")
    assert "core1" in stored and "core1" not in out
    assert shape(out, "ios") == shape(stored, "ios")
    assert main(["--config", config, "sanitize", "--device", "nope"]) == 2
