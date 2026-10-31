"""Simulated network devices for demos, tests and screenshots - no hardware required.

Use ``driver: simulated`` on any inventory entry. The device's platform selects the
configuration style; ``optional_args`` tune the simulation:

``cpu`` / ``memory`` / ``temperature``
    Base load (percent) and temperature (Celsius).
``fan_failed`` / ``psu_failed`` / ``temp_alert``
    Simulate hardware faults.
``unreachable`` / ``auth_fail``
    Simulate connection or login failures (``outage_minutes``: unreachable since that long before start).
``change``
    Produce a configuration change when ``SimulatedDriver.revision`` is 2 or higher.
``unsaved``
    Leave that change out of the startup configuration (``write memory`` forgotten).
``memory_leak`` / ``temperature_drift``
    Percent / degrees per day the value keeps rising (for forecast demos).
``neighbors``
    LLDP neighbors: ``{local_port: [remote_name, remote_port]}``.
``uptime_days`` / ``model`` / ``os_version`` / ``serial``
    Facts.
``latency``
    Seconds to "log in" (default: 0.3-1.4 s, fixed per device).

Devices with ``change`` also accumulate a few earlier edits; ``SimulatedDriver.epoch`` selects how
many of them have happened yet (the demo uses it to build weeks of realistic history).
"""

from __future__ import annotations

import base64
import hashlib
import math
import random
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from napalm.base import NetworkDriver
from napalm.base.exceptions import ConnectAuthError, ConnectionException

_STARTED = time.time()


def _seeded(*parts: Any) -> random.Random:
    return random.Random(hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest())


def _token(rng: random.Random, length: int, alphabet: str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") -> str:
    return "".join(rng.choice(alphabet) for _ in range(length))


def _ios_time(dt: datetime) -> str:
    return dt.strftime("%H:%M:%S UTC %a %b ") + str(dt.day) + dt.strftime(" %Y")


class _Ctx:
    def __init__(self, driver: SimulatedDriver, revision: int):
        self.name = driver.name
        self.args = driver.args
        self.revision = revision
        self.changed = revision >= 2 and bool(driver.args.get("change"))
        self.rng = _seeded(driver.name, "config")
        self.octet = 10 + _seeded(driver.name, "octet").randint(1, 200)
        self.site = str(driver.args.get("site_code") or driver.name.split("-")[0])
        self.changed_by = str(driver.args.get("changed_by", "jsmith"))
        now = datetime.now(timezone.utc).replace(microsecond=0)
        self.change_time = now - timedelta(minutes=37) if self.changed else now - timedelta(days=18, hours=3, minutes=12)
        self.legacy_vty = bool(driver.args.get("legacy_vty"))
        self.epoch = int(driver.args.get("epoch", type(driver).epoch))
        self.history = bool(driver.args.get("change"))
        users = ("netadmin", "akhan", "rpatel", "akhan", "dwright", "netadmin")
        self.author = self.changed_by if self.changed else users[min(self.epoch, len(users) - 1)] if self.history else "netadmin"

    def at(self, edit: int) -> bool:
        """Whether earlier edit number ``edit`` has happened (only devices that change accumulate history)."""
        return self.history and self.epoch > edit

    def secret(self, label: str, length: int = 32) -> str:
        return _token(_seeded(self.name, label), length, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./")


# --------------------------------------------------------------------------- config templates


def _ios(c: _Ctx) -> str:
    vlans = [(10, "USERS"), (20, "VOICE"), (30, "SERVERS"), (99, "MGMT")]
    if c.changed:
        vlans.insert(3, (40, "GUEST-WIFI"))
    lines = [
        "Building configuration...",
        "",
        f"Current configuration : {14000 + c.octet * 7} bytes",
        "!",
        f"! Last configuration change at {_ios_time(c.change_time)} by {c.author}",
        f"! NVRAM config last updated at {_ios_time(c.change_time - timedelta(minutes=5))} by netadmin",
        "!",
        "version 17.9",
        "service timestamps debug datetime msec",
        "service timestamps log datetime msec",
        "service password-encryption",
        "platform punt-keepalive disable-kernel-core",
        "!",
        f"hostname {c.name}",
        "!",
        "vrf definition Mgmt-vrf",
        " !",
        " address-family ipv4",
        " exit-address-family",
        "!",
        "logging buffered 64000 informational",
        *(["logging trap informational", "logging host 10.10.0.50"] if c.at(0) else []),
        f"enable secret 9 $9${c.secret('enable', 14)}${c.secret('enable2', 43)}",
        "!",
        "aaa new-model",
        "aaa authentication login default group tacacs+ local",
        "aaa authorization exec default group tacacs+ local",
        "aaa accounting commands 15 default start-stop group tacacs+",
        "!",
        "clock timezone EST -5 0",
        "ip domain name corp.example.net",
        "ip name-server 10.10.0.53 10.20.0.53",
        "login on-success log",
        "!",
        f"username netadmin privilege 15 secret 9 $9${c.secret('user', 14)}${c.secret('user2', 43)}",
        "!",
        "spanning-tree mode rapid-pvst",
        "spanning-tree extend system-id",
        "!",
    ]
    for vid, name in vlans:
        lines += [f"vlan {vid}", f" name {name}", "!"]
    lines += [
        "interface Port-channel1",
        f" description Uplink to {c.name[:-1]}{'2' if c.name.endswith('1') else '1'}",
        " switchport mode trunk",
        "!",
        "interface GigabitEthernet0/0",
        " vrf forwarding Mgmt-vrf",
        f" ip address 10.10.99.{c.octet} 255.255.255.0",
        " negotiation auto",
        "!",
    ]
    for port in range(1, 7):
        peer = c.rng.choice(["hq-dist-sw01", "hq-dist-sw02", "hq-wlc01", "esx-hq-01", "esx-hq-02"])
        suffix = " (rack B2)" if port == 5 and c.at(1) else ""
        lines += [
            f"interface TwentyFiveGigE1/0/{port}",
            f" description {peer} Te1/1/{port}{suffix}",
            " switchport mode trunk",
            *([" channel-group 1 mode active"] if port <= 2 else []),
            "!",
        ]
    for vid, name in vlans:
        if vid == 99:
            continue
        lines += [
            f"interface Vlan{vid}",
            f" description {name}",
            f" ip address 10.10.{vid}.{2 if c.name.endswith('1') else 3} 255.255.255.0",
            f" standby {vid} ip 10.10.{vid}.1",
            f" standby {vid} priority {110 if c.name.endswith('1') else 100}",
            f" standby {vid} preempt",
            *([" ip access-group GUEST-ISOLATION in"] if vid == 40 else []),
            "!",
        ]
    lines += [
        "router ospf 1",
        f" router-id 10.255.0.{c.octet}",
        " passive-interface default",
        " no passive-interface Port-channel1",
        " network 10.10.0.0 0.0.255.255 area 0",
        "!",
        *(["ip route 10.99.0.0 255.255.0.0 10.10.0.254 name LAB-NET", "!"] if c.at(2) else []),
        "ip ssh version 2",
        "ip ssh time-out 60",
        "!",
        "ip access-list standard SNMP-ACL",
        " 10 permit 10.10.99.0 0.0.0.255",
    ]
    if c.changed:
        lines += [
            "ip access-list extended GUEST-ISOLATION",
            " 10 deny ip 10.10.40.0 0.0.0.255 10.0.0.0 0.255.255.255",
            " 20 permit ip any any",
        ]
    lines += [
        "!",
        f"snmp-server community {c.site.upper()}-netops-RO RO SNMP-ACL",
        f"snmp-server location HQ Data Room, Rack {'A4' if c.at(3) else 'A3'}",
        "snmp-server contact noc@example.net",
        "!",
        "tacacs server ISE-1",
        " address ipv4 10.10.0.40",
        f" key 7 {_token(_seeded(c.name, 'tacacs'), 18, '0123456789ABCDEF')}",
        "!",
        "ntp server 10.10.0.123 prefer",
        "ntp server 10.20.0.123",
        f"ntp clock-period {17179000 + int(time.time()) % 997}",
        "!",
        "line con 0",
        " exec-timeout 15 0",
        " stopbits 1",
        "line vty 0 15",
        " access-class SNMP-ACL in",
        " exec-timeout 15 0",
        " transport input telnet ssh" if c.legacy_vty else " transport input ssh",
        "!",
        "end",
    ]
    return "\n".join(lines)


def _fortios(c: _Ctx) -> str:
    rnd = random.Random()  # FortiOS re-encrypts secrets on every display; simulate that
    enc = base64.b64encode(bytes(rnd.getrandbits(8) for _ in range(48))).decode()
    model = str(c.args.get("model", "FortiGate-200F")).replace("FortiGate-", "FG")
    policies = [
        (1, "Users-to-Internet", "port2", "port1", "NET-USERS", "all", "ALL", True),
        (2, "Servers-to-Updates", "port3", "port1", "NET-SERVERS", "FQDN-UPDATES", "HTTPS SSH" if c.at(1) else "HTTPS", True),
        (3, "VPN-DC1", "port2", "to-dc1", "NET-USERS", "NET-DC1", "ALL", False),
    ]
    if c.changed:
        policies.append((4, "Guest-to-Internet", "port4", "port1", "NET-GUEST", "all", "HTTP HTTPS DNS", True))
    lines = [
        f"#config-version={model}-7.4.3-FW-build2573-240201:opmode=0:vdom=0:user=netledger",
        f"#conf_file_ver={rnd.randint(10**13, 10**14)}",
        "#buildno=2573",
        "#global_vdom=1",
        "config system global",
        "    set admin-sport 8443",
        "    set admintimeout 30",
        f'    set alias "{c.args.get("model", "FortiGate-200F")}"',
        f'    set hostname "{c.name}"',
        '    set timezone "US/Eastern"',
        "end",
        "config system interface",
        '    edit "mgmt"',
        f"        set ip 10.10.99.{c.octet} 255.255.255.0",
        "        set allowaccess ping https ssh snmp",
        "        set type physical",
        "    next",
        '    edit "port1"',
        '        set alias "WAN1"',
        "        set ip 203.0.113.10 255.255.255.248",
        "        set allowaccess ping",
        "        set role wan",
        "    next",
        '    edit "port2"',
        '        set alias "INSIDE"',
        "        set ip 10.10.0.1 255.255.255.0",
        "        set allowaccess ping https ssh",
        "        set role lan",
        "    next",
        '    edit "port3"',
        '        set alias "SERVERS"',
        "        set ip 10.10.30.1 255.255.255.0",
        "        set role lan",
        "    next",
    ]
    if c.changed:
        lines += [
            '    edit "port4"',
            '        set alias "GUEST"',
            "        set ip 10.10.40.1 255.255.255.0",
            "        set allowaccess ping",
            "        set role lan",
            "    next",
        ]
    lines += [
        "end",
        "config system admin",
        '    edit "admin"',
        '        set accprofile "super_admin"',
        f"        set password ENC SH2{c.secret('admin', 60)}",
        "    next",
        "end",
        "config system dns",
        "    set primary 10.10.0.53",
        f"    set secondary {'10.30.0.53' if c.at(2) else '10.20.0.53'}",
        "end",
        "config system ntp",
        "    set ntpsync enable",
        "    set type custom",
        "    config ntpserver",
        "        edit 1",
        '            set server "10.10.0.123"',
        "        next",
        "    end",
        "end",
        "config firewall address",
        '    edit "NET-USERS"',
        "        set subnet 10.10.10.0 255.255.255.0",
        "    next",
        '    edit "NET-SERVERS"',
        "        set subnet 10.10.30.0 255.255.255.0",
        "    next",
        '    edit "NET-DC1"',
        "        set subnet 10.20.0.0 255.255.0.0",
        "    next",
    ]
    if c.at(0):
        lines += ['    edit "NET-PRINTERS"', "        set subnet 10.10.50.0 255.255.255.0", "    next"]
    if c.changed:
        lines += ['    edit "NET-GUEST"', "        set subnet 10.10.40.0 255.255.255.0", "    next"]
    lines += ["end", "config firewall policy"]
    for pid, name, src, dst, srcaddr, dstaddr, service, nat in policies:
        lines += [
            f"    edit {pid}",
            f'        set name "{name}"',
            f'        set srcintf "{src}"',
            f'        set dstintf "{dst}"',
            "        set action accept",
            f'        set srcaddr "{srcaddr}"',
            f'        set dstaddr "{dstaddr}"',
            '        set schedule "always"',
            "        set service " + " ".join(f'"{s}"' for s in service.split()),
            "        set utm-status enable",
            '        set ssl-ssh-profile "certificate-inspection"',
            '        set av-profile "default"',
            '        set webfilter-profile "default"',
            "        set logtraffic all",
            *(["        set nat enable"] if nat else []),
            "    next",
        ]
    lines += [
        "end",
        "config vpn ipsec phase1-interface",
        '    edit "to-dc1"',
        '        set interface "port1"',
        "        set peertype any",
        "        set proposal aes256-sha256",
        "        set remote-gw 198.51.100.20",
        f"        set psksecret ENC {enc}",
        "    next",
        "end",
        "config router static",
        "    edit 1",
        "        set gateway 203.0.113.9",
        '        set device "port1"',
        "    next",
        "end",
    ]
    return "\n".join(lines)


def _junos(c: _Ctx) -> str:
    leafs = [("et-0/0/48", "dc1-leaf01 Ethernet49/1", 0), ("et-0/0/49", "dc1-leaf02 Ethernet49/1", 2)]
    if c.changed:
        leafs.append(("et-0/0/50", "dc1-leaf03 Ethernet49/1 (new rack R14)", 4))
    when = c.change_time.strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        f"## Last commit: {when} by {c.changed_by if c.changed else c.author if c.history else 'mlopez'}",
        "version 22.4R3-S2.11;",
        "system {",
        f"    host-name {c.name};",
        "    root-authentication {",
        f'        encrypted-password "$6${c.secret("root", 8)}${c.secret("root2", 86)}"; ## SECRET-DATA',
        "    }",
        "    login {",
        "        user netops {",
        "            uid 2001;",
        "            class super-user;",
        "            authentication {",
        f'                encrypted-password "$6${c.secret("netops", 8)}${c.secret("netops2", 86)}"; ## SECRET-DATA',
        "            }",
        "        }",
        "    }",
        "    services {",
        "        ssh {",
        "            root-login deny;",
        "        }",
        "        netconf {",
        "            ssh;",
        "        }",
        "    }",
        "    ntp {",
        *(["        server 10.10.0.123;"] if c.at(0) else []),
        "        server 10.20.0.123;",
        "    }",
        "}",
        "interfaces {",
    ]
    for ifname, desc, base in leafs:
        lines += [
            f"    {ifname} {{",
            f'        description "{desc}";',
            f"        mtu {9192 if base == 0 and c.at(2) else 9216};",
            "        unit 0 {",
            "            family inet {",
            f"                address 10.255.1.{base}/31;",
            "            }",
            "        }",
            "    }",
        ]
    lines += [
        "    lo0 {",
        "        unit 0 {",
        "            family inet {",
        f"                address 10.255.0.{c.octet}/32;",
        "            }",
        "        }",
        "    }",
        "}",
        "protocols {",
        "    bgp {",
        "        group LEAFS {",
        "            type external;",
        "            export LOOPBACKS;",
        "            peer-as 65031;",
        *(["            bfd-liveness-detection {", "                minimum-interval 300;", "            }"] if c.at(1) else []),
        "            neighbor 10.255.1.1;",
        "            neighbor 10.255.1.3;",
        *(["            neighbor 10.255.1.5;"] if c.changed else []),
        "        }",
        "    }",
        "    lldp {",
        "        interface all;",
        "    }",
        "}",
        "snmp {",
        "    community dc1-ro {",
        "        authorization read-only;",
        "    }",
        "}",
    ]
    return "\n".join(lines)


def _eos(c: _Ctx) -> str:
    model = c.args.get("model", "DCS-7050SX3-48YC8")
    version = c.args.get("os_version", "4.31.2F")
    lines = [
        "! Command: show running-config",
        f"! device: {c.name} ({model}, EOS-{version})",
        "!",
        f"! boot system flash:/EOS-{version}.swi",
        "!",
        "no aaa root",
        "!",
        f"username admin privilege 15 role network-admin secret sha512 $6${c.secret('admin', 16)}${c.secret('admin2', 86)}",
        "!",
        "service routing protocols model multi-agent",
        "!",
        f"hostname {c.name}",
        "ip name-server vrf MGMT 10.20.0.53",
        "dns domain dc1.example.net",
        "!",
        "spanning-tree mode mstp",
        "!",
        "vlan 100",
        "   name PROD-WEB",
        "!",
        "vlan 200",
        "   name PROD-DB",
        "!",
        *(["vlan 300", "   name PROD-CACHE", "!"] if c.at(0) else []),
        "vrf instance MGMT",
        "!",
    ]
    for port in range(1, 9):
        host = f"esxi-dc1-{port:02d}"
        desc = f"{host} vmnic{0 if port % 2 else 1}"
        if c.changed and port == 3:
            desc = f"{host} vmnic0 (migrated to 25G - CHG0041872)"
        vlan = 100 if port <= 4 else 300 if port == 8 and c.at(1) else 200
        lines += [f"interface Ethernet{port}", f"   description {desc}", f"   switchport access vlan {vlan}", "!"]
    lines += [
        "interface Ethernet49/1",
        "   description dc1-spine01 et-0/0/48",
        "   mtu 9214",
        "   no switchport",
        f"   ip address 10.255.1.{1 if c.name.endswith('1') else 3}/31",
        "!",
        "interface Loopback0",
        f"   ip address 10.255.0.{c.octet}/32",
        "!",
        "interface Management1",
        "   vrf MGMT",
        f"   ip address 10.20.99.{c.octet}/24",
        "!",
        "ip routing",
        "no ip routing vrf MGMT",
        "!",
        "ntp server vrf MGMT 10.20.0.123",
        "!",
        f"router bgp 650{c.octet % 90 + 10}",
        f"   router-id 10.255.0.{c.octet}",
        "   neighbor SPINES peer group",
        "   neighbor SPINES remote-as 65020",
        f"   neighbor 10.255.1.{0 if c.name.endswith('1') else 2} peer group SPINES",
        f"   network 10.255.0.{c.octet}/32",
        "!",
        "management api http-commands",
        "   no shutdown",
        "   vrf MGMT",
        "      no shutdown",
        "!",
        "end",
    ]
    return "\n".join(lines)


def _panos(c: _Ctx) -> str:
    rules = [
        ("allow-web", "trust", "untrust", "[ web-browsing ssl ]", "application-default"),
        ("allow-dns", "trust", "untrust", "dns", "application-default"),
        ("allow-partner-api", "untrust", "dmz", "ssl", "service-https"),
    ]
    if c.changed:
        rules.insert(2, ("allow-o365", "trust", "untrust", "[ ms-office365-base ms-teams ]", "application-default"))
    lines = [
        f"set deviceconfig system hostname {c.name}",
        f"set deviceconfig system ip-address 10.20.99.{c.octet}",
        "set deviceconfig system netmask 255.255.255.0",
        "set deviceconfig system default-gateway 10.20.99.1",
        "set deviceconfig system dns-setting servers primary 10.20.0.53",
        "set deviceconfig system ntp-servers primary-ntp-server ntp-server-address 10.20.0.123",
        *(["set deviceconfig system ntp-servers secondary-ntp-server ntp-server-address 10.10.0.123"] if c.at(1) else []),
        "set deviceconfig system timezone US/Eastern",
        f"set mgt-config users admin phash $5${c.secret('phash', 16)}${c.secret('phash2', 43)}",
        "set mgt-config users admin permissions role-based superuser yes",
        "set network interface ethernet ethernet1/1 layer3 ip 198.51.100.20/29",
        "set network interface ethernet ethernet1/2 layer3 ip 10.20.0.1/24",
        "set network interface ethernet ethernet1/3 layer3 ip 10.20.60.1/24",
        "set network virtual-router default interface [ ethernet1/1 ethernet1/2 ethernet1/3 ]",
        "set network virtual-router default routing-table ip static-route default destination 0.0.0.0/0 nexthop ip-address 198.51.100.17",
        "set zone untrust network layer3 ethernet1/1",
        "set zone trust network layer3 ethernet1/2",
        "set zone dmz network layer3 ethernet1/3",
        f"set network ike gateway hq-fw01 authentication pre-shared-key key -AQ=={c.secret('psk', 40)}",
        *(["set address PARTNER-API ip-netmask 192.0.2.0/24", "set address PARTNER-API description \"Partner API gateway\""] if c.at(0) else []),
    ]
    for name, src, dst, app, service in rules:
        lines += [
            f"set rulebase security rules {name} from {src}",
            f"set rulebase security rules {name} to {dst}",
            f"set rulebase security rules {name} source any",
            f"set rulebase security rules {name} destination any",
            f"set rulebase security rules {name} application {app}",
            f"set rulebase security rules {name} service {service}",
            f"set rulebase security rules {name} action allow",
            f"set rulebase security rules {name} log-end yes",
        ]
    lines += [
        "set rulebase nat rules outbound-nat from trust to untrust source any destination any service any",
        "set rulebase nat rules outbound-nat source-translation dynamic-ip-and-port interface-address interface ethernet1/1",
    ]
    return "\n".join(lines)


def _routeros(c: _Ctx) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        f"# {now} by RouterOS {c.args.get('os_version', '7.14.3')}",
        f"# software id = {_token(_seeded(c.name, 'swid'), 4, 'ABCDEFGHJKLMNPQRSTUVWXYZ0123456789')}-"
        f"{_token(_seeded(c.name, 'swid2'), 4, 'ABCDEFGHJKLMNPQRSTUVWXYZ0123456789')}",
        "#",
        f"# model = {c.args.get('model', 'CCR2004-1G-12S+2XS')}",
        f"# serial number = {c.args.get('serial', 'HEX0A1B2C3D4')}",
        "/interface bridge add name=bridge-lan",
        '/interface ethernet set [ find default-name=sfp-sfpplus1 ] comment="ISP uplink"',
        "/interface bridge port add bridge=bridge-lan interface=sfp-sfpplus2",
        "/interface bridge port add bridge=bridge-lan interface=sfp-sfpplus3",
        "/ip address add address=192.0.2.2/30 interface=sfp-sfpplus1 network=192.0.2.0",
        "/ip address add address=10.30.0.1/24 interface=bridge-lan network=10.30.0.0",
        f"/ip dns set allow-remote-requests=yes servers={'10.30.0.53,' if c.at(0) else ''}10.10.0.53,10.20.0.53",
        *(["/ip firewall address-list add address=10.10.0.0/16 list=HQ"] if c.at(1) else []),
        '/ip firewall filter add action=accept chain=input comment="accept established" connection-state=established,related',
        '/ip firewall filter add action=drop chain=input comment="drop invalid" connection-state=invalid',
        "/ip firewall filter add action=accept chain=input protocol=icmp",
        "/ip firewall filter add action=accept chain=input src-address=10.10.99.0/24",
    ]
    if c.changed:
        lines.append('/ip firewall filter add action=accept chain=input comment="WireGuard from HQ" dst-port=13231 protocol=udp')
    lines += [
        "/ip firewall filter add action=drop chain=input in-interface=sfp-sfpplus1",
        "/ip firewall nat add action=masquerade chain=srcnat out-interface=sfp-sfpplus1",
        "/ip route add gateway=192.0.2.1",
        "/ip service set telnet disabled=yes",
        "/ip service set ftp disabled=yes",
        "/ip service set www disabled=yes",
        '/snmp set enabled=yes location="NYC branch"',
        f"/system identity set name={c.name}",
        "/system ntp client set enabled=yes",
        "/system ntp client servers add address=10.10.0.123",
        f'/user add group=full name=netops password="{c.secret("mtpass", 16)}"',
    ]
    return "\n".join(lines)


def _aoscx(c: _Ctx) -> str:
    lines = [
        "Current configuration:",
        "!",
        f"!Version ArubaOS-CX {c.args.get('os_version', 'FL.10.13.1000')}",
        "!export-password: default",
        f"hostname {c.name}",
        f"user admin group administrators password ciphertext AQBapb{c.secret('cx', 60)}",
        "clock timezone america/new_york",
        "ntp server 10.10.0.123 iburst",
        "ntp enable",
        "!",
        "ssh server vrf mgmt",
        "snmp-server vrf mgmt",
        "snmp-server community nycRO",
        "!",
        "vlan 1",
        "vlan 10",
        "    name USERS",
        "vlan 20",
        "    name VOICE",
        "spanning-tree",
        "interface mgmt",
        "    no shutdown",
        f"    ip static 10.30.99.{c.octet}/24",
        "    default-gateway 10.30.99.1",
    ]
    for port in range(1, 9):
        lines += [f"interface 1/1/{port}", f"    description Desk-{100 + port}", "    no shutdown", "    vlan access 10"]
    lines += [
        "interface 1/1/49",
        "    description Uplink to branch-nyc-rtr01",
        "    no shutdown",
        "    vlan trunk native 1",
        "    vlan trunk allowed 10,20",
        "interface vlan 10",
        f"    ip address 10.30.10.{c.octet}/24",
        "!",
        "https-server vrf mgmt",
    ]
    return "\n".join(lines)


def _procurve(c: _Ctx) -> str:
    lines = [
        "Running configuration:",
        "",
        f"; {c.args.get('model', 'JL261A')} Configuration Editor; Created on release #{c.args.get('os_version', 'WC.16.11.0012')}",
        "; Ver #14:41.44.00.04.19.02.13.98.82.34.61.18.28.f3.84.9c.63.ff.37.27:05",
        f'hostname "{c.name}"',
        "module 1 type jl261a",
        "time daylight-time-rule western-europe",
        "time timezone 0",
        "ip default-gateway 10.40.99.1",
        "ip dns server-address priority 1 10.10.0.53",
        'snmp-server community "lonRO" operator',
        'snmp-server contact "noc@example.net"',
        'snmp-server location "London branch, comms cabinet"',
        "vlan 1",
        '   name "DEFAULT_VLAN"',
        "   no untagged 1-24",
        "   untagged 25-28",
        "   no ip address",
        "   exit",
        "vlan 10",
        '   name "USERS"',
        "   untagged 1-20",
        "   tagged 25-28",
        "   no ip address",
        "   exit",
        "vlan 99",
        '   name "MGMT"',
        "   tagged 25-28",
        f"   ip address 10.40.99.{c.octet} 255.255.255.0",
        "   exit",
        "spanning-tree",
        f'password manager user-name "netops" sha1 "{hashlib.sha1(c.name.encode()).hexdigest()}"',
    ]
    return "\n".join(lines)


def _asa(c: _Ctx) -> str:
    lines = [
        ": Saved",
        "",
        ":",
        f": Serial Number: {c.args.get('serial', 'JAD2207812X')}",
        ": Hardware:   ASA5516, 8192 MB RAM, CPU Atom C2000 series 2416 MHz, 1 CPU (8 cores)",
        ":",
        f"ASA Version {c.args.get('os_version', '9.16(4)')}",
        "!",
        f"hostname {c.name}",
        "domain-name example.net",
        "enable password ***** pbkdf2",
        "names",
        "no mac-address auto",
        "",
        "!",
        "interface GigabitEthernet1/1",
        " nameif outside",
        " security-level 0",
        " ip address 198.51.100.30 255.255.255.248",
        "!",
        "interface GigabitEthernet1/2",
        " nameif inside",
        " security-level 100",
        " ip address 10.20.50.1 255.255.255.0",
        "!",
        "object network PARTNER-NET",
        " subnet 192.0.2.0 255.255.255.0",
        "object network API-GW",
        " host 10.20.50.10",
        "access-list OUTSIDE-IN extended permit tcp object PARTNER-NET object API-GW eq https",
        "access-group OUTSIDE-IN in interface outside",
        "route outside 0.0.0.0 0.0.0.0 198.51.100.25 1",
        "aaa-server ISE protocol tacacs+",
        "aaa-server ISE (inside) host 10.10.0.40",
        " key *****",
        "ssh 10.10.99.0 255.255.255.0 inside",
        "ssh version 2",
        "ntp server 10.10.0.123 source inside prefer",
        "username netops password ***** pbkdf2 privilege 15",
        f"Cryptochecksum:{hashlib.md5(c.name.encode()).hexdigest()}",
        ": end",
    ]
    return "\n".join(lines)


TEMPLATES: dict[str, Callable[[_Ctx], str]] = {
    "ios": _ios,
    "fortios": _fortios,
    "junos": _junos,
    "eos": _eos,
    "panos": _panos,
    "routeros": _routeros,
    "aoscx": _aoscx,
    "procurve": _procurve,
    "asa": _asa,
}

PROFILE_FACTS: dict[str, dict[str, Any]] = {
    "ios": {"vendor": "Cisco", "model": "C9500-48Y4C", "os_version": "17.9.4a"},
    "fortios": {"vendor": "Fortinet", "model": "FortiGate-200F", "os_version": "v7.4.3 build2573"},
    "junos": {"vendor": "Juniper", "model": "QFX5120-48Y", "os_version": "22.4R3-S2.11"},
    "eos": {"vendor": "Arista", "model": "DCS-7050SX3-48YC8", "os_version": "4.31.2F"},
    "panos": {"vendor": "Palo Alto Networks", "model": "PA-3220", "os_version": "10.2.7-h3"},
    "routeros": {"vendor": "MikroTik", "model": "CCR2004-1G-12S+2XS", "os_version": "7.14.3"},
    "aoscx": {"vendor": "HPE Aruba", "model": "JL658A 6300M 24SFP+ 4SFP56 Swch", "os_version": "FL.10.13.1000"},
    "procurve": {"vendor": "HPE Aruba", "model": "JL261A 2930F-24G-PoE+-4SFP", "os_version": "WC.16.11.0012"},
    "asa": {"vendor": "Cisco", "model": "ASA5516", "os_version": "9.16(4)"},
}

SENSORS: dict[str, dict[str, list[str]]] = {
    "ios": {"temp": ["Inlet", "Outlet", "HotSpot"], "fans": ["FAN 1", "FAN 2", "FAN 3", "FAN 4"], "psu": ["PS1", "PS2"]},
    "fortios": {"temp": ["DTS CPU0", "TD1", "TD2"], "fans": ["FAN1", "FAN2"], "psu": ["PS1 Status", "PS2 Status"]},
    "junos": {"temp": ["FPC 0 CPU", "FPC 0 Intake", "FPC 0 Exhaust"], "fans": ["Fan Tray 0 Fan 0", "Fan Tray 1 Fan 0"], "psu": ["Power Supply 0", "Power Supply 1"]},
    "eos": {"temp": ["Cpu temp sensor", "Front-panel temp sensor", "Switch chip sensor"], "fans": ["Fan1/1", "Fan2/1", "Fan3/1"], "psu": ["PowerSupply1", "PowerSupply2"]},
    "panos": {"temp": ["Temperature near CPU", "Temperature @ MP"], "fans": ["Fan #1 RPM", "Fan #2 RPM"], "psu": ["Power Supply #1 (left)", "Power Supply #2 (right)"]},
    "routeros": {"temp": ["cpu-temperature", "board-temperature1"], "fans": ["fan1-speed", "fan2-speed"], "psu": ["psu1-state", "psu2-state"]},
    "aoscx": {"temp": ["1/1-CPU", "1/1-Switch-ASIC-Internal", "1/1-PHY-01-04"], "fans": ["1/1", "1/2", "1/3", "1/4"], "psu": ["1/1", "1/2"]},
    "procurve": {"temp": ["Chassis"], "fans": ["Sys-1", "Sys-2"], "psu": ["PS 1", "PS 2"]},
    "asa": {"temp": ["Processor 1", "Ambient 1"], "fans": ["Cooling Fan 1", "Cooling Fan 2"], "psu": ["Power Supply 0"]},
}


def _wave(ts: float, period: float = 86400.0, peak_hour: float = 14.0) -> float:
    """-1..1 daily cycle in local time, highest at ``peak_hour``."""
    local = time.localtime(ts)
    hours = local.tm_hour + local.tm_min / 60 + local.tm_sec / 3600
    return math.cos(2 * math.pi * (hours - peak_hour) * 3600 / period)


def _noise(name: str, label: str, ts: float, spread: float, step: int = 300) -> float:
    return _seeded(name, label, int(ts // step)).uniform(-spread, spread)


def simulated_reading(name: str, args: dict[str, Any], ts: float) -> dict[str, float]:
    """Deterministic CPU (busiest core), memory and base temperature of a simulated device at time ``ts``.

    The configured values are what the device shows when the simulation starts; history before that
    follows a daily load cycle, plus any ``memory_leak`` / ``temperature_drift``.
    """
    base = _seeded(name, "env")
    cpu = float(args.get("cpu", base.uniform(6, 24)))
    memory = float(args.get("memory", base.uniform(32, 61)))
    temperature = float(args.get("temperature", base.uniform(34, 47)))
    days = (ts - _STARTED) / 86400
    cycle = _wave(ts) - _wave(_STARTED)
    cpu = cpu + cpu * 0.05 * cycle + _noise(name, "cpu", ts, max(0.8, cpu * 0.025))
    memory = memory + float(args.get("memory_leak", 0)) * days + 0.6 * cycle + _noise(name, "mem", ts, 0.35)
    temperature = temperature + float(args.get("temperature_drift", 0)) * days + 1.3 * cycle + _noise(name, "temp", ts, 0.3)
    return {
        "cpu": round(max(0.5, min(100.0, cpu)), 1),
        "memory": round(max(1.0, min(99.0, memory)), 1),
        "temperature": round(temperature, 1),
    }


class SimulatedDriver(NetworkDriver):
    """NAPALM-compatible driver that fabricates realistic device data."""

    accepts_platform_hint = True
    revision = 1
    epoch = 99  # all earlier edits have happened
    latency_scale = 1.0
    clock: Callable[[], float] | None = None  # simulated "now" (the demo uses it to build history)
    revisions: dict[str, int] = {}  # per-device revision overrides

    def __init__(
        self,
        hostname: str,
        username: str,
        password: str,
        timeout: int = 60,
        optional_args: dict[str, Any] | None = None,
    ) -> None:
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.args = dict(optional_args or {})
        profile = str(self.args.get("profile") or self.args.get("_netledger_platform") or "ios")
        self.profile = profile if profile in TEMPLATES else "ios"
        self.name = str(self.args.get("_netledger_device") or hostname)
        self._open = False

    @property
    def _revision(self) -> int:
        return int(self.args.get("revision", type(self).revisions.get(self.name, type(self).revision)))

    def open(self) -> None:
        delay = float(self.args.get("latency", _seeded(self.name, "latency").uniform(0.3, 1.4))) * type(self).latency_scale
        if delay:
            time.sleep(delay)
        current = type(self).clock() if type(self).clock else time.time()
        outage = self.args.get("outage_minutes")
        if self.args.get("unreachable") or (outage is not None and current >= _STARTED - float(outage) * 60):
            raise ConnectionException(f"{self.hostname}: TCP connection to port 22 timed out after {self.timeout}s")
        if self.args.get("auth_fail"):
            raise ConnectAuthError(f"authentication failed for {self.username}@{self.hostname}")
        self._open = True

    def close(self) -> None:
        self._open = False

    def is_alive(self) -> dict[str, bool]:
        return {"is_alive": self._open}

    def get_config(self, retrieve: str = "all", full: bool = False, sanitized: bool = False, format: str = "text") -> dict[str, str]:
        template = TEMPLATES[self.profile]
        running = template(_Ctx(self, self._revision))
        startup_rev = 1 if self.args.get("unsaved") else self._revision
        startup = template(_Ctx(self, startup_rev))
        if self.profile == "ios":
            startup = startup.replace("Building configuration...\n\n", "")
            startup = re.sub(r"^Current configuration : \d+ bytes$", "Using 14823 out of 33554432 bytes", startup, flags=re.M)
        return {
            "running": running if retrieve in ("all", "running") else "",
            "startup": startup if retrieve in ("all", "startup") else "",
            "candidate": "",
        }

    def get_facts(self) -> dict[str, Any]:
        base = PROFILE_FACTS[self.profile]
        uptime_days = float(self.args.get("uptime_days", _seeded(self.name, "uptime").randint(12, 410)))
        serial = self.args.get("serial") or _token(_seeded(self.name, "serial"), 3, "ABCDEFGHJKLMNPQRSTUVWXYZ") + _token(
            _seeded(self.name, "serial2"), 8, "0123456789ABCDEF"
        )
        return {
            "uptime": uptime_days * 86400 + (time.time() - _STARTED),
            "vendor": self.args.get("vendor", base["vendor"]),
            "model": self.args.get("model", base["model"]),
            "hostname": self.name,
            "fqdn": f"{self.name}.example.net",
            "os_version": self.args.get("os_version", base["os_version"]),
            "serial_number": serial,
            "interface_list": [],
        }

    def get_environment(self) -> dict[str, Any]:
        rng = random.Random()
        sensors = SENSORS[self.profile]
        reading = simulated_reading(self.name, self.args, time.time())
        cpu, mem, temp = reading["cpu"], reading["memory"], reading["temperature"]
        total = int(self.args.get("memory_total", 8 * 1024**3))
        env: dict[str, Any] = {
            "cpu": {i: {"%usage": round(max(0.0, min(100.0, cpu - i * 2.5 + (rng.uniform(-1.5, 1.5) if i else 0))), 1)} for i in range(4)},
            "memory": {"available_ram": total, "used_ram": int(total * max(0.0, min(99.0, mem)) / 100)},
            "temperature": {},
            "fans": {},
            "power": {},
        }
        for index, name in enumerate(sensors["temp"]):
            value = round(temp + index * 4.5 + rng.uniform(-0.6, 0.6), 1)
            alert = bool(self.args.get("temp_alert")) and index == len(sensors["temp"]) - 1
            env["temperature"][name] = {"temperature": value, "is_alert": alert, "is_critical": False}
        for index, name in enumerate(sensors["fans"]):
            env["fans"][name] = {"status": not (self.args.get("fan_failed") and index == 1)}
        for index, name in enumerate(sensors["psu"]):
            failed = bool(self.args.get("psu_failed")) and index == len(sensors["psu"]) - 1
            env["power"][name] = {"status": not failed, "capacity": 1100.0, "output": 0.0 if failed else round(rng.uniform(180, 260), 1)}
        return env

    def get_lldp_neighbors(self) -> dict[str, list[dict[str, str]]]:
        neighbors: dict[str, list[dict[str, str]]] = {}
        for port, remote in (self.args.get("neighbors") or {}).items():
            name, remote_port = (list(remote) + ["", ""])[:2] if isinstance(remote, (list, tuple)) else (str(remote), "")
            neighbors.setdefault(str(port), []).append({"hostname": str(name), "port": str(remote_port)})
        return neighbors

    def cli(self, commands: list[str], encoding: str = "text") -> dict[str, str]:
        facts = self.get_facts()
        result = {}
        for command in commands:
            if command.startswith("show inventory"):
                result[command] = (
                    f'NAME: "Chassis", DESCR: "{facts["vendor"]} {facts["model"]} Chassis"\n'
                    f'PID: {facts["model"]:<18}, VID: V02  , SN: {facts["serial_number"]}\n\n'
                    'NAME: "Power Supply Module 0", DESCR: "Cisco Catalyst 9500 1600W AC Power Supply"\n'
                    f'PID: C9K-PWR-1600WAC-R , VID: V01  , SN: {_token(_seeded(self.name, "ps0"), 11, "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789")}\n'
                )
            else:
                result[command] = f"{self.name}: simulated output for '{command}'\n"
        return result
