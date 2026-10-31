"""Platform registry: drivers, aliases and per-platform normalization rules.

Every platform maps to a NAPALM driver (either a core/community NAPALM driver such as
``napalm:ios`` or a NetLedger built-in driver class) plus the rules used to keep Git
history clean:

* ``volatile`` rules remove content that changes without a real configuration change
  (timestamps, byte counts, re-encrypted secrets). A rule with ``replace=None`` drops
  matching lines; otherwise it is a regular-expression substitution.
* ``secrets`` rules locate secrets (named group ``secret``) so they can be masked or
  replaced with a keyed hash when ``normalize.secrets`` is ``mask`` or ``hmac``.
* ``meta`` patterns extract "who/when changed it" details for commit messages.

Every rule has a stable id, so users can switch individual rules off with
``normalize.disable_rules``.
"""

from __future__ import annotations

import importlib
import re
from dataclasses import dataclass
from functools import cached_property
from typing import Any


@dataclass(frozen=True)
class Rule:
    id: str
    pattern: str
    replace: str | None = None
    flags: int = re.M

    @cached_property
    def regex(self) -> re.Pattern[str]:
        return re.compile(self.pattern, self.flags)


@dataclass(frozen=True)
class SecretRule:
    id: str
    pattern: str
    flags: int = re.M

    @cached_property
    def regex(self) -> re.Pattern[str]:
        compiled = re.compile(self.pattern, self.flags)
        if "secret" not in compiled.groupindex:
            raise ValueError(f"secret rule {self.id} has no (?P<secret>...) group")
        return compiled


@dataclass(frozen=True)
class Platform:
    key: str
    name: str
    vendor: str
    driver: str
    aliases: tuple[str, ...] = ()
    extension: str = "cfg"
    volatile: tuple[Rule, ...] = ()
    secrets: tuple[SecretRule, ...] = ()
    meta: tuple[str, ...] = ()
    startup: bool = True
    candidate: bool = False
    enable_arg: str | None = "secret"
    netmiko_based: bool = True
    memory_free_semantics: bool = False
    health: str = "full"
    notes: str = ""

    @cached_property
    def meta_regexes(self) -> tuple[re.Pattern[str], ...]:
        return tuple(re.compile(p, re.M) for p in self.meta)

    @property
    def builtin(self) -> bool:
        return self.driver.startswith("netledger.")


_S = SecretRule

# --------------------------------------------------------------------------- Cisco IOS / IOS-XE

IOS_VOLATILE = (
    Rule("ios.building", r"^Building configuration\.\.\.\s*$"),
    Rule("ios.current-config", r"^Current configuration\s*:\s*\d+ bytes\s*$"),
    Rule("ios.startup-usage", r"^Using \d+ out of \d+ bytes.*$"),
    Rule("ios.last-change", r"^! Last configuration change at .*$"),
    Rule("ios.nvram-updated", r"^! NVRAM config last updated at .*$"),
    Rule("ios.no-change", r"^! No configuration change since last restart.*$"),
    Rule("ios.ntp-clock-period", r"^ntp clock-period \d+\s*$"),
    Rule("ios.exec-timestamp", r"^(?:Load for five secs:.*|Time source is .*|No time source, .*)$"),
)
IOS_META = (r"^! Last configuration change at (?P<changed_at>.+?)(?: by (?P<changed_by>\S+))?\s*$",)
IOS_SECRETS = (
    _S("ios.enable", r"^enable (?:secret|password)(?: level \d+)?(?: \d{1,2})? (?P<secret>\S+)"),
    _S("ios.username", r"^username \S+ .*?\b(?:secret|password)(?: \d{1,2})? (?P<secret>\S+)"),
    _S("ios.line-password", r"^\s+(?:password|secret)(?: \d{1,2})? (?P<secret>\S+)"),
    _S("ios.snmp-community", r"^snmp-server community (?P<secret>\S+)"),
    _S(
        "ios.snmp-host",
        r"^snmp-server host \S+(?: vrf \S+)?(?: informs| traps)?(?: version (?:1|2c|3 (?:noauth|auth|priv)))?"
        r" (?P<secret>(?!version\b|informs\b|traps\b|vrf\b)\S+)",
    ),
    _S("ios.server-key", r"^(?:tacacs-server|radius-server)\b.*?\bkey(?: \d)? (?P<secret>\S+)"),
    _S("ios.aaa-server-key", r"^\s+(?:server-)?key(?: \d)? (?P<secret>\S+)\s*$"),
    _S("ios.isakmp-key", r"^crypto isakmp key(?: \d)? (?P<secret>\S+) (?:address|hostname)"),
    _S("ios.pre-shared-key", r"\bpre-shared-key(?: local| remote)?(?: \d)? (?P<secret>\S+)"),
    _S("ios.ospf-md5", r"^\s+ip ospf message-digest-key \d+ md5(?: \d)? (?P<secret>\S+)"),
    _S("ios.ospf-auth", r"^\s+ip ospf authentication-key(?: \d)? (?P<secret>\S+)"),
    _S("ios.bgp-password", r"^\s+neighbor \S+ password(?: \d)? (?P<secret>\S+)"),
    _S("ios.key-string", r"^\s+key-string(?: \d)? (?P<secret>\S+)"),
    _S("ios.hsrp-md5", r"^\s+standby(?: \d+)? authentication md5 key-string(?: \d)? (?P<secret>\S+)"),
    _S("ios.hsrp-text", r"^\s+standby(?: \d+)? authentication(?: text)? (?P<secret>(?!md5\b)\S+)\s*$"),
    _S("ios.vrrp", r"^\s+vrrp \d+ authentication(?: text)? (?P<secret>(?!md5\b)\S+)\s*$"),
    _S("ios.ppp", r"^\s+ppp (?:chap|pap) (?:password|sent-username \S+ password)(?: \d)? (?P<secret>\S+)"),
    _S("ios.wpa-psk", r"\bwpa-psk (?:ascii|hex)(?: \d)? (?P<secret>\S+)"),
    _S("ios.ntp-key", r"^ntp authentication-key \d+ md5 (?P<secret>\S+)"),
)

# --------------------------------------------------------------------------- Cisco NX-OS

NXOS_VOLATILE = (
    Rule("nxos.command", r"^!Command: show (?:running|startup)-config.*$"),
    Rule("nxos.last-done", r"^!Running configuration last done at: .*$"),
    Rule("nxos.time", r"^!Time: .*$"),
    Rule("nxos.startup-saved", r"^!Startup config saved at: .*$"),
)
NXOS_META = (r"^!Running configuration last done at: (?P<changed_at>.+?)\s*$",)
NXOS_SECRETS = (
    _S("nxos.username", r"^username \S+ password(?: \d)? (?P<secret>\S+)"),
    _S("nxos.snmp-auth", r"^snmp-server user \S+(?: \S+)? auth \S+ (?P<secret>\S+)"),
    _S("nxos.snmp-priv", r"^snmp-server user .*? priv(?: aes-128)? (?P<secret>\S+)"),
    _S("nxos.snmp-community", r"^snmp-server community (?P<secret>\S+)"),
    _S("nxos.server-key", r'^(?:tacacs|radius)-server (?:host \S+ )?key(?: \d)? (?P<secret>"[^"]*"|\S+)'),
    _S("nxos.key-string", r"^\s+key-string(?: \d)? (?P<secret>\S+)"),
    _S("nxos.neighbor-password", r"^\s+password(?: \d)? (?P<secret>\S+)"),
    _S("nxos.ospf", r"^\s+ip ospf (?:authentication-key|message-digest-key \d+ md5)(?: \d)? (?P<secret>\S+)"),
    _S("nxos.hsrp", r"^\s+authentication (?:text|md5 key-string)(?: \d)? (?P<secret>\S+)"),
)

# --------------------------------------------------------------------------- Cisco IOS-XR

IOSXR_VOLATILE = (
    Rule(
        "iosxr.timestamp",
        r"^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +\d+"
        r" \d{1,2}:\d{2}:\d{2}(?:\.\d+)? \S+\s*$",
    ),
    Rule("iosxr.building", r"^Building configuration\.\.\.\s*$"),
    Rule("iosxr.last-change", r"^!! Last configuration change at .*$"),
)
IOSXR_META = (r"^!! Last configuration change at (?P<changed_at>.+?) by (?P<changed_by>\S+)\s*$",)
IOSXR_SECRETS = (
    _S("iosxr.secret", r"^\s*(?:secret|password)(?: \d{1,2}| encrypted| clear)? (?P<secret>\S+)"),
    _S("iosxr.key", r"^\s*key (?:\d{1,2}|encrypted|clear) (?P<secret>\S+)\s*$"),
    _S("iosxr.key-string", r"^\s*key-string(?: password)?(?: \d| encrypted| clear)? (?P<secret>\S+)"),
    _S("iosxr.snmp-community", r"^snmp-server community (?P<secret>\S+)"),
)

# --------------------------------------------------------------------------- Arista EOS

EOS_VOLATILE = (
    Rule("eos.command", r"^! Command: show (?:running|startup)-config.*$"),
    Rule("eos.startup-modified", r"^! Startup-config last modified at .*$"),
    Rule("eos.time", r"^! Time: .*$"),
)
EOS_SECRETS = (
    _S("eos.username", r"^username \S+ .*?\b(?:secret|password)(?: sha512| \d)? (?P<secret>\S+)"),
    _S("eos.enable", r"^enable (?:secret|password)(?: sha512| \d)? (?P<secret>\S+)"),
    _S("eos.snmp-community", r"^snmp-server community (?P<secret>\S+)"),
    _S("eos.server-key", r"^(?:tacacs|radius)-server\b.*?\bkey(?: \d)? (?P<secret>\S+)"),
    _S("eos.bgp-password", r"^\s+neighbor \S+ password(?: \d)? (?P<secret>\S+)"),
    _S("eos.ospf", r"^\s+ip ospf (?:authentication-key|message-digest-key \d+ md5)(?: \d)? (?P<secret>\S+)"),
)

# --------------------------------------------------------------------------- Juniper Junos

JUNOS_VOLATILE = (
    Rule("junos.last-commit", r"^## Last commit: .*$"),
    Rule("junos.last-changed", r"^## Last changed: .*$"),
)
JUNOS_META = (r"^## Last commit: (?P<changed_at>.+?) by (?P<changed_by>\S+)\s*$",)
JUNOS_SECRETS = (
    _S("junos.secret-data", r'\s"?(?P<secret>[^"\s;]+)"?;\s*## SECRET-DATA'),
    _S("junos.community", r"^\s*community (?P<secret>\S+) \{"),
)

# --------------------------------------------------------------------------- Cisco ASA

ASA_VOLATILE = (Rule("asa.written-by", r"^: Written by .*$"),)
ASA_SECRETS = (
    _S("asa.enable", r"^enable password (?P<secret>\S+)"),
    _S("asa.username", r"^username \S+ password (?P<secret>\S+)"),
    _S("asa.passwd", r"^passwd (?P<secret>\S+)"),
    _S("asa.psk", r"\bpre-shared-key (?P<secret>\S+)"),
    _S("asa.snmp-community", r"^snmp-server (?:community|host \S+ \S+ community) (?P<secret>\S+)"),
    _S("asa.aaa-key", r"^\s+key (?P<secret>\S+)"),
    _S("asa.ldap", r"^\s+ldap-login-password (?P<secret>\S+)"),
    _S("asa.ospf", r"^\s+ospf (?:authentication-key|message-digest-key \d+ md5) (?P<secret>\S+)"),
    _S("asa.failover-key", r"^failover key (?P<secret>\S+)"),
    _S("asa.bgp-password", r"^\s+neighbor \S+ password(?: \d)? (?P<secret>\S+)"),
)

# --------------------------------------------------------------------------- Fortinet FortiOS

FORTIOS_VOLATILE = (
    Rule("fortios.conf-file-ver", r"^#conf_file_ver=.*$"),
    # FortiOS re-encrypts reversible secrets with a random salt every time the config is shown.
    Rule("fortios.enc", r"(\bset [\w-]+ ENC )(?!SH2)\S+", r"\1<encrypted>"),
    Rule(
        "fortios.private-key",
        r'(set private-key ")-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----(")',
        r"\1<private key removed>\2",
        re.S,
    ),
)
FORTIOS_SECRETS = (_S("fortios.enc-value", r"\bset [\w-]+ ENC (?P<secret>\S+)"),)

# --------------------------------------------------------------------------- Palo Alto PAN-OS

PANOS_SECRETS = (
    _S(
        "panos.set",
        r'(?<![\w-])(?:pre-shared-key key|phash|password|secret|key|auth-password|priv-password|bind-password'
        r'|shared-secret|passphrase|snmp-community-string|community)\s+(?P<secret>"[^"]*"|\S+)',
    ),
    _S(
        "panos.xml",
        r"<(?P<tag>phash|password|secret|key|pre-shared-key|auth-password|priv-password|bind-password"
        r"|shared-secret|passphrase|snmp-community-string)>(?P<secret>[^<]+)</(?P=tag)>",
    ),
)

# --------------------------------------------------------------------------- Huawei VRP

VRP_VOLATILE = (Rule("vrp.last-config", r"^!Last configuration was (?:updated|saved) at .*$"),)
VRP_META = (r"^!Last configuration was updated at (?P<changed_at>.+?) by (?P<changed_by>\S+)\s*$",)
VRP_SECRETS = (
    _S("vrp.cipher", r"\b(?:irreversible-)?cipher (?P<secret>\S+)"),
    _S("vrp.simple", r"\b(?:password|key|pre-shared-key|authentication-key) simple (?P<secret>\S+)"),
    _S("vrp.snmp-community", r"^\s*snmp-agent community (?:read|write) (?!cipher\b)(?P<secret>\S+)"),
)

# --------------------------------------------------------------------------- HPE Comware / ProCurve / AOS-CX

COMWARE_SECRETS = (
    _S(
        "comware.password",
        r"\b(?:password|super password(?: level \d+| role \S+)?|key(?: authentication| accounting)?"
        r"|pre-shared-key|authentication-key) (?:cipher|simple|hash) (?P<secret>\S+)",
    ),
    _S("comware.snmp-community", r"^\s*snmp-agent community (?:read|write)(?: (?:cipher|simple))? (?P<secret>\S+)"),
)
PROCURVE_VOLATILE = (Rule("procurve.header", r"^Running configuration:\s*$"),)
PROCURVE_SECRETS = (
    _S(
        "procurve.password",
        r'^password (?:manager|operator)(?: user-name \S+)? (?:sha1|sha256|plaintext) (?P<secret>"[^"]*"|\S+)',
    ),
    _S("procurve.snmp", r'^snmp-server community (?P<secret>"[^"]*"|\S+)'),
    _S("procurve.server-key", r'^(?:radius|tacacs)-server (?:host \S+ )?key (?:encrypted-key )?(?P<secret>"[^"]*"|\S+)'),
)
AOSCX_VOLATILE = (Rule("aoscx.header", r"^Current configuration:\s*$"),)
AOSCX_SECRETS = (
    _S("aoscx.user", r"^user \S+ group \S+ password (?:ciphertext|plaintext) (?P<secret>\S+)"),
    _S("aoscx.snmp", r"^snmp-server community (?P<secret>\S+)"),
    _S("aoscx.ciphertext", r"\b(?:key|password|secret|psk) (?:ciphertext|plaintext) (?P<secret>\S+)"),
)

# --------------------------------------------------------------------------- MikroTik RouterOS

ROUTEROS_VOLATILE = (Rule("routeros.export-time", r"^# \S+ \S+ by (RouterOS .*)$", r"# \1"),)
ROUTEROS_SECRETS = (
    _S(
        "routeros.secret",
        r'(?<![\w-])(?:password|secret|wpa-pre-shared-key|wpa2-pre-shared-key|authentication-key|passphrase'
        r'|private-key|preshared-key|pre-shared-key|auth-key|key)=(?P<secret>"(?:[^"\\]|\\.)*"|\S+)',
    ),
    _S("routeros.snmp-community", r'^/snmp community .*?\bname=(?P<secret>"(?:[^"\\]|\\.)*"|\S+)'),
)

# --------------------------------------------------------------------------- others

OS10_VOLATILE = (Rule("os10.last-change", r"^! Last configuration change at .*$"),)
OS10_SECRETS = (
    _S("os10.username", r"^username \S+ password (?P<secret>\S+)"),
    _S("os10.enable", r"^enable password(?: \d+)?(?: priv-lvl \d+)? (?P<secret>\S+)"),
    _S("os10.snmp", r"^snmp-server community (?P<secret>\S+)"),
    _S("os10.server-key", r"^(?:radius|tacacs)-server host \S+ .*?\bkey(?: \d)? (?P<secret>\S+)"),
)
EXOS_SECRETS = (
    _S("exos.encrypted", r'\bencrypted (?P<secret>"[^"]*"|\S+)'),
    _S("exos.community", r'^configure snmpv3 add community (?P<secret>"[^"]*"|(?!encrypted\b)\S+)'),
)
VYOS_SECRETS = (
    _S(
        "vyos.secret",
        r"(?<![\w-])(?:encrypted-password|plaintext-password|pre-shared-secret|password|secret|md5-key"
        r"|private-key|preshared-key|shared-secret|authentication-key) (?P<secret>'[^']*'|\S+)",
    ),
    _S("vyos.community", r"\bsnmp community (?P<secret>'[^']*'|\S+)"),
)
FASTIRON_VOLATILE = (Rule("fastiron.header", r"^Current configuration:\s*$"),)
FASTIRON_SECRETS = (
    _S(
        "fastiron.enable",
        r"^enable (?:super-user-password|password|read-only-password|port-config-password)(?: \d)? (?P<secret>\S+)",
    ),
    _S("fastiron.username", r"^username \S+ .*?\bpassword(?: \d)? (?P<secret>\S+)"),
    _S("fastiron.snmp", r"^snmp-server community(?: \d)? (?P<secret>\S+)"),
    _S("fastiron.server-key", r"^(?:radius|tacacs)-server\b.*?\bkey(?: \d)? (?P<secret>\S+)"),
)
GAIA_VOLATILE = (Rule("gaia.exported", r"^# Exported by .*$"),)
GAIA_SECRETS = (
    _S("gaia.password-hash", r"^set user \S+ password-hash (?P<secret>\S+)"),
    _S("gaia.expert", r"^set expert-password-hash (?P<secret>\S+)"),
    _S("gaia.snmp", r"^set snmp community (?P<secret>\S+)"),
    _S("gaia.server-key", r"^(?:add|set) aaa (?:tacacs|radius)-servers .*?\bkey (?P<secret>\S+)"),
)
AIREOS_SECRETS = (
    _S("aireos.radius", r"^radius (?:auth|acct) add \d+ \S+ \d+ (?:ascii|hex) (?P<secret>\S+)"),
    _S("aireos.snmp", r"^snmp community create (?P<secret>\S+)"),
    _S("aireos.psk", r"\bpsk set-key (?:ascii|hex) (?P<secret>\S+)"),
    _S("aireos.mgmtuser", r"^mgmtuser add (?:encrypt )?\S+ (?P<secret>\S+)"),
)
SMB_SECRETS = (
    _S("smb.username", r"^username \S+ password encrypted (?P<secret>\S+)"),
    _S("smb.enable", r"^enable password level \d+ encrypted (?P<secret>\S+)"),
    _S("smb.snmp", r"^snmp-server community (?P<secret>\S+)"),
)

# --------------------------------------------------------------------------- registry

BUILTIN_PLATFORMS: tuple[Platform, ...] = (
    Platform(
        "ios", "Cisco IOS / IOS-XE", "Cisco", "netledger.drivers.ios:IOSDriver",
        aliases=("cisco_ios", "iosxe", "ios_xe", "cisco_xe", "cisco_iosxe", "catalyst"),
        volatile=IOS_VOLATILE, secrets=IOS_SECRETS, meta=IOS_META,
        notes="NAPALM ios driver (SSH or telnet); keeps the 'last changed by' header for commit messages.",
    ),
    Platform(
        "nxos", "Cisco NX-OS (SSH)", "Cisco", "napalm:nxos_ssh",
        aliases=("cisco_nxos", "nxos_ssh", "nexus"),
        volatile=NXOS_VOLATILE, secrets=NXOS_SECRETS, meta=NXOS_META,
    ),
    Platform(
        "nxos_api", "Cisco NX-OS (NX-API)", "Cisco", "napalm:nxos",
        aliases=("nxapi", "nxos_nxapi"),
        volatile=NXOS_VOLATILE, secrets=NXOS_SECRETS, meta=NXOS_META,
        enable_arg=None, netmiko_based=False, memory_free_semantics=True,
        notes="Requires 'feature nxapi' on the switch.",
    ),
    Platform(
        "iosxr", "Cisco IOS-XR", "Cisco", "napalm:iosxr",
        aliases=("cisco_xr", "iosxr_xml"),
        volatile=IOSXR_VOLATILE, secrets=IOSXR_SECRETS, meta=IOSXR_META,
        startup=False, candidate=True, enable_arg=None, netmiko_based=False,
        notes="Requires 'xml agent tty'. Use iosxr_netconf for NETCONF.",
    ),
    Platform(
        "iosxr_netconf", "Cisco IOS-XR (NETCONF)", "Cisco", "napalm:iosxr_netconf",
        volatile=IOSXR_VOLATILE, secrets=IOSXR_SECRETS, meta=IOSXR_META,
        startup=False, candidate=True, enable_arg=None, netmiko_based=False,
    ),
    Platform(
        "asa", "Cisco ASA", "Cisco", "netledger.drivers.cisco:ASADriver",
        aliases=("cisco_asa",),
        volatile=ASA_VOLATILE, secrets=ASA_SECRETS,
    ),
    Platform(
        "aireos", "Cisco AireOS Wireless LAN Controller", "Cisco", "netledger.drivers.cisco:AireOSDriver",
        aliases=("cisco_wlc", "wlc"),
        secrets=AIREOS_SECRETS, startup=False, enable_arg=None, health="partial",
    ),
    Platform(
        "cisco_smb", "Cisco Small Business (SG300/350/550, CBS)", "Cisco", "netledger.drivers.cisco:CiscoSMBDriver",
        aliases=("cisco_s300", "sg300", "sg350", "sg550", "cbs", "cisco_sb"),
        secrets=SMB_SECRETS, health="partial",
    ),
    Platform(
        "eos", "Arista EOS", "Arista", "napalm:eos",
        aliases=("arista", "arista_eos"),
        volatile=EOS_VOLATILE, secrets=EOS_SECRETS,
        enable_arg="enable_password", netmiko_based=False,
        notes="Uses eAPI ('management api http-commands').",
    ),
    Platform(
        "junos", "Juniper Junos", "Juniper", "napalm:junos",
        aliases=("juniper", "juniper_junos", "srx", "ex", "mx", "qfx"),
        extension="conf", volatile=JUNOS_VOLATILE, secrets=JUNOS_SECRETS, meta=JUNOS_META,
        startup=False, candidate=True, enable_arg=None, netmiko_based=False,
        notes="Uses NETCONF over SSH ('set system services netconf ssh').",
    ),
    Platform(
        "fortios", "Fortinet FortiGate (FortiOS)", "Fortinet", "netledger.drivers.fortinet:FortiOSDriver",
        aliases=("fortinet", "fortigate", "forti"),
        extension="conf", volatile=FORTIOS_VOLATILE, secrets=FORTIOS_SECRETS,
        startup=False, enable_arg=None,
        notes="Multi-VDOM aware. Re-encrypted ENC values are normalized so they do not create noise commits.",
    ),
    Platform(
        "panos", "Palo Alto Networks PAN-OS", "Palo Alto Networks", "netledger.drivers.paloalto:PANOSDriver",
        aliases=("paloalto", "paloalto_panos", "pan_os", "palo"),
        extension="conf", secrets=PANOS_SECRETS, startup=False, enable_arg=None,
        notes="Stores 'set' format by default (optional_args.config_format: set|xml|json|default).",
    ),
    Platform(
        "huawei_vrp", "Huawei VRP", "Huawei", "netledger.drivers.huawei:HuaweiVRPDriver",
        aliases=("huawei", "vrp"),
        volatile=VRP_VOLATILE, secrets=VRP_SECRETS, meta=VRP_META, enable_arg=None,
    ),
    Platform(
        "comware", "HPE Comware / H3C", "HPE", "netledger.drivers.hpe:ComwareDriver",
        aliases=("hp_comware", "hpe_comware", "h3c"),
        secrets=COMWARE_SECRETS, enable_arg=None,
    ),
    Platform(
        "procurve", "HPE Aruba AOS-S (ProCurve)", "HPE Aruba", "netledger.drivers.hpe:ProCurveDriver",
        aliases=("hp_procurve", "aruba_osswitch", "aruba_procurve", "aos_s", "arubaos_switch"),
        volatile=PROCURVE_VOLATILE, secrets=PROCURVE_SECRETS,
    ),
    Platform(
        "aoscx", "HPE Aruba AOS-CX", "HPE Aruba", "netledger.drivers.hpe:AOSCXDriver",
        aliases=("aruba_aoscx", "aos_cx", "arubaos_cx", "aruba_cx"),
        volatile=AOSCX_VOLATILE, secrets=AOSCX_SECRETS, enable_arg=None,
    ),
    Platform(
        "routeros", "MikroTik RouterOS", "MikroTik", "netledger.drivers.mikrotik:RouterOSDriver",
        aliases=("mikrotik", "mikrotik_routeros", "ros"),
        extension="rsc", volatile=ROUTEROS_VOLATILE, secrets=ROUTEROS_SECRETS,
        startup=False, enable_arg=None,
        notes="Stores '/export terse'. Set optional_args.show_sensitive: true to include secrets on v7.",
    ),
    Platform(
        "dellos10", "Dell EMC SmartFabric OS10", "Dell", "netledger.drivers.dell:OS10Driver",
        aliases=("dell_os10", "os10"),
        volatile=OS10_VOLATILE, secrets=OS10_SECRETS, enable_arg=None,
    ),
    Platform(
        "exos", "Extreme Networks EXOS / Switch Engine", "Extreme Networks", "netledger.drivers.extreme:EXOSDriver",
        aliases=("extreme_exos", "extreme", "xos", "switch_engine"),
        secrets=EXOS_SECRETS, startup=False, enable_arg=None,
    ),
    Platform(
        "vyos", "VyOS", "VyOS", "netledger.drivers.vyos:VyOSDriver",
        extension="conf", secrets=VYOS_SECRETS, startup=False, enable_arg=None, health="partial",
    ),
    Platform(
        "edgeos", "Ubiquiti EdgeOS (EdgeRouter)", "Ubiquiti", "netledger.drivers.vyos:EdgeOSDriver",
        aliases=("ubiquiti_edgerouter", "edgerouter", "ubiquiti"),
        extension="conf", secrets=VYOS_SECRETS, startup=False, enable_arg=None, health="partial",
    ),
    Platform(
        "fastiron", "Ruckus ICX / Brocade FastIron", "Ruckus", "netledger.drivers.ruckus:FastIronDriver",
        aliases=("ruckus_fastiron", "icx", "ruckus_icx", "brocade_fastiron"),
        volatile=FASTIRON_VOLATILE, secrets=FASTIRON_SECRETS,
    ),
    Platform(
        "gaia", "Check Point Gaia", "Check Point", "netledger.drivers.checkpoint:GaiaDriver",
        aliases=("checkpoint_gaia", "checkpoint"),
        extension="conf", volatile=GAIA_VOLATILE, secrets=GAIA_SECRETS,
        startup=False, enable_arg=None, health="partial",
        notes="Backs up the Gaia OS (clish) configuration; security policy lives on the management server.",
    ),
    Platform(
        "generic", "Any Netmiko-supported device (config only)", "Generic", "netledger.drivers.generic:GenericDriver",
        aliases=("netmiko", "custom"),
        extension="txt", health="none",
        notes="Set optional_args.netmiko_device_type and optional_args.config_command.",
    ),
)

_REGISTRY: dict[str, Platform] = {}
_ALIASES: dict[str, str] = {}


def _norm(name: str) -> str:
    return re.sub(r"[\s\-.]+", "_", str(name).strip().lower())


def register_platform(platform: Platform, replace: bool = False) -> None:
    """Register a platform (built-in or third-party)."""
    key = _norm(platform.key)
    if key in _REGISTRY and not replace:
        raise ValueError(f"platform {platform.key!r} is already registered")
    _REGISTRY[key] = platform
    for alias in (platform.key, *platform.aliases):
        _ALIASES[_norm(alias)] = key


for _platform in BUILTIN_PLATFORMS:
    register_platform(_platform)


def resolve_platform(name: str) -> str | None:
    """Canonical platform key for a name or alias, or None if unknown."""
    return _ALIASES.get(_norm(name))


def get_platform(name: str) -> Platform:
    key = resolve_platform(name)
    if key is None:
        raise KeyError(name)
    return _REGISTRY[key]


def custom_platform(name: str, driver: str) -> Platform:
    """Platform for an explicit third-party driver without built-in rules."""
    return Platform(key=name, name=name, vendor="", driver=driver, netmiko_based=False, health="unknown")


def all_platforms() -> list[Platform]:
    return sorted(_REGISTRY.values(), key=lambda p: (p.vendor.lower(), p.key))


DRIVER_ALIASES = {
    "simulated": "netledger.drivers.simulated:SimulatedDriver",
    "demo": "netledger.drivers.simulated:SimulatedDriver",
}


def load_driver_class(spec: str) -> Any:
    """Load a NAPALM driver class from ``napalm:<name>``, ``module:Class`` or a plain NAPALM name."""
    spec = DRIVER_ALIASES.get(spec, spec)
    if ":" in spec and not spec.startswith("napalm:"):
        module_name, _, attr = spec.partition(":")
        module = importlib.import_module(module_name)
        try:
            return getattr(module, attr)
        except AttributeError as exc:
            raise ImportError(f"{module_name} has no driver class {attr!r}") from exc
    from napalm import get_network_driver

    return get_network_driver(spec.split(":", 1)[1] if spec.startswith("napalm:") else spec)
