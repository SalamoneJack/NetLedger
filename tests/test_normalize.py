from __future__ import annotations

from netledger.config import CustomRule, NormalizeSettings
from netledger.normalize import Normalizer, basic_clean, finalize
from netledger.platforms import get_platform

IOS_RUNNING = """\r
Building configuration...\r
\r
Current configuration : 4012 bytes\r
!\r
! Last configuration change at 14:02:11 UTC Tue Oct 27 2026 by jsmith\r
! NVRAM config last updated at 13:58:40 UTC Tue Oct 27 2026 by netadmin\r
!\r
version 17.9\r
hostname core1\r
enable secret 9 $9$abc$defghijk\r
username admin privilege 15 secret 9 $9$xyz$123\r
username bob password 7 0822455D0A16\r
username nopw privilege 1 nopassword\r
snmp-server community S3cretComm RO SNMP-ACL\r
snmp-server host 10.0.0.5 version 2c TrapComm\r
tacacs server ISE\r
 address ipv4 10.0.0.40\r
 key 7 0822455D0A16544541\r
interface Vlan10\r
 standby 10 authentication md5 key-string 7 1234ABCD\r
router bgp 65000\r
 neighbor 10.1.1.1 password 7 05080F1C2243\r
ntp clock-period 17179224\r
line vty 0 4\r
 password 7 045802150C2E\r
end\r
"""


def test_basic_clean_and_finalize() -> None:
    assert basic_clean("a\r\nb\rc\x1b[0mx\x07") == "a\nb\ncx"
    assert finalize("\n\n  a  \nb\t\n\n\n") == "  a\nb\n"
    assert finalize("\n \n") == ""


def test_ios_volatile_lines_and_meta() -> None:
    result = Normalizer().normalize(IOS_RUNNING, get_platform("ios"))
    assert "Building configuration" not in result.text
    assert "Current configuration" not in result.text
    assert "Last configuration change" not in result.text
    assert "ntp clock-period" not in result.text
    assert result.text.startswith("!\n!\nversion 17.9\n")
    assert result.meta == {"changed_at": "14:02:11 UTC Tue Oct 27 2026", "changed_by": "jsmith"}
    assert "\r" not in result.text and result.text.endswith("end\n")
    # keep mode leaves secrets untouched
    assert "S3cretComm" in result.text and "0822455D0A16544541" in result.text


def test_ios_running_and_startup_normalize_identically() -> None:
    startup = IOS_RUNNING.replace("Building configuration...\r\n\r\n", "").replace(
        "Current configuration : 4012 bytes", "Using 4012 out of 33554432 bytes"
    ).replace("ntp clock-period 17179224", "ntp clock-period 17179001")
    normalizer = Normalizer()
    platform = get_platform("ios")
    assert normalizer.normalize(IOS_RUNNING, platform).text == normalizer.normalize(startup, platform).text


def test_ios_secret_masking() -> None:
    text = Normalizer(NormalizeSettings(secrets="mask")).normalize(IOS_RUNNING, get_platform("ios")).text
    for secret in ("$9$abc$defghijk", "$9$xyz$123", "0822455D0A16", "S3cretComm", "TrapComm",
                   "0822455D0A16544541", "1234ABCD", "05080F1C2243", "045802150C2E"):
        assert secret not in text, secret
    assert "enable secret 9 <removed>" in text
    assert "username admin privilege 15 secret 9 <removed>" in text
    assert "snmp-server community <removed> RO SNMP-ACL" in text
    assert "snmp-server host 10.0.0.5 version 2c <removed>" in text
    assert "username nopw privilege 1 nopassword" in text
    assert " key 7 <removed>" in text


def test_hmac_mode_is_stable_keyed_and_idempotent() -> None:
    platform = get_platform("ios")
    first = Normalizer(NormalizeSettings(secrets="hmac", secret_key="k1")).normalize(IOS_RUNNING, platform).text
    again = Normalizer(NormalizeSettings(secrets="hmac", secret_key="k1")).normalize(IOS_RUNNING, platform).text
    other_key = Normalizer(NormalizeSettings(secrets="hmac", secret_key="k2")).normalize(IOS_RUNNING, platform).text
    assert first == again
    assert first != other_key
    assert "S3cretComm" not in first and "<secret:" in first
    changed = Normalizer(NormalizeSettings(secrets="hmac", secret_key="k1")).normalize(
        IOS_RUNNING.replace("S3cretComm", "N3wComm"), platform
    ).text
    assert changed != first  # a secret change is still visible in the diff
    # normalizing already-normalized text does not re-hash placeholders
    assert Normalizer(NormalizeSettings(secrets="hmac", secret_key="k1")).normalize(first, platform).text == first


FORTIOS = """#config-version=FG200F-7.4.3-FW-build2573-240201:opmode=0:vdom=0:user=netledger
#conf_file_ver=31536984502711
#buildno=2573
config system admin
    edit "admin"
        set password ENC SH2nlFk8Ghhd2yC0I5gUmkA0AAAAA
    next
end
config vpn ipsec phase1-interface
    edit "to-dc1"
        set psksecret ENC 4rG7vSyCqUL9/xLrHgYp0w==
    next
end
config vpn certificate local
    edit "web"
        set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQI
-----END ENCRYPTED PRIVATE KEY-----"
        set certificate "-----BEGIN CERTIFICATE-----
MIIDdzCCAl+gAwIBAgIE
-----END CERTIFICATE-----"
    next
end
"""


def test_fortios_noise_is_removed_but_real_content_kept() -> None:
    platform = get_platform("fortios")
    run1 = Normalizer().normalize(FORTIOS, platform).text
    run2 = Normalizer().normalize(
        FORTIOS.replace("31536984502711", "99999999999999").replace("4rG7vSyCqUL9/xLrHgYp0w==", "Zm9vYmFyYmF6cXV4"), platform
    ).text
    assert run1 == run2
    assert "#conf_file_ver" not in run1
    assert "set psksecret ENC <encrypted>" in run1
    assert "set password ENC SH2nlFk8Ghhd2yC0I5gUmkA0AAAAA" in run1  # stable hash, kept
    assert 'set private-key "<private key removed>"' in run1
    assert "BEGIN CERTIFICATE" in run1  # public certificate kept


def test_disable_rules_and_mask_sh2() -> None:
    platform = get_platform("fortios")
    keep_enc = Normalizer(NormalizeSettings(disable_rules=["fortios.enc"])).normalize(FORTIOS, platform).text
    assert "4rG7vSyCqUL9/xLrHgYp0w==" in keep_enc
    masked = Normalizer(NormalizeSettings(secrets="mask")).normalize(FORTIOS, platform).text
    assert "SH2nlFk8" not in masked and "set password ENC <removed>" in masked


def test_custom_rules_scoped_by_platform() -> None:
    settings = NormalizeSettings(rules=[
        CustomRule(pattern=r"^! Last reload.*"),
        CustomRule(pattern=r"(snmp-server location) .*", replace=r"\1 <hidden>", platforms=["ios"]),
    ])
    text = "! Last reload: today\nsnmp-server location Rack 4\nhostname x\n"
    ios = Normalizer(settings).normalize(text, get_platform("ios")).text
    eos = Normalizer(settings).normalize(text, get_platform("eos")).text
    assert ios == "snmp-server location <hidden>\nhostname x\n"
    assert eos == "snmp-server location Rack 4\nhostname x\n"


def test_other_platform_rules() -> None:
    mask = Normalizer(NormalizeSettings(secrets="mask"))
    ros = mask.normalize(
        '# 2026-10-30 21:00:00 by RouterOS 7.14.3\n/user add name=ops password="p@ss word"\n/interface wireguard add private-key=abc= public-key=pub\n',
        get_platform("routeros"),
    ).text
    assert ros.startswith("# RouterOS 7.14.3\n")
    assert 'password="<removed>"' in ros and "private-key=<removed>" in ros and "public-key=pub" in ros

    junos = mask.normalize(
        '## Last commit: 2026-10-26 09:14:03 UTC by mlopez\nsystem {\n    root-authentication {\n'
        '        encrypted-password "$6$abc$def"; ## SECRET-DATA\n    }\n}\n',
        get_platform("junos"),
    )
    assert "Last commit" not in junos.text and '"<removed>"; ## SECRET-DATA' in junos.text
    assert junos.meta["changed_by"] == "mlopez"

    panos = mask.normalize(
        "set network ike gateway gw authentication pre-shared-key key -AQ==abcdef\nset mgt-config users admin phash $5$xyz\n",
        get_platform("panos"),
    ).text
    assert "-AQ==abcdef" not in panos and "pre-shared-key key <removed>" in panos and "phash <removed>" in panos

    vrp = mask.normalize(
        "!Last configuration was updated at 2026-10-30 10:00:00+00:00 by admin\nlocal-user admin password irreversible-cipher $1a$xyz$\n",
        get_platform("huawei_vrp"),
    )
    assert "Last configuration" not in vrp.text and "irreversible-cipher <removed>" in vrp.text
    assert vrp.meta["changed_by"] == "admin"


def test_command_output_exclusions() -> None:
    out = Normalizer().normalize_output("router uptime is 5 weeks\nCisco IOS 17.9\n", get_platform("ios"), ["uptime is"])
    assert out == "Cisco IOS 17.9\n"
