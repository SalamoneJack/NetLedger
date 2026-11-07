"""Sanitize configurations and command output so they can be shared in bug reports.

``netledger sanitize`` keeps what a parser depends on (sections, indentation, keywords, masks, wildcards,
prefix lengths) and replaces what identifies a network:

* secrets, with the platform's own secret rules first and generic ones after;
* IPv4 and IPv6 addresses, mapped consistently and prefix-preservingly: the same address always gets the same
  replacement in one run, and a host stays inside its subnet. Masks and wildcards are kept, and so are
  special ranges (loopback, link-local, multicast, documentation). Private addresses stay private;
  ``keep_private`` leaves them unchanged;
* host names, domain names, user names, SNMP communities, descriptions and comments, MAC addresses (the
  vendor prefix is kept), serial numbers, AS numbers (mapped to the private range from 64512) and
  certificate, key and banner text.

Lines are never added or removed and indentation never changes, so the result parses like the original.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import secrets
from collections import Counter
from typing import Dict, Iterable, List, Optional, Tuple, Union

from netledger.intel import detect_syntax, parse
from netledger.normalize import MASK, apply_secret_rules, basic_clean
from netledger.platforms import Platform, SecretRule, get_platform

# Secret rules to use when the platform is not given, by syntax family.
_SYNTAX_PLATFORMS = {
    "fortios": ("fortios",),
    "braces": ("junos", "vyos"),
    "set": ("panos", "gaia"),
    "routeros": ("routeros",),
    "indent": ("ios", "nxos", "iosxr", "eos", "asa", "aireos", "cisco_smb", "huawei_vrp", "comware", "procurve", "aoscx", "dellos10", "exos", "fastiron"),
}

# Generic rules never cross a line break ([ \t], not \s): a keyword at the end of one line must not mask the
# first word of the next one.
_GENERIC_SECRETS = (
    SecretRule(
        "sanitize.keyword",
        r"(?<![\w-])(?:password|passwd|secret|pre-shared-key(?:[ \t]+key)?|psksecret|passphrase|key-string|auth-key"
        r"|authentication-key|md5-key|shared-secret|wpa-psk|encrypted-password|plaintext-password)"
        r"(?:[ \t]+(?:\d{1,2}|encrypted|cipher|simple|hash|ascii|hex|plaintext|ciphertext|irreversible-cipher|ENC|sha512|sha256|md5))?"
        r"[ \t]+(?P<secret>\"[^\"\n]*\"|'[^'\n]*'|[^\s;]+)",
        re.M | re.I,
    ),
    SecretRule(
        "sanitize.key-value",
        r"(?<![\w-])(?:password|secret|psk|passphrase|wpa2?-pre-shared-key|pre-shared-key|private-key|auth-key|key)"
        r"=(?P<secret>\"[^\"\n]*\"|\S+)",
        re.M | re.I,
    ),
    SecretRule(
        "sanitize.snmp-community",
        r"\bsnmp(?:-server|-agent)?\b[^\n]*?\bcommunity[ \t]+(?:(?:read|write|cipher|simple|create)[ \t]+)*(?P<secret>\"[^\"\n]*\"|[^\s;{]+)",
        re.M | re.I,
    ),
    SecretRule("sanitize.crypt-hash", r"(?P<secret>\$(?:1|2[aby]?|5|6|8|9|14)\$[^\s\";]+)", re.M),
)

_PEM = re.compile(r"(-----BEGIN ([A-Z0-9 ]+)-----)(.*?)(-----END \2-----)", re.S)
_HEX_LINE = re.compile(r"^(\s+)[0-9A-Fa-f]{8}(?: [0-9A-Fa-f]{8})*\s*$")
_SSH_KEY = re.compile(r"\b((?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-\S+)\s+)AAAA[0-9A-Za-z+/=]+")
_COMMENT = re.compile(r"^(\s*(?:[!#;]+\s*)?)")

# Free text: the value after these keywords is replaced, the keyword and quoting are kept.
_FREE_TEXT = (
    re.compile(
        r'^(?P<lead>\s*(?:no\s+)?(?:description|remark|snmp-server\s+(?:location|contact)|location|contact|announcement|message)\s+)'
        r'(?P<value>.+?)(?P<tail>;?)\s*$',
        re.I,
    ),
    re.compile(r'(?P<lead>\sremark\s+)(?P<value>.+?)(?P<tail>)\s*$', re.I),  # access-list NAME remark ...
    re.compile(  # set description "...", neighbor X description ..., Junos description "...";
        r'(?P<lead>(?:^|\s)(?:set\s+alias|(?:set\s+)?(?:description|comments?|location|contact|contact-info))\s+)'
        r'(?P<value>"[^"]*"|[^"\s;][^;]*?)(?P<tail>;?)\s*$',
        re.I,
    ),
    re.compile(r'(?P<lead>(?:^|\s)(?:comment|location|contact)=)(?P<value>"(?:[^"\\]|\\.)*"|\S+)(?P<tail>)', re.I),
)

_HOSTNAMES = (
    re.compile(r'^\s*(?:set\s+)?(?:system\s+)?(?:hostname|host-name|switchname|sysname)\s+"?(?P<name>[^"\s;]+)', re.I),
    re.compile(r'^\s*set\s+deviceconfig\s+system\s+hostname\s+"?(?P<name>[^"\s]+)', re.I),
    re.compile(r'^/system identity set name="?(?P<name>[^"\s]+)', re.I),
    re.compile(r'^\s*configure\s+snmp\s+sysName\s+"?(?P<name>[^"\s]+)', re.I),
    re.compile(r'^\s*ip\s+host\s+(?:vrf\s+\S+\s+)?(?P<name>[A-Za-z][\w.-]*)\s', re.I),
)
_USERS = (
    re.compile(r'^\s*(?:username|local-user)\s+"?(?P<name>[^"\s]+)', re.I),
    re.compile(r'^\s*user\s+"?(?P<name>[^"\s]+)"?\s+(?:group\b|\{)', re.I),
    re.compile(r'^\s*(?:set\s+system\s+login\s+user|set\s+mgt-config\s+users)\s+"?(?P<name>[^"\s]+)', re.I),
    re.compile(r'\bpassword\s+(?:manager|operator)\s+user-name\s+"?(?P<name>[^"\s]+)', re.I),
    re.compile(r'^\s*snmp-server\s+user\s+(?P<name>\S+)', re.I),
    re.compile(r'^/user\s+(?:add|set)\b.*\bname="?(?P<name>[^"\s]+)', re.I),
    re.compile(r'^\s*[!#]+.*\bby\s+(?P<name>[A-Za-z][\w.-]*)\s*$', re.I),
    re.compile(r'[:\s]user=(?P<name>[A-Za-z][\w.-]*)', re.I),
)
_FORTI_USERS = ("config system admin", "config user local", "config system snmp user")
_DOMAINS = re.compile(
    r'(?:\bip\s+domain[- ](?:name|list)|\bdomain-name|\bdns\s+domain|\bset\s+domain|\bdeviceconfig\s+system\s+domain'
    r'|\bdomain-search|\bdomain-lookup\s+domain)\s+(?:vrf\s+\S+\s+)?"?(?P<name>[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)"?',
    re.I,
)
_KEEP_NAMES = frozenset({
    "admin", "administrator", "root", "cisco", "manager", "operator", "guest", "user", "super", "superuser", "monitor",
    "readonly", "read-only", "support", "enable", "default", "none", "any", "all", "netledger", "localhost",
})
_TLDS = frozenset({
    "com", "net", "org", "edu", "gov", "mil", "int", "io", "co", "us", "uk", "de", "fr", "nl", "be", "ch", "at", "se",
    "no", "dk", "fi", "it", "es", "pt", "ie", "pl", "cz", "eu", "ca", "au", "nz", "jp", "cn", "in", "br", "mx", "za",
    "ru", "local", "lan", "corp", "internal", "intranet", "home", "localdomain", "cloud", "online", "tech", "dev",
    "app", "site", "biz", "info", "me", "tv",
})
_FQDN = re.compile(r"(?<![\w.@/-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{0,23})(?![\w-]|\.\w)")
_EMAIL = re.compile(r"(?<![\w.+-])([\w.+-]+)@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24})(?![\w-])")

_IPV4 = re.compile(r"(?<![\w.:])(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?(?![\w.])")
_NEXT_MASK = re.compile(r"^\s+(?:mask\s+|netmask\s+)?(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])", re.I)
_IPV6 = re.compile(r"(?<![\w:.])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?::\d{1,3}(?:\.\d{1,3}){3})?)(?:/(\d{1,3}))?(?![\w:.])")
_MAC = re.compile(
    r"(?<![\w:.-])([0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\2){4}[0-9A-Fa-f]{2}|[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}"
    r"|[0-9A-Fa-f]{6}-[0-9A-Fa-f]{6})(?![\w:.-])"
)
_SERIALS = (
    re.compile(r'(?P<lead>\bserial(?:[ _-]?(?:number|num|no))?\s*[:=#]?\s*"?)(?P<value>[A-Z0-9][A-Z0-9-]{5,})', re.I),
    re.compile(r"(?P<lead>\bSN:\s*)(?P<value>[A-Z0-9][A-Z0-9-]{5,})"),
    re.compile(r"(?P<lead>\bsn\s+)(?P<value>[A-Z0-9]{8,})", re.I),
    re.compile(r"(?P<lead>\bProcessor board ID\s+)(?P<value>[A-Z0-9]{6,})", re.I),
    re.compile(r"(?P<lead>\bchassis-id\s+)(?P<value>\S{6,})", re.I),
    re.compile(r"(?P<lead>\bsoftware id\s*=\s*)(?P<value>[A-Z0-9][A-Z0-9-]{5,})", re.I),
)
_ASNS = (
    re.compile(r"(?P<lead>\brouter\s+bgp\s+)(?P<asn>\d+)", re.I),
    re.compile(r"(?P<lead>^\s*bgp\s+)(?P<asn>\d+)(?=\s*$)", re.I),
    re.compile(r"(?P<lead>\b(?:remote-as|local-as|peer-as|as-number|autonomous-system|confederation\s+identifier)\s+)(?P<asn>\d+)", re.I),
    re.compile(r"(?P<lead>\bset\s+(?:as|remote-as|local-as)\s+)(?P<asn>\d+)", re.I),
    re.compile(r"(?P<lead>(?:^|\s)(?:remote\.as|local\.as|remote-as|as)=)(?P<asn>\d+)", re.I),
)
_CONFED_PEERS = re.compile(r"(?P<lead>\bconfederation\s+peers\s+)(?P<asns>\d+(?:\s+\d+)*)", re.I)
_COMMUNITY_LINE = re.compile(r"\b(?:community|route-target|extcommunity|vpn-target|rd|target)\b", re.I)
_COMMUNITY = re.compile(r"(?<![\w.:])(\d{1,10}):(\d{1,10})(?![\w.:])")
_RESERVED_ASNS = frozenset({0, 23456, 65535, 4294967295})

# IPv4 ranges kept as they are, and private blocks whose prefix is kept (only the rest is mapped)
_SPECIAL4 = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/3", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "198.18.0.0/15",
))
_RFC1918 = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
_SHARED4 = (ipaddress.ip_network("100.64.0.0/10"),)
_SPECIAL6 = tuple(ipaddress.ip_network(n) for n in ("::/127", "::ffff:0:0/96", "ff00::/8", "2001:db8::/32", "64:ff9b::/96"))
_UNIQUE_LOCAL6 = ipaddress.ip_network("fc00::/7")
_LINK_LOCAL6 = ipaddress.ip_network("fe80::/10")


def _lead(line: str) -> str:
    """Leading whitespace and comment characters, kept so a line keeps its place in the structure."""
    match = _COMMENT.match(line)
    return match.group(1) if match else ""


def _is_address(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _contiguous_mask(value: int) -> Optional[int]:
    """Prefix length if ``value`` is a netmask (255.255.255.0) or an ACL wildcard (0.0.0.255), else None."""
    full = (1 << 32) - 1
    inverted = full ^ value
    if inverted & (inverted + 1) == 0:
        return 32 - inverted.bit_length()
    if value & (value + 1) == 0:
        return 32 - value.bit_length()
    return None


class Sanitizer:
    """Replaces identifying content consistently within one run. Use one instance per document (or set)."""

    def __init__(
        self,
        platform: Optional[Platform] = None,
        keep_private: bool = False,
        key: Optional[bytes] = None,
        names: Iterable[str] = (),
    ):
        self.platform = platform
        self.keep_private = keep_private
        self.key = key if key is not None else secrets.token_bytes(32)
        self.counts: Counter[str] = Counter()
        self._flips: Dict[Tuple[int, int, int], int] = {}
        self._addresses: set[str] = set()
        self._identifiers: Dict[str, str] = {}
        self._kinds: Counter[str] = Counter()
        self._texts: Dict[str, str] = {}
        self._domains: Dict[str, str] = {}
        self._labels: Dict[str, str] = {}
        self._fqdns: Dict[str, str] = {}
        self._emails: Dict[str, str] = {}
        self._macs: Dict[str, str] = {}
        self._serials: Dict[str, str] = {}
        self._asns: Dict[int, int] = {}
        self._known_domains: set[str] = set()
        self._names_regex: Optional[re.Pattern[str]] = None
        for name in names:
            self._identifier(name, "device")

    # ------------------------------------------------------------------ mapping helpers

    def _flip(self, width: int, index: int, prefix: int) -> int:
        cached = self._flips.get((width, index, prefix))
        if cached is None:
            digest = hmac.new(self.key, f"{width}/{index}/{prefix:x}".encode(), hashlib.sha256).digest()
            cached = self._flips[(width, index, prefix)] = digest[0] & 1
        return cached

    def _permute(self, value: int, width: int, keep: int) -> int:
        """Prefix-preserving keyed permutation: the top ``keep`` bits stay, the rest are mapped."""
        result = (value >> (width - keep)) << (width - keep) if keep else 0
        for index in range(keep, width):
            position = width - 1 - index
            bit = (value >> position) & 1
            result |= (bit ^ self._flip(width, index, value >> (position + 1))) << position
        return result

    def _identifier(self, name: str, kind: str) -> Optional[str]:
        clean = name.strip().strip('"').strip("'")
        lower = clean.lower()
        if not clean or lower in _KEEP_NAMES or clean.startswith("<") or _is_address(clean) or re.fullmatch(r"(?:device|user|host|text)\d+", lower):
            return None
        if lower not in self._identifiers:
            self._kinds[kind] += 1
            self._identifiers[lower] = f"{kind}{self._kinds[kind]}"
            self._names_regex = None
        return self._identifiers[lower]

    def _text(self, value: str) -> str:
        quote = value[0] if value[:1] in ('"', "'") and value.endswith(value[0]) and len(value) > 1 else ""
        inner = value[1:-1] if quote else value
        if not inner.strip() or inner.startswith("<"):
            return value
        replacement = self._texts.setdefault(inner, f"text-{len(self._texts) + 1}")
        return f"{quote}{replacement}{quote}"

    def _label(self, label: str) -> str:
        known = self._identifiers.get(label.lower())
        if known:
            return known
        return self._labels.setdefault(label.lower(), f"host{len(self._labels) + 1}")

    def fqdn(self, name: str) -> str:
        lower = name.lower().rstrip(".")
        if lower in self._fqdns:
            return self._fqdns[lower]
        domain = next((d for d in sorted(self._known_domains, key=len, reverse=True) if lower == d or lower.endswith("." + d)), None)
        if domain is None:
            labels = lower.split(".")
            domain = ".".join(labels[-2:])
        mapped = self._domains.setdefault(domain, f"domain{len(self._domains) + 1}.example")
        if lower != domain:
            mapped = ".".join(self._label(label) for label in lower[: -len(domain) - 1].split(".")) + "." + mapped
        self._fqdns[lower] = mapped
        return mapped

    def _is_fqdn(self, name: str) -> bool:
        lower = name.lower()
        if lower.rsplit(".", 1)[-1] in _TLDS:
            return True
        return any(lower == d or lower.endswith("." + d) for d in self._known_domains)

    def address4(self, text: str, prefix: Optional[int] = None) -> str:
        address = ipaddress.IPv4Address(text)
        value = int(address)
        if _contiguous_mask(value) is not None or any(address in net for net in _SPECIAL4):
            return text
        private = next((net for net in _RFC1918 if address in net), None)
        if private is not None and self.keep_private:
            return text
        block = private or next((net for net in _SHARED4 if address in net), None)
        keep = block.prefixlen if block is not None else 8
        mapped = self._permute(value, 32, keep)
        if prefix is not None and 0 < prefix < 32 and value & ((1 << (32 - prefix)) - 1) == 0:
            mapped &= ((1 << 32) - 1) ^ ((1 << (32 - prefix)) - 1)  # a network stays a network
        self._addresses.add(text)
        return str(ipaddress.IPv4Address(mapped))

    def address6(self, text: str, prefix: Optional[int] = None) -> str:
        address = ipaddress.IPv6Address(text)
        if any(address in net for net in _SPECIAL6):
            return text
        if address in _UNIQUE_LOCAL6:
            if self.keep_private:
                return text
            keep = 8
        elif address in _LINK_LOCAL6:
            keep = 64  # only the interface id (often derived from the MAC address) is identifying
        else:
            keep = 16
        value = int(address)
        mapped = self._permute(value, 128, keep)
        if prefix is not None and 0 < prefix < 128 and value & ((1 << (128 - prefix)) - 1) == 0:
            mapped &= ((1 << 128) - 1) ^ ((1 << (128 - prefix)) - 1)
        self._addresses.add(address.compressed)
        return ipaddress.IPv6Address(mapped).compressed

    def mac(self, text: str) -> str:
        digits = re.sub(r"[^0-9A-Fa-f]", "", text).lower()
        first = int(digits[:2], 16)
        if first & 1 or digits in ("000000000000", "ffffffffffff"):
            return text  # multicast, broadcast, empty
        if digits not in self._macs:
            nic = hmac.new(self.key, b"mac/" + digits.encode(), hashlib.sha256).hexdigest()[:6]
            self._macs[digits] = digits[:6] + nic
        mapped = iter(self._macs[digits])
        result = "".join(next(mapped) if ch in "0123456789abcdefABCDEF" else ch for ch in text)
        return result.upper() if any(ch in "ABCDEF" for ch in text) else result

    def asn(self, value: int) -> int:
        if value in _RESERVED_ASNS or value > 4294967295:
            return value
        if value not in self._asns:
            index = len(self._asns)
            self._asns[value] = 64512 + index if index < 1023 else 4200000000 + index
        return self._asns[value]

    # ------------------------------------------------------------------ passes

    def _secret_platforms(self, text: str) -> List[Platform]:
        if self.platform is not None:
            return [self.platform]
        return [get_platform(key) for key in _SYNTAX_PLATFORMS.get(detect_syntax(text), ())]

    def _mask_secrets(self, text: str) -> str:
        before = text.count(MASK)
        for platform in self._secret_platforms(text):
            text = apply_secret_rules(text, platform.secrets, lambda _value: MASK)
        text = apply_secret_rules(text, _GENERIC_SECRETS, lambda _value: MASK)
        self.counts["secrets"] += text.count(MASK) - before
        return text

    def _mask_key_material(self, text: str) -> str:
        def pem(match: re.Match[str]) -> str:
            self.counts["keys and certificates"] += 1
            body = "\n".join(_lead(line) + MASK if line.strip() else line for line in match.group(3).split("\n"))
            return match.group(1) + body + match.group(4)

        text = _PEM.sub(pem, text)
        text = _SSH_KEY.sub(lambda m: m.group(1) + MASK, text)
        lines = text.split("\n")
        for index, line in enumerate(lines):
            match = _HEX_LINE.match(line)
            if match:
                lines[index] = match.group(1) + MASK
        return "\n".join(lines)

    def _mask_banners(self, lines: List[str]) -> None:
        index = 0
        while index < len(lines):
            match = re.match(r"^(banner\s+\S+)(\s*)(.*)$", lines[index])
            if not match:
                index += 1
                continue
            rest = match.group(3)
            if not rest:
                delimiter, body = "EOF", ""
            elif rest.startswith("^C"):
                delimiter, body = "^C", rest[2:]
            else:
                delimiter, body = rest[0], rest[1:]
            head = match.group(1) + match.group(2) + (delimiter if rest else "")
            if delimiter != "EOF" and delimiter in body:  # a banner on one line
                lines[index] = head + (MASK if body.split(delimiter, 1)[0] else "") + delimiter + body.split(delimiter, 1)[1]
                index += 1
                continue
            lines[index] = head + (MASK if body.strip() else body)
            index += 1
            while index < len(lines):
                line = lines[index]
                done = line.strip() == "EOF" if delimiter == "EOF" else delimiter in line
                if done:
                    if delimiter != "EOF" and line.split(delimiter, 1)[0].strip():
                        lines[index] = MASK + delimiter + line.split(delimiter, 1)[1]
                    break
                if line.strip():
                    lines[index] = _lead(line) + MASK
                index += 1
            self.counts["banners"] += 1
            index += 1

    def _learn(self, lines: List[str], paths: List[Optional[Tuple[str, ...]]]) -> None:
        for line, path in zip(lines, paths):
            for pattern in _HOSTNAMES:
                match = pattern.search(line)
                if match:
                    self._identifier(match.group("name"), "device")
            for pattern in _USERS:
                match = pattern.search(line)
                if match:
                    self._identifier(match.group("name"), "user")
            if path and path[0] in _FORTI_USERS and line.strip().startswith("edit "):
                self._identifier(line.strip()[5:], "user")
            match = _DOMAINS.search(line)
            if match:
                self._known_domains.add(match.group("name").lower())
            for pattern in _ASNS:
                for found in pattern.finditer(line):
                    self.asn(int(found.group("asn")))

    def _free_text(self, line: str, path: Optional[Tuple[str, ...]]) -> str:
        if path and path[0] == "config system snmp community" and re.match(r"^\s*set\s+name\s", line):
            return re.sub(r'(set\s+name\s+)("[^"]*"|\S+)', lambda m: m.group(1) + '"' + MASK + '"', line)
        for index, pattern in enumerate(_FREE_TEXT):
            if index == 0:
                match = pattern.match(line)
                if match and not match.group("value").startswith("<"):
                    self.counts["descriptions"] += 1
                    return match.group("lead") + self._text(match.group("value")) + match.group("tail")
                continue
            replaced, count = pattern.subn(lambda m: m.group("lead") + self._text(m.group("value")) + m.group("tail"), line)
            if count:
                self.counts["descriptions"] += count
                return replaced
        return line

    def _addresses_in(self, line: str) -> str:
        # networks written with a prefix on this line, e.g. RouterOS "address=10.1.1.1/24 ... network=10.1.1.0"
        known: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        for pattern in (_IPV4, _IPV6):
            for text, length in pattern.findall(line):
                if length:
                    try:
                        known.append(ipaddress.ip_network(f"{text}/{length}", strict=False))
                    except ValueError:
                        pass

        def network_prefix(address: Union[ipaddress.IPv4Address, ipaddress.IPv6Address], fallback: int) -> int:
            """A bare network address (x.y.z.0, 2001:db8:1::): the prefix of a network it starts, or a cautious guess."""
            for network in known:
                if network.version == address.version and address == network.network_address:
                    return network.prefixlen
            return fallback

        def v4(match: re.Match[str]) -> str:
            text, length = match.group(1), match.group(2)
            try:
                address = ipaddress.IPv4Address(text)
            except ValueError:
                return match.group(0)
            prefix = int(length) if length else None
            if prefix is None:
                following = _NEXT_MASK.match(line[match.end():])
                if following:
                    try:
                        prefix = _contiguous_mask(int(ipaddress.IPv4Address(following.group(1))))
                    except ValueError:
                        prefix = None
            if prefix is None and int(address) & 0xFF == 0:
                prefix = network_prefix(address, 24)  # only the last octet: never pushes a host out of its subnet
            mapped = self.address4(text, prefix)
            return mapped + (f"/{length}" if length else "")

        def v6(match: re.Match[str]) -> str:
            text, length = match.group(1), match.group(2)
            try:
                address = ipaddress.IPv6Address(text)
            except ValueError:
                return match.group(0)
            prefix = int(length) if length else None
            if prefix is None and int(address) & 0xFFFF == 0:
                prefix = network_prefix(address, 64)
            return self.address6(text, prefix) + (f"/{length}" if length else "")

        line = _IPV4.sub(v4, line)
        return _IPV6.sub(v6, line)

    def email(self, match: re.Match[str]) -> str:
        address = match.group(0).lower()
        if address not in self._emails:
            self._emails[address] = f"user{len(self._emails) + 1}@{self.fqdn(match.group(2))}"
        return self._emails[address]

    def _names_in(self, line: str) -> str:
        line = _EMAIL.sub(self.email, line)
        line = _FQDN.sub(lambda m: self.fqdn(m.group(1)) if self._is_fqdn(m.group(1)) else m.group(1), line)
        if self._identifiers:
            if self._names_regex is None:
                alternatives = "|".join(re.escape(name) for name in sorted(self._identifiers, key=len, reverse=True))
                self._names_regex = re.compile(rf"(?<![\w.-])(?:{alternatives})(?![\w-])", re.I)
            line = self._names_regex.sub(lambda m: self._identifiers[m.group(0).lower()], line)
        return line

    def _numbers_in(self, line: str) -> str:
        line = _MAC.sub(lambda m: self.mac(m.group(1)), line)
        for pattern in _SERIALS:
            line = pattern.sub(lambda m: m.group("lead") + self._serials.setdefault(m.group("value"), f"SERIAL{len(self._serials) + 1}"), line)
        for pattern in _ASNS:
            line = pattern.sub(lambda m: m.group("lead") + str(self.asn(int(m.group("asn")))), line)
        line = _CONFED_PEERS.sub(lambda m: m.group("lead") + " ".join(str(self.asn(int(a))) for a in m.group("asns").split()), line)
        if _COMMUNITY_LINE.search(line):
            line = _COMMUNITY.sub(lambda m: f"{self.asn(int(m.group(1)))}:{m.group(2)}" if int(m.group(1)) <= 4294967295 else m.group(0), line)
        if "as-path" in line.lower() and self._asns:  # AS-path expressions: only numbers known to be AS numbers
            line = re.sub(r"(?<!\d)\d+(?!\d)", lambda m: str(self._asns.get(int(m.group(0)), m.group(0))), line)
        return line

    def sanitize(self, text: str) -> str:
        """The sanitized text: same lines and indentation, nothing identifying."""
        text = basic_clean(text)
        text = self._mask_secrets(text)
        text = self._mask_key_material(text)
        lines = text.split("\n")
        self._mask_banners(lines)
        parsed = parse("\n".join(lines), platform=self.platform.key if self.platform else None)
        paths = parsed.paths + [None] * (len(lines) - len(parsed.paths))
        self._learn(lines, paths)
        out = []
        for line, path in zip(lines, paths):
            line = self._free_text(line, path)
            line = self._names_in(line)
            line = self._addresses_in(line)
            line = self._numbers_in(line)
            out.append(line)
        self.counts["addresses"] = len(self._addresses)
        self.counts["names"] = len(self._identifiers) + len(self._fqdns) + len(self._emails)
        self.counts["MAC addresses"] = len(self._macs)
        self.counts["serial numbers"] = len(self._serials)
        self.counts["AS numbers"] = len(self._asns)
        return "\n".join(out)

    def summary(self) -> str:
        parts = [f"{count} {what}" for what, count in self.counts.items() if count]
        return ", ".join(parts) if parts else "nothing to replace"


def sanitize(text: str, platform: Optional[str] = None, keep_private: bool = False, key: Optional[bytes] = None) -> str:
    """Sanitize one text (see :class:`Sanitizer`)."""
    return Sanitizer(get_platform(platform) if platform else None, keep_private, key).sanitize(text)
