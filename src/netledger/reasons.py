"""Why a change got its risk level, in plain English.

Change intelligence (:mod:`netledger.intel`) places every changed line in its configuration section and
gives the section a risk level from its category. This module explains the level from what the change
actually does: a firewall rule that now allows more traffic, an interface shut down, a routing neighbor
removed, route redistribution, accounts and AAA, address translation. It reads the same syntax families
as the parser: indentation (IOS, NX-OS, EOS, IOS-XR, ASA, ...), FortiOS ``config``/``edit`` blocks, Junos
braces and PAN-OS ``set`` commands.

Lines arrive as ``(path, text)`` pairs: the section headers above a line and the line relative to its
section, exactly as :func:`netledger.intel.analyze` groups them.
"""

from __future__ import annotations

import difflib
import ipaddress
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

Line = Tuple[Tuple[str, ...], str]

_ORDER = {"low": 0, "medium": 1, "high": 2}
_FULL = {4: (1 << 32) - 1, 6: (1 << 128) - 1}
_TOKEN = re.compile(r'"[^"]*"|\'[^\']*\'|\S+')
_DOTTED = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


@dataclass
class Finding:
    """One reason. ``level`` raises the section to at least that risk; ``None`` explains without raising it."""

    text: str
    level: Optional[str] = None


# --------------------------------------------------------------------------- text helpers


def _short(text: str, limit: int = 64) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _unquote(text: str) -> str:
    return text.strip().strip('"').strip("'")


def _join(words: List[str]) -> str:
    return words[0] if len(words) == 1 else ", ".join(words[:-1]) + " and " + words[-1]


_PROTOCOL_NAMES = {
    "bgp": "BGP", "ospf": "OSPF", "ospf3": "OSPFv3", "ospfv3": "OSPFv3", "eigrp": "EIGRP", "isis": "IS-IS",
    "rip": "RIP", "ripng": "RIPng", "pim": "PIM", "ldp": "LDP", "msdp": "MSDP",
}
_PROTOCOL = re.compile(r"\b(bgp|ospfv3|ospf3|ospf|eigrp|isis|ripng|rip|pim|ldp|msdp)\b", re.I)


def _inline(label: str) -> str:
    """A section label inside a sentence: ``router bgp 65010`` -> ``BGP 65010``, others unchanged."""
    match = re.match(r"^(?:router\s+)?(bgp|ospfv3|ospf3|ospf|eigrp|isis|ripng|rip|pim|ldp|msdp)\b(.*)$", label, re.I)
    return _PROTOCOL_NAMES[match.group(1).lower()] + match.group(2) if match else label


def _nice(label: str) -> str:
    """A section label at the start of a sentence."""
    label = _inline(label)
    return label[:1].upper() + label[1:]


def _protocol(key: Tuple[str, ...], label: str) -> str:
    match = _PROTOCOL.search(" ".join(key) + " " + label)
    return _PROTOCOL_NAMES[match.group(1).lower()] if match else "Routing"


# --------------------------------------------------------------------------- addresses, ports and matches


@dataclass(frozen=True)
class Member:
    """One element of a rule's source, destination or service: any, an address set, a port range or a name."""

    kind: str  # any | net | port | name
    text: str
    version: int = 4
    base: int = 0
    wild: int = 0  # address bits that may vary, like an ACL wildcard
    proto: str = ""
    low: int = 0
    high: int = 65535

    def covers(self, other: Member) -> bool:
        if self.kind == "any":
            return True
        if other.kind == "any" or other.kind != self.kind:
            return False
        if self.kind == "name":
            return self.text.lower() == other.text.lower()
        if self.kind == "port":
            return self.proto in ("", other.proto) and self.low <= other.low and other.high <= self.high
        return self.version == other.version and other.wild & ~self.wild == 0 and (other.base ^ self.base) & ~self.wild == 0

    @property
    def size(self) -> Optional[int]:
        return 1 << bin(self.wild).count("1") if self.kind == "net" else None


ANY = Member("any", "any")


def _net(text: str) -> Optional[Member]:
    """``10.1.1.0/24``, ``10.1.1.5`` or ``2001:db8::/32`` as an address set (``None`` if it is not an address)."""
    text = _unquote(text)
    if "." not in text and ":" not in text:
        return None
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None
    if network.prefixlen == 0:
        return ANY
    shown = str(network.network_address) if network.prefixlen == network.max_prefixlen else str(network)
    return Member("net", shown, network.version, int(network.network_address), int(network.hostmask))


def _masked(address: str, mask: str, netmask: bool) -> Optional[Member]:
    """``10.1.0.0 0.0.255.255`` (an ACL wildcard) or ``10.1.0.0 255.255.0.0`` (a netmask).

    Contiguous masks say which they are. ``0.0.0.0`` and ``255.255.255.255`` are ambiguous, so ``netmask``
    (ASA, FortiOS) decides those; only wildcards can be non-contiguous.
    """
    try:
        base = int(ipaddress.IPv4Address(address))
        bits = int(ipaddress.IPv4Address(mask))
    except ValueError:
        return None
    full = _FULL[4]
    inverted = full ^ bits
    if bits in (0, full):
        wild = inverted if netmask else bits
    elif inverted & (inverted + 1) == 0:  # 255.255.255.0
        wild = inverted
    elif bits & (bits + 1) == 0:  # 0.0.0.255
        wild = bits
    elif netmask:
        return None
    else:
        wild = bits
    if wild == full:
        return ANY
    base &= full ^ wild
    if wild & (wild + 1) == 0:
        prefix = 32 - wild.bit_length()
        shown = str(ipaddress.IPv4Address(base)) + ("" if prefix == 32 else f"/{prefix}")
    else:
        shown = f"{ipaddress.IPv4Address(base)} {mask}"
    return Member("net", shown, 4, base, wild)


_PORTS = {
    "ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "tacacs": 49, "domain": 53, "dns": 53,
    "bootps": 67, "bootpc": 68, "tftp": 69, "www": 80, "http": 80, "pop3": 110, "sunrpc": 111, "ntp": 123,
    "netbios-ns": 137, "netbios-dgm": 138, "netbios-ss": 139, "imap": 143, "imap4": 143, "snmp": 161,
    "snmptrap": 162, "bgp": 179, "ldap": 389, "https": 443, "microsoft-ds": 445, "isakmp": 500, "syslog": 514,
    "lpd": 515, "ldaps": 636, "sqlnet": 1521, "radius": 1812, "radius-acct": 1813, "rdp": 3389,
}


def _port(token: str) -> Optional[int]:
    if token.isdigit():
        value = int(token)
        return value if value <= 65535 else None
    return _PORTS.get(token.lower())


def _port_member(proto: str, low: int, high: int) -> Member:
    span = str(low) if low == high else f"{low}-{high}"
    return Member("port", f"{proto}/{span}" if proto else f"port {span}", proto=proto, low=low, high=high)


@dataclass
class Match:
    """What a rule matches in one dimension (source, destination, service or application)."""

    members: List[Member]

    @property
    def is_any(self) -> bool:
        return any(m.kind == "any" for m in self.members)

    @property
    def text(self) -> str:
        if self.is_any:
            return "any"
        shown = [m.text for m in self.members]
        more = f" and {len(shown) - 3} more" if len(shown) > 3 else ""
        return _short(", ".join(shown[:3]) + more, 72)

    def covers(self, other: Match) -> bool:
        return all(any(mine.covers(theirs) for mine in self.members) for theirs in other.members)

    def size(self) -> Optional[int]:
        sizes = [m.size for m in self.members]
        if not sizes or any(s is None for s in sizes):
            return None
        return sum(s or 0 for s in sizes)


def _match(members: Iterable[Member]) -> Optional[Match]:
    members = list(members)
    return Match(members) if members else None


def _compare(old: Match, new: Match, sized: bool) -> str:
    """``any``, ``wider``, ``narrower``, ``same`` or ``changed`` (neither contains the other)."""
    if [m.text.lower() for m in old.members] == [m.text.lower() for m in new.members]:
        return "same"
    if new.is_any:
        return "same" if old.is_any else "any"
    if old.is_any:
        return "narrower"
    wider, narrower = new.covers(old), old.covers(new)
    if wider != narrower:
        return "wider" if wider else "narrower"
    if wider:
        return "same"
    if sized:
        before, after = old.size(), new.size()
        if before is not None and after is not None and before != after:
            return "wider" if after > before else "narrower"
    return "changed"


# --------------------------------------------------------------------------- firewall rules

DIMENSIONS = ("source", "destination", "service", "application")


@dataclass
class Rule:
    """A firewall rule or ACL entry reduced to what it lets through. ``None`` dimensions do not apply."""

    label: str
    action: Optional[str] = None  # permit | deny
    enabled: bool = True
    source: Optional[Match] = None
    destination: Optional[Match] = None
    service: Optional[Match] = None
    application: Optional[Match] = None

    def dimensions(self) -> List[Tuple[str, Match]]:
        return [(name, match) for name in DIMENSIONS if (match := getattr(self, name)) is not None]


def _flow(rule: Rule) -> str:
    parts = []
    if rule.source is not None and rule.destination is not None:
        parts.append(f"{rule.source.text} → {rule.destination.text}")
    elif rule.source is not None:
        parts.append(f"from {rule.source.text}")
    parts += [match.text for match in (rule.service, rule.application) if match is not None]
    return _short(", ".join(parts), 90)


def rule_findings(old: Optional[Rule], new: Optional[Rule]) -> List[Finding]:
    """What happened to one rule: added, removed, re-actioned, enabled, widened or narrowed."""
    if old is None and new is not None:
        if not new.enabled:
            return []
        if new.action == "permit":
            wide = [f"any {name}" for name, match in new.dimensions() if match.is_any]
            if wide:
                return [Finding(f"{new.label}: new rule allows {_join(wide)}", "high")]
            return [Finding(f"{new.label}: new permit rule opens access ({_flow(new)})")]
        if new.action == "deny":
            return [Finding(f"{new.label}: new deny rule tightens access ({_flow(new)})")]
        return []
    if new is None and old is not None:
        if not old.enabled:
            return []
        if old.action == "deny":
            return [Finding(f"{old.label}: deny rule removed, so traffic it blocked may now be allowed", "high")]
        if old.action == "permit":
            return [Finding(f"{old.label}: permit rule removed, so traffic it allowed may now be blocked")]
        return []
    if old is None or new is None:
        return []
    label = new.label
    if old.action and new.action and old.action != new.action:
        if new.action == "permit":
            return [Finding(f"{label} now permits traffic it used to deny", "high")]
        return [Finding(f"{label} now denies traffic it used to permit, which tightens access")]
    if old.enabled != new.enabled:
        if new.action == "permit":
            if new.enabled:
                return [Finding(f"{label} enabled again: it allows its traffic again", "high")]
            return [Finding(f"{label} disabled: it no longer allows its traffic")]
        if new.enabled:
            return [Finding(f"{label} enabled again: it blocks its traffic again, which tightens access")]
        return [Finding(f"{label} disabled: traffic it blocked may now be allowed", "high")]
    if not new.enabled or new.action not in ("permit", "deny"):
        return []
    findings: List[Finding] = []
    for name in DIMENSIONS:
        before, after = getattr(old, name), getattr(new, name)
        if before is None or after is None:
            continue
        verdict = _compare(before, after, sized=name in ("source", "destination"))
        if verdict in ("same", "changed"):
            continue
        if new.action == "permit":
            if verdict == "any":
                findings.append(Finding(f"{label} now allows any {name} (was {before.text})", "high"))
            elif verdict == "wider":
                findings.append(Finding(f"{label} now allows a wider {name}: {after.text} (was {before.text})", "high"))
            else:
                findings.append(Finding(f"{label} now allows a narrower {name}: {after.text} (was {before.text})"))
        elif verdict == "narrower":
            findings.append(Finding(
                f"{label} now blocks a narrower {name}: {after.text} (was {before.text}), so more traffic gets through", "high",
            ))
        elif verdict == "any":
            findings.append(Finding(f"{label} now blocks any {name} (was {before.text})"))
        else:
            findings.append(Finding(f"{label} now blocks a wider {name}: {after.text} (was {before.text})"))
    return findings


# IOS-style access lists: IOS / IOS-XE named and numbered, NX-OS, EOS, IOS-XR, ASA

_ACL_HEAD = re.compile(r"^(?:ip|ipv4|ipv6)\s+access-list\s+(?:(extended|standard|role-based)\s+)?(\S+)", re.I)
_ACL_LINE = re.compile(r"^access-list\s+(\S+)", re.I)
_PROTOCOLS = frozenset({
    "ip", "ipv4", "ipv6", "tcp", "udp", "icmp", "icmpv6", "gre", "esp", "ahp", "ah", "eigrp", "ospf", "pim",
    "igmp", "sctp", "nos", "pcp", "ipinip", "vrrp", "l2tp",
})
_ANY_PROTOCOLS = frozenset({"ip", "ipv4", "ipv6"})
_PORTED = frozenset({"tcp", "udp", "sctp"})


def _address(tokens: List[str], i: int, netmask: bool) -> Tuple[Optional[Member], int]:
    if i >= len(tokens):
        return None, i
    token = tokens[i].lower()
    if token in ("any", "any4", "any6"):
        return ANY, i + 1
    if token in ("host", "object-group", "object", "addrgroup", "interface") and i + 1 < len(tokens):
        if token == "host":
            return _net(tokens[i + 1]) or Member("name", tokens[i + 1]), i + 2
        return Member("name", tokens[i + 1]), i + 2
    if _DOTTED.match(tokens[i]) and i + 1 < len(tokens) and _DOTTED.match(tokens[i + 1]):
        masked = _masked(tokens[i], tokens[i + 1], netmask)
        if masked is not None:
            return masked, i + 2
    member = _net(tokens[i])
    return (member, i + 1) if member is not None else (None, i)


def _ports(tokens: List[str], i: int, proto: str) -> Tuple[List[Member], int]:
    if i >= len(tokens):
        return [], i
    op = tokens[i].lower()
    if op == "range" and i + 2 < len(tokens):
        low, high = _port(tokens[i + 1]), _port(tokens[i + 2])
        if low is None or high is None:
            return [Member("name", f"{proto} {tokens[i + 1]}-{tokens[i + 2]}")], i + 3
        return [_port_member(proto, low, high)], i + 3
    if op in ("eq", "neq", "lt", "gt") and i + 1 < len(tokens):
        values: List[int] = []
        j = i + 1
        while j < len(tokens) and (op == "eq" or j == i + 1):
            value = _port(tokens[j])
            if value is None:
                break
            values.append(value)
            j += 1
        if not values:
            return [Member("name", f"{proto} {op} {tokens[i + 1]}")], i + 2
        if op == "eq":
            return [_port_member(proto, value, value) for value in values], j
        value = values[0]
        if op == "gt":
            return [_port_member(proto, min(value + 1, 65535), 65535)], j
        if op == "lt":
            return [_port_member(proto, 0, max(value - 1, 0))], j
        return [_port_member(proto, 0, 65535)], j  # neq: everything but one port
    if op == "object-group" and i + 1 < len(tokens):
        return [Member("name", tokens[i + 1])], i + 2
    return [], i


@dataclass
class _Entry:
    seq: Optional[str]
    text: str
    rule: Rule


def _ace(text: str, netmask: bool, extended: Optional[bool]) -> Optional[_Entry]:
    """Parse one access-list entry (``[seq] permit|deny ...`` or a whole ``access-list NAME ...`` line)."""
    tokens = text.split()
    i, seq = 0, None
    if tokens[:1] == ["access-list"]:
        if len(tokens) < 4:
            return None
        i = 2
        if tokens[i] == "line" and len(tokens) > i + 2:
            i += 2
        if tokens[i] in ("extended", "standard"):
            extended = tokens[i] == "extended"
            i += 1
        elif tokens[1].isdigit():  # IOS numbered lists: 1-99 and 1300-1999 are standard
            number = int(tokens[1])
            extended = not (1 <= number <= 99 or 1300 <= number <= 1999)
        if i < len(tokens) and tokens[i] == "dynamic":
            i += 2
    elif tokens and tokens[0].isdigit():
        seq, i = tokens[0], 1
    if i >= len(tokens) or tokens[i] not in ("permit", "deny"):
        return None
    action = tokens[i]
    i += 1
    if i >= len(tokens):
        return None
    if extended is None:
        extended = tokens[i].lower() in _PROTOCOLS or tokens[i].isdigit() or tokens[i] in ("object-group", "object")
    proto, service = "", None
    if extended:
        if tokens[i] in ("object-group", "object") and i + 1 < len(tokens):
            service = Match([Member("name", tokens[i + 1])])  # a service object in the protocol position
            i += 2
        else:
            proto = tokens[i].lower()
            i += 1
    source, i = _address(tokens, i, netmask)
    if source is None:
        return None
    destination = None
    if extended:
        if proto in _PORTED:
            _, i = _ports(tokens, i, proto)  # source ports
        destination, i = _address(tokens, i, netmask)
        if destination is None:
            return None
        if service is None:
            if proto in _ANY_PROTOCOLS:
                service = Match([ANY])
            elif proto in _PORTED:
                ports, i = _ports(tokens, i, proto)
                service = Match(ports or [Member("port", proto, proto=proto)])
            else:
                service = Match([Member("port", proto, proto=proto)])
    rule = Rule("", action, True, Match([source]), Match([destination]) if destination else None, service)
    return _Entry(seq, text, rule)


def _pair_entries(old: List[_Entry], new: List[_Entry]) -> List[Tuple[Optional[_Entry], Optional[_Entry]]]:
    """Match removed and added entries: by sequence number, then by similarity."""
    old, new = list(old), list(new)
    pairs: List[Tuple[Optional[_Entry], Optional[_Entry]]] = []
    for entry in list(new):
        same = next((o for o in old if entry.seq and o.seq == entry.seq), None)
        if same is not None:
            pairs.append((same, entry))
            old.remove(same)
            new.remove(entry)
    if old and new and len(old) * len(new) <= 2500:
        scored = sorted(
            ((difflib.SequenceMatcher(None, a.text.split(), b.text.split()).ratio(), x, y) for x, a in enumerate(old) for y, b in enumerate(new)),
            key=lambda item: -item[0],
        )
        used_old: set[int] = set()
        used_new: set[int] = set()
        for score, x, y in scored:
            if score < 0.5:
                break
            if x not in used_old and y not in used_new:
                pairs.append((old[x], new[y]))
                used_old.add(x)
                used_new.add(y)
        old = [e for x, e in enumerate(old) if x not in used_old]
        new = [e for y, e in enumerate(new) if y not in used_new]
    return pairs + [(o, None) for o in old] + [(None, n) for n in new]


def _acl_findings(key: Tuple[str, ...], removed: List[Line], added: List[Line], netmask: bool) -> List[Finding]:
    head = key[0] if key else ""
    named = _ACL_HEAD.match(head)
    if named:
        kind = (named.group(1) or "").lower()
        extended = None if kind in ("", "role-based") else kind == "extended"
        label = f"ACL {named.group(2)}"
        old_lines = [rel for path, rel in removed if path]
        new_lines = [rel for path, rel in added if path]
    else:
        numbered = _ACL_LINE.match(head)
        if not numbered:
            return []
        extended, label = None, f"ACL {numbered.group(1)}"
        old_lines = [rel for _, rel in removed]
        new_lines = [rel for _, rel in added]
    old = [e for e in (_ace(text, netmask, extended) for text in old_lines) if e]
    new = [e for e in (_ace(text, netmask, extended) for text in new_lines) if e]
    findings: List[Finding] = []
    for before, after in _pair_entries(old, new):
        entry = after or before
        name = f"{label} entry {entry.seq}" if entry and entry.seq else label
        for side in (before, after):
            if side is not None:
                side.rule.label = name
        findings += rule_findings(before.rule if before else None, after.rule if after else None)
    return findings


# FortiOS policies

_FORTI_POLICY = ("config firewall policy", "config firewall policy6", "config firewall security-policy")
_FORTI_SERVICES = {
    "all": ANY,
    "all_tcp": Member("port", "ALL_TCP", proto="tcp"),
    "all_udp": Member("port", "ALL_UDP", proto="udp"),
    "all_icmp": Member("port", "ALL_ICMP", proto="icmp"),
}


def _forti_settings(lines: List[Line], depth: int) -> Dict[str, List[str]]:
    values: Dict[str, List[str]] = {}
    for path, rel in lines:
        if len(path) != depth:
            continue
        tokens = _TOKEN.findall(rel)
        if len(tokens) >= 2 and tokens[0] == "set":
            values[tokens[1]] = [_unquote(t) for t in tokens[2:]]
        elif len(tokens) >= 2 and tokens[0] == "unset":
            values.pop(tokens[1], None)
    return values


def _forti_addresses(names: List[str]) -> Optional[Match]:
    return _match(ANY if name.lower() in ("all", "any") else _net(name) or Member("name", name) for name in names)


def _forti_rule(lines: List[Line], key: Tuple[str, ...]) -> Optional[Rule]:
    if not lines:
        return None
    values = _forti_settings(lines, len(key))
    action = (values.get("action") or ["deny"])[0].lower()  # FortiOS policies deny unless told otherwise
    return Rule(
        f"Policy {_unquote(key[1][5:])}",
        "permit" if action in ("accept", "ipsec") else "deny",
        (values.get("status") or ["enable"])[0].lower() != "disable",
        _forti_addresses(values.get("srcaddr", []) + values.get("srcaddr4", []) + values.get("srcaddr6", [])),
        _forti_addresses(values.get("dstaddr", []) + values.get("dstaddr4", []) + values.get("dstaddr6", [])),
        _match(_FORTI_SERVICES.get(name.lower()) or Member("name", name) for name in values.get("service", [])),
    )


# PAN-OS security rules (set format)

_PANOS_ACTIONS = {"allow": "permit", "deny": "deny", "drop": "deny", "reset-client": "deny", "reset-server": "deny", "reset-both": "deny"}


def _set_values(lines: List[Line]) -> Dict[str, List[str]]:
    values: Dict[str, List[str]] = {}
    for _, rel in lines:
        tokens = [t for t in _TOKEN.findall(rel) if t not in ("[", "]")]
        if len(tokens) >= 2:
            values.setdefault(tokens[0], []).extend(_unquote(t) for t in tokens[1:])
    return values


def _panos_members(names: List[str]) -> Optional[Match]:
    members: List[Member] = []
    for name in names:
        if name.lower() == "any":
            members.append(ANY)
            continue
        if re.match(r"^[\d.]+-[\d.]+$", name):
            start, end = name.split("-")
            try:
                networks = list(ipaddress.summarize_address_range(ipaddress.IPv4Address(start), ipaddress.IPv4Address(end)))
            except ValueError:
                networks = []
            parts = [_net(str(n)) for n in networks]
            if parts and all(parts):
                members += [p for p in parts if p]
                continue
        members.append(_net(name) or Member("name", name))
    return _match(members)


def _panos_rule(lines: List[Line], key: Tuple[str, ...]) -> Optional[Rule]:
    if not lines:
        return None
    values = _set_values(lines)
    parts = key[0].split(None, 3)
    return Rule(
        f"Security rule {_unquote(parts[3]) if len(parts) > 3 else key[0]}",
        _PANOS_ACTIONS.get((values.get("action") or [""])[0].lower()),
        (values.get("disabled") or ["no"])[0].lower() != "yes",
        _panos_members(values.get("source", [])),
        _panos_members(values.get("destination", [])),
        _panos_members(values.get("service", [])),
        _panos_members(values.get("application", [])),
    )


# Junos firewall filter terms and SRX security policies


def _junos_rule_index(parts: Tuple[str, ...]) -> Optional[int]:
    for index, part in enumerate(parts):
        words = part.split()
        if not words:
            continue
        if words[0] == "term" and any(p.startswith("filter ") for p in parts[:index]):
            return index
        if words[0] == "policy" and len(words) == 2 and any(p.startswith("from-zone ") or p in ("global", "policies") for p in parts[:index]):
            return index
    return None


def _junos_label(parts: Tuple[str, ...], index: int) -> str:
    kind, name = parts[index].split(" ", 1)
    if kind == "term":
        name_of_filter = next((p.split(" ", 1)[1] for p in parts[:index] if p.startswith("filter ")), "")
        return f"Filter {name_of_filter} term {name}"
    zones = next((re.match(r"from-zone (\S+) to-zone (\S+)", p) for p in parts[:index] if p.startswith("from-zone ")), None)
    return f"Policy {name} ({zones.group(1)} to {zones.group(2)})" if zones else f"Policy {name}"


def _junos_members(names: List[str]) -> Optional[Match]:
    return _match(ANY if name.lower() in ("any", "any-ipv4", "any-ipv6") else _net(name) or Member("name", name) for name in names)


def _junos_service(protocols: List[str], ports: List[str]) -> Match:
    if not protocols and not ports:
        return Match([ANY])
    members: List[Member] = []
    for proto in protocols or [""]:
        if not ports:
            members.append(Member("port", proto, proto=proto))
        for port in ports:
            low, _, high = port.partition("-")
            first, last = _port(low), _port(high) if high else _port(low)
            if first is None or last is None:
                members.append(Member("name", f"{proto}/{port}" if proto else port))
            else:
                members.append(_port_member(proto, first, last))
    return Match(members)


def _junos_rules(lines: List[Line]) -> Dict[Tuple[str, ...], Rule]:
    raw: Dict[Tuple[str, ...], Dict[str, List[str]]] = {}
    labels: Dict[Tuple[str, ...], str] = {}
    for path, rel in lines:
        parts = (*path, rel)
        index = _junos_rule_index(parts)
        if index is None:
            continue
        rid = parts[: index + 1]
        values = raw.setdefault(rid, {})
        labels.setdefault(rid, _junos_label(parts, index))
        sub = parts[index + 1:]
        if not sub:
            continue
        if len(sub) == 1 and sub[0].startswith("then "):
            values.setdefault("then", []).extend(sub[0].split()[1:])
        elif sub[0] == "then" and len(sub) == 2:
            values.setdefault("then", []).append(sub[1].split()[0] if sub[1].split() else "")
        elif sub[0] in ("from", "match") and len(sub) == 2:
            tokens = [t for t in _TOKEN.findall(sub[1]) if t not in ("[", "]")]
            if len(tokens) >= 2:
                values.setdefault(tokens[0], []).extend(_unquote(t) for t in tokens[1:])
        elif sub[0] in ("from", "match") and len(sub) == 3:
            tokens = sub[2].split()
            if tokens and "except" not in tokens[1:]:
                values.setdefault(sub[1].split()[0], []).append(tokens[0])
    rules: Dict[Tuple[str, ...], Rule] = {}
    for rid, values in raw.items():
        then = set(values.get("then", []))
        action = "permit" if then & {"accept", "permit"} else "deny" if then & {"discard", "reject", "deny"} else None
        if rid[-1].startswith("policy "):
            rules[rid] = Rule(
                labels[rid], action, True,
                _junos_members(values.get("source-address", [])), _junos_members(values.get("destination-address", [])),
                None, _junos_members(values.get("application", [])),
            )
            continue
        # a filter term matches anything it does not mention
        sources = values.get("source-address", []) + values.get("address", []) + values.get("source-prefix-list", []) + values.get("prefix-list", [])
        targets = values.get("destination-address", []) + values.get("address", []) + values.get("destination-prefix-list", []) + values.get("prefix-list", [])
        rules[rid] = Rule(
            labels[rid], action, True,
            _junos_members(sources) or Match([ANY]), _junos_members(targets) or Match([ANY]),
            _junos_service(values.get("protocol", []), values.get("destination-port", []) + values.get("port", [])),
        )
    return rules


def _junos_findings(removed: List[Line], added: List[Line], before: List[Line], after: List[Line]) -> List[Finding]:
    touched: List[Tuple[str, ...]] = []
    for path, rel in (*removed, *added):
        parts = (*path, rel)
        index = _junos_rule_index(parts)
        if index is not None and parts[: index + 1] not in touched:
            touched.append(parts[: index + 1])
    if not touched:
        return []
    old, new = _junos_rules(before), _junos_rules(after)
    findings: List[Finding] = []
    for rid in touched:
        findings += rule_findings(old.get(rid), new.get(rid))
    return findings


_ACCESS_GROUP = re.compile(
    r"^(?:ip|ipv6)\s+(?:access-group|traffic-filter)\s+(?P<acl>\S+)\s+(?P<dir>in|out)\b"
    r"|^access-group\s+(?P<asa>\S+)\s+(?P<asadir>in|out)\s+interface\s+(?P<iface>\S+)",
    re.I,
)


def _access_group_findings(key: Tuple[str, ...], label: str, removed: List[Line], added: List[Line], before: List[Line], after: List[Line]) -> List[Finding]:
    """An access list attached to, or detached from, an interface."""
    def groups(entries: List[Line]) -> Dict[Tuple[str, str, str], str]:
        found: Dict[Tuple[str, str, str], str] = {}
        for _, rel in entries:
            match = _ACCESS_GROUP.match(rel)
            if match and match.group("acl"):
                found[(match.group("acl"), match.group("dir").lower(), _inline(label))] = rel
            elif match:
                found[(match.group("asa"), match.group("asadir").lower(), f"interface {match.group('iface')}")] = rel
        return found

    old, new = groups(before), groups(after)
    findings = [
        Finding(f"ACL {acl} removed from {where}: {direction}bound traffic there is no longer filtered", "high")
        for acl, direction, where in groups(removed) if (acl, direction, where) not in new
    ]
    findings += [
        Finding(f"ACL {acl} now filters {direction}bound traffic on {where}")
        for acl, direction, where in groups(added) if (acl, direction, where) not in old
    ]
    return findings


def _firewall_findings(syntax: str, key: Tuple[str, ...], label: str, removed: List[Line], added: List[Line], before: List[Line], after: List[Line], netmask: bool) -> List[Finding]:
    if syntax == "fortios" and len(key) > 1 and key[0] in _FORTI_POLICY and key[1].startswith("edit "):
        return rule_findings(_forti_rule(before, key), _forti_rule(after, key))
    if syntax == "set" and key and key[0].startswith("rulebase security rules "):
        return rule_findings(_panos_rule(before, key), _panos_rule(after, key))
    if syntax == "braces":
        return _junos_findings(removed, added, before, after)
    if syntax == "indent":
        return _acl_findings(key, removed, added, netmask) + _access_group_findings(key, label, removed, added, before, after)
    return []


# address objects that rules refer to


def _object_findings(syntax: str, key: Tuple[str, ...], before: List[Line], after: List[Line]) -> List[Finding]:
    def value(lines: List[Line]) -> Optional[Match]:
        if syntax == "fortios":
            settings = _forti_settings(lines, len(key))
            subnet = settings.get("subnet") or []
            if len(subnet) == 2:
                return _match(m for m in [_masked(subnet[0], subnet[1], netmask=True)] if m)
            return _match(m for m in [_net(" ".join(settings.get("ip6") or []))] if m)
        if syntax == "set":
            values = _set_values(lines)
            return _panos_members(values.get("ip-netmask", []) + values.get("ip-range", []))
        members = []
        for _, rel in lines:
            tokens = rel.split()
            if len(tokens) == 3 and tokens[0] == "subnet":
                members.append(_masked(tokens[1], tokens[2], netmask=True) or _net(f"{tokens[1]}/{tokens[2]}"))
            elif len(tokens) == 2 and tokens[0] in ("host", "subnet"):
                members.append(_net(tokens[1]))
        return _match(m for m in members if m)

    if syntax == "fortios" and len(key) > 1 and key[0] in ("config firewall address", "config firewall address6") and key[1].startswith("edit "):
        name = _unquote(key[1][5:])
    elif syntax == "set" and key and re.match(r"^address\s+\S+$", key[0]):
        name = _unquote(key[0].split(None, 1)[1])
    elif syntax == "indent" and key and re.match(r"^object network\s+\S+$", key[0]):
        name = key[0].split()[2]
    else:
        return []
    old, new = value(before), value(after)
    if old is None or new is None:
        return []
    verdict = _compare(old, new, sized=True)
    if verdict in ("any", "wider"):
        return [Finding(f"Address object {name} now covers {new.text} (was {old.text}), so every rule that uses it allows more", "high")]
    if verdict == "narrower":
        return [Finding(f"Address object {name} now covers less: {new.text} (was {old.text})")]
    return []


# --------------------------------------------------------------------------- interfaces


_DOWN = re.compile(r"^(?:shutdown|disable|set\s+status\s+down|link-state\s+down|admin-state\s+down)$", re.I)


def _shutdown_findings(syntax: str, key: Tuple[str, ...], label: str, category: str, removed: List[Line], added: List[Line], before: List[Line], after: List[Line]) -> List[Finding]:
    previous = {rel for _, rel in before}
    current = {rel for _, rel in after}
    interface = category == "interfaces" or label.lower().startswith("interface")
    for _, rel in added:
        down = _DOWN.match(rel) or (syntax == "routeros" and key and key[0].startswith("/interface") and re.search(r"\bdisabled=yes\b", rel))
        if down and rel not in previous:
            if interface:
                return [Finding(f"{_nice(label)} shut down: traffic through it stops", "high")]
            return [Finding(f"{_nice(label)} disabled", "high")]
    for _, rel in removed:
        if _DOWN.match(rel) and rel not in current and before and after:
            return [Finding(f"{_nice(label)} brought back up" if interface else f"{_nice(label)} enabled again")]
    return []


# --------------------------------------------------------------------------- routing


_NEIGHBOR = re.compile(r"(?:^|\s)(?:neighbou?r|peer)\s+(\"[^\"]+\"|[^\s;{]+)", re.I)
_REMOTE_AS = re.compile(r"\b(?:remote-as|peer-as|as-number)\s+(\d+)", re.I)
_ROUTING_PROCESS = re.compile(r"^(?:router\s+)?(?:bgp|ospfv3|ospf3|ospf|eigrp|isis|ripng|rip)\b", re.I)


def _neighbors(lines: List[Line]) -> Dict[str, str]:
    found: Dict[str, str] = {}
    for path, rel in lines:
        for part in (*path, rel):
            for match in _NEIGHBOR.finditer(part):
                peer = _unquote(match.group(1))
                if peer.lower() not in ("shutdown", "default"):
                    found.setdefault(peer, "")
                    remote = _REMOTE_AS.search(part[match.end():] if part == rel else "")
                    if remote:
                        found[peer] = remote.group(1)
    return found


def _neighbor_findings(syntax: str, key: Tuple[str, ...], label: str, action: str, removed: List[Line], added: List[Line], before: List[Line], after: List[Line]) -> List[Finding]:
    proto = _protocol(key, label)
    if syntax == "fortios" and "config neighbor" in key and key[-1].startswith("edit "):
        peer = _unquote(key[-1][5:])
        if action == "removed":
            return [Finding(f"{proto} neighbor {peer} removed: routes learned from it are withdrawn", "high")]
        return [Finding(f"New {proto} neighbor {peer}")] if action == "added" else []
    if syntax == "routeros" and key and key[0] in ("/routing bgp connection", "/routing bgp peer"):
        name = re.search(r'\bname=("[^"]*"|\S+)', key[-1])
        peer = _unquote(name.group(1)) if name else _short(key[-1], 40)
        if action == "removed":
            return [Finding(f"BGP peer {peer} removed: routes learned from it are withdrawn", "high")]
        return [Finding(f"New BGP peer {peer}")] if action == "added" else []
    old, new = _neighbors(before), _neighbors(after)
    gone = [peer for peer in _neighbors(removed) if peer not in new]
    fresh = [peer for peer in _neighbors(added) if peer not in old]
    findings = [Finding(f"{proto} neighbor {peer} removed: routes learned from it are withdrawn", "high") for peer in gone[:3]]
    if len(gone) > 3:
        findings.append(Finding(f"{len(gone) - 3} more {proto} neighbors removed", "high"))
    if action == "removed" and not gone and _ROUTING_PROCESS.match(label):
        findings.append(Finding(f"{_nice(label)} removed: the routes it provided are withdrawn", "high"))
    for _, rel in added:
        shut = re.match(r"^neighbou?r\s+(\S+)\s+shutdown\b", rel, re.I)
        if shut and rel not in {r for _, r in before}:
            findings.append(Finding(f"{proto} neighbor {shut.group(1)} shut down: routes learned from it are withdrawn", "high"))
    findings += [Finding(f"New {proto} neighbor {peer}" + (f" (AS {new[peer]})" if new.get(peer) else "")) for peer in fresh[:3]]
    return findings


_REDISTRIBUTE = re.compile(r"^(?:no\s+)?(?:redistribute|import-route)\b", re.I)


def _redistribution_lines(syntax: str, key: Tuple[str, ...], entries: List[Line]) -> List[str]:
    found = []
    for path, rel in entries:
        if _REDISTRIBUTE.match(rel) or (syntax == "braces" and rel.startswith("export ") and "protocols" in (*key, *path)):
            found.append(rel)
        elif syntax == "fortios" and rel.startswith("set status ") and any(p.startswith("config redistribute") for p in path):
            block = next(p for p in path if p.startswith("config redistribute"))
            found.append(f"{_unquote(block[len('config redistribute'):])} routes {rel.split()[-1]}")
        elif syntax == "routeros":
            match = re.search(r"\bredistribute=\S+", rel)
            if match:
                found.append(match.group(0))
    return found


def _redistribution_findings(syntax: str, key: Tuple[str, ...], label: str, removed: List[Line], added: List[Line]) -> List[Finding]:
    old, new = _redistribution_lines(syntax, key, removed), _redistribution_lines(syntax, key, added)
    where = _inline(label)
    if old and new:
        return [Finding(f"Redistribution changed in {where}: {_short(old[0], 40)} → {_short(new[0], 40)}", "high")]
    if new:
        return [Finding(f"Redistribution added in {where}: {_short(new[0], 50)}, so more routes are advertised", "high")]
    if old:
        return [Finding(f"Redistribution removed in {where}: {_short(old[0], 50)}, so those routes stop being advertised", "high")]
    return []


_ROUTES = (
    re.compile(r"^ip(?:v6)?\s+route\s+(?:vrf\s+\S+\s+)?(?P<dest>[0-9a-fA-F:.]+(?:/\d+)?)(?:\s+(?P<mask>\d+\.\d+\.\d+\.\d+))?", re.I),
    re.compile(r"^route\s+(?P<dest>[0-9a-fA-F:.]+/\d+)", re.I),
    re.compile(r"^route\s+\S+\s+(?P<dest>\d+\.\d+\.\d+\.\d+)\s+(?P<mask>\d+\.\d+\.\d+\.\d+)", re.I),
    re.compile(r"(?:^|\s)dst-address=(?P<dest>[0-9a-fA-F:.]+/\d+)", re.I),
)


def _route(text: str) -> Optional[str]:
    for pattern in _ROUTES:
        match = pattern.search(text)
        if match:
            mask = match.groupdict().get("mask")
            dest = match.group("dest")
            member = _masked(dest, mask, netmask=True) if mask else _net(dest)
            if member is None:
                return None
            return ("::/0" if ":" in dest else "0.0.0.0/0") if member.kind == "any" else member.text
    return None


def _static_route_findings(syntax: str, key: Tuple[str, ...], action: str, removed: List[Line], added: List[Line], before: List[Line], after: List[Line]) -> List[Finding]:
    if syntax == "fortios" and len(key) > 1 and key[0] == "config router static":
        relevant = ("dst", "gateway", "device", "distance", "priority", "status", "blackhole")

        def route(lines: List[Line]) -> Tuple[str, Tuple[List[str], ...]]:
            settings = _forti_settings(lines, len(key))
            value = settings.get("dst") or ["0.0.0.0", "0.0.0.0"]  # FortiOS: no dst means the default route
            member = _masked(value[0], value[1], netmask=True) if len(value) == 2 else None
            dest = "0.0.0.0/0" if member is None or member.kind == "any" else member.text
            return dest, tuple(settings.get(name) or [] for name in relevant)

        if before and after and route(before)[1] == route(after)[1]:
            return []
        old = {route(before)[0]} if before else set()
        new = {route(after)[0]} if after else set()
    else:
        old = {r for r in (_route(rel) for _, rel in removed) if r}
        new = {r for r in (_route(rel) for _, rel in added) if r}
    default = {"0.0.0.0/0", "::/0"}
    findings: List[Finding] = []
    for dest in sorted(old - new):
        if dest in default:
            findings.append(Finding("Default route removed: traffic with no more specific route has nowhere to go", "high"))
        else:
            findings.append(Finding(f"Static route {dest} removed: traffic to it may lose its path"))
    for dest in sorted(old & new):
        if dest in default:
            findings.append(Finding("Default route changed: traffic with no more specific route takes a new path", "high"))
        else:
            findings.append(Finding(f"Static route {dest} changed: traffic to it takes a new path"))
    for dest in sorted(new - old):
        findings.append(Finding("Default route added" if dest in default else f"Static route {dest} added"))
    return findings[:4]


# --------------------------------------------------------------------------- accounts, AAA and management access


_USER = re.compile(r'^(?:username|user|local-user)\s+("[^"]+"|[^\s;]+)', re.I)
_RIGHTS = re.compile(
    r'\bprivilege(?:\s+level)?\s+(\d+)|\brole\s+("[^"]+"|\S+)|\bclass\s+(\S+)|\blevel\s+(\S+)'
    r'|\baccprofile\s+("[^"]+"|\S+)|\bgroup[ =]("[^"]+"|\S+)|\b(superuser)\s+yes',
    re.I,
)
_RIGHT_NAMES = ("privilege", "role", "class", "level", "profile", "group", "")
_ADMIN = re.compile(
    r"^(?:privilege 15|role (?:network-admin|vdc-admin|priv-15|admin|system-admin)|class super-user|level admin"
    r"|profile (?:super_admin|prof_admin)|group (?:full|administrators)|superuser)$",
    re.I,
)


def _rights(text: str) -> str:
    match = _RIGHTS.search(text)
    if not match:
        return ""
    for index, value in enumerate(match.groups()):
        if value:
            return "superuser" if index == 6 else f"{_RIGHT_NAMES[index]} {_unquote(value)}"
    return ""


def _accounts(syntax: str, key: Tuple[str, ...], lines: List[Line]) -> Dict[str, str]:
    """Local accounts in these lines, with their privilege / role / class ("" when not stated)."""
    accounts: Dict[str, str] = {}
    if not lines or not key:
        return accounts
    if syntax == "fortios":
        if key[0] == "config system admin" and len(key) > 1 and key[1].startswith("edit "):
            profile = _forti_settings(lines, len(key)).get("accprofile")
            accounts[_unquote(key[1][5:])] = f"profile {profile[0]}" if profile else ""
        return accounts
    if syntax == "set":
        user = re.match(r'^mgt-config\s+users\s+("[^"]+"|\S+)$', key[0])
        if user:
            text = " ".join(rel for _, rel in lines)
            accounts[_unquote(user.group(1))] = "superuser" if re.search(r"\bsuperuser\s+yes\b", text) else _rights(text)
        return accounts
    if syntax == "routeros":
        if key[0] == "/user":
            for _, rel in lines:
                name = re.search(r'\bname=("[^"]*"|\S+)', rel)
                group = re.search(r'\bgroup=("[^"]*"|\S+)', rel)
                if name:
                    accounts[_unquote(name.group(1))] = f"group {_unquote(group.group(1))}" if group else ""
        return accounts
    for path, rel in lines:
        if syntax == "braces":
            if "login" not in path:
                continue
            user = next((p.split(" ", 1)[1] for p in (*path, rel) if p.startswith("user ") and len(p.split()) == 2), None)
            if user:
                accounts.setdefault(user, "")
                rights = _rights(rel)
                if rights:
                    accounts[user] = rights
            continue
        match = _USER.match(rel)
        if match:
            name = _unquote(match.group(1))
            accounts.setdefault(name, "")
            rights = _rights(rel[match.end():])
            if rights:
                accounts[name] = rights
    return accounts


def _account_findings(syntax: str, key: Tuple[str, ...], removed: List[Line], added: List[Line], before: List[Line], after: List[Line]) -> List[Finding]:
    touched = list(dict.fromkeys([*_accounts(syntax, key, removed), *_accounts(syntax, key, added)]))
    if not touched:
        return []
    old, new = _accounts(syntax, key, before), _accounts(syntax, key, after)
    findings: List[Finding] = []
    for name in touched[:4]:
        if name in new and name not in old:
            admin = bool(_ADMIN.match(new[name]))
            text = f"New {'admin ' if admin else ''}account '{name}'" + (f" ({new[name]})" if new[name] else "")
            findings.append(Finding(text, "high" if admin else None))
        elif name in old and name not in new:
            findings.append(Finding(f"Account '{name}' removed"))
        elif old.get(name) != new.get(name):
            gained = bool(_ADMIN.match(new.get(name) or "")) and not _ADMIN.match(old.get(name) or "")
            findings.append(Finding(
                f"Account '{name}' rights changed: {old.get(name) or 'default'} → {new.get(name) or 'default'}", "high" if gained else None,
            ))
        else:
            findings.append(Finding(f"Password or settings changed for account '{name}'"))
    return findings


_AAA = re.compile(r"^aaa\s+(authentication|authorization|accounting)\b", re.I)
_AAA_SERVER = re.compile(r"^(tacacs-server|tacacs|radius-server|radius|tacplus-server)\s+(?:server\s+|host\s+)?(\S+)", re.I)


def _aaa_findings(syntax: str, key: Tuple[str, ...], label: str, action: str, removed: List[Line], added: List[Line]) -> List[Finding]:
    findings: List[Finding] = []
    kinds: Dict[str, List[List[str]]] = {}
    for index, entries in enumerate((removed, added)):
        for _, rel in entries:
            match = _AAA.match(rel)
            if match:
                kinds.setdefault(match.group(1).lower(), [[], []])[index].append(rel)
            elif syntax == "braces" and rel.startswith("authentication-order"):
                kinds.setdefault("login order", [[], []])[index].append(rel)
    for kind, (old, new) in kinds.items():
        verb = "changed" if old and new else "added" if new else "removed"
        findings.append(Finding(f"AAA {kind} {verb}: {_short((new or old)[0], 60)}"))
    head = next((part for part in key if _AAA_SERVER.match(part)), key[0] if key else "")
    server = _AAA_SERVER.match(head)
    if syntax == "fortios" and head in ("config user tacacs+", "config user radius") and len(key) > 1:
        server_kind, name = ("TACACS+" if "tacacs" in head else "RADIUS"), _unquote(key[1][5:])
    elif server and not _AAA.match(head):
        server_kind, name = ("TACACS+" if "tac" in server.group(1).lower() else "RADIUS"), _unquote(server.group(2))
    else:
        return findings
    if action == "added":
        findings.append(Finding(f"{server_kind} server {name} added: logins are checked against it"))
    elif action == "removed":
        findings.append(Finding(f"{server_kind} server {name} removed: logins are no longer checked against it"))
    else:
        findings.append(Finding(f"{server_kind} server {name} changed"))
    return findings


def _management_findings(syntax: str, key: Tuple[str, ...], label: str, before: List[Line], after: List[Line]) -> List[Finding]:
    findings: List[Finding] = []
    head = key[0] if key else ""
    if syntax == "fortios" and head == "config system interface" and len(key) > 1:
        old = set(_forti_settings(before, len(key)).get("allowaccess") or [])
        new = set(_forti_settings(after, len(key)).get("allowaccess") or [])
        if before and new - old:
            insecure = (new - old) & {"telnet", "http"}
            findings.append(Finding(
                f"{_nice(label)} now accepts {_join(sorted(new - old))} management access" + (" (unencrypted)" if insecure else ""),
                "high" if insecure else None,
            ))
        if after and old - new:
            findings.append(Finding(f"{_nice(label)} no longer accepts {_join(sorted(old - new))} management access"))
    elif syntax == "fortios" and head == "config system admin" and len(key) > 1 and before and after:
        def hosts(lines: List[Line]) -> Match:
            settings = _forti_settings(lines, len(key))
            members = [_masked(v[0], v[1], netmask=True) for k, v in settings.items() if k.startswith("trusthost") and len(v) == 2]
            return _match(m for m in members if m) or Match([ANY])  # no trusted hosts: logins from anywhere

        old_hosts, new_hosts = hosts(before), hosts(after)
        verdict = _compare(old_hosts, new_hosts, sized=True)
        name = _unquote(key[1][5:])
        if verdict == "any":
            findings.append(Finding(f"Admin '{name}' can now log in from anywhere (was {old_hosts.text})", "high"))
        elif verdict == "wider":
            findings.append(Finding(f"Admin '{name}' can now log in from {new_hosts.text} (was {old_hosts.text})", "high"))
    elif syntax == "indent" and re.match(r"^line\s+(?:vty|tty)\b", head) and before and after:
        def transports(lines: List[Line]) -> set[str]:
            found: set[str] = set()
            for _, rel in lines:
                if rel.startswith("transport input "):
                    found.update(rel.split()[2:])
            return found

        def access_class(lines: List[Line]) -> bool:
            return any(re.match(r"^(?:ipv6\s+)?access-class\s+\S+\s+in\b", rel) for _, rel in lines)

        added_transports = transports(after) - transports(before)
        if added_transports & {"telnet", "all"}:
            findings.append(Finding(f"{_nice(head)} now accepts telnet logins (unencrypted)", "high"))
        if access_class(before) and not access_class(after):
            findings.append(Finding(f"{_nice(head)} lost its access-class: logins are allowed from any address", "high"))
    return findings


# --------------------------------------------------------------------------- NAT


_NAT_LINE = re.compile(
    r"\bnat\b|\bsnat\b|\bdnat\b|masquerade|srcnat|dstnat|\bvip\b|ippool|central-snat|static-nat|source-translation"
    r"|destination-translation",
    re.I,
)
_STATIC_NAT = re.compile(
    r"\b(?:static|static-nat|vip|dst-?nat|dstnat|destination-translation|destination|port-?forward|to-addresses)\b",
    re.I,
)


def _nat_findings(syntax: str, key: Tuple[str, ...], label: str, action: str, category: str, removed: List[Line], added: List[Line], before: List[Line], after: List[Line]) -> List[Finding]:
    if category != "nat":
        findings = []
        for verb, entries in (("on", added), ("off", removed)):
            line = next((rel for _, rel in entries if _NAT_LINE.search(rel)), None)
            if line:
                findings.append(Finding(f"NAT turned {verb} in {_inline(label)}: {_short(line, 50)}"))
        return findings
    lines = after or before
    detail = _short(label, 70)
    if syntax == "fortios" and key and key[0] == "config firewall vip" and len(key) > 1:
        settings = _forti_settings(lines, len(key))
        ext, mapped = settings.get("extip"), settings.get("mappedip")
        if ext and mapped:
            detail = f"{_unquote(key[1][5:])} maps {ext[0]} to {mapped[0]}"
    static = bool(_STATIC_NAT.search(" ".join((*key, *(rel for _, rel in lines)))))
    kind = "Static NAT" if static else "Source NAT"
    if action == "added":
        return [Finding(f"{kind} added: {detail}" + (", which exposes an inside host" if static else ""), "high" if static else None)]
    if action == "removed":
        return [Finding(f"{kind} removed: {detail}, so traffic that depends on it stops working")]
    return [Finding(f"{kind} changed: {detail}")]


# --------------------------------------------------------------------------- entry point


def explain(
    syntax: str,
    key: Tuple[str, ...],
    label: str,
    action: str,
    category: str,
    categories: List[str],
    removed: List[Line],
    added: List[Line],
    before: List[Line],
    after: List[Line],
    platform: Optional[str] = None,
) -> List[Finding]:
    """Reasons for one changed section, most severe first.

    ``removed`` / ``added`` are the changed lines; ``before`` / ``after`` are the whole section on each side
    (empty when the section was added or removed).
    """
    touched = {category, *categories}
    netmask = platform == "asa" or any(re.match(r"^access-list\s+\S+\s+(?:line\s+\d+\s+)?extended\s", rel) for _, rel in (*removed, *added))
    findings: List[Finding] = []
    if "firewall" in touched:
        findings += _firewall_findings(syntax, key, label, removed, added, before, after, netmask)
    if "objects" in touched:
        findings += _object_findings(syntax, key, before, after)
    findings += _shutdown_findings(syntax, key, label, category, removed, added, before, after)
    if "routing" in touched:
        findings += _neighbor_findings(syntax, key, label, action, removed, added, before, after)
        findings += _redistribution_findings(syntax, key, label, removed, added)
        findings += _static_route_findings(syntax, key, action, removed, added, before, after)
    if "access" in touched:
        findings += _account_findings(syntax, key, removed, added, before, after)
        findings += _aaa_findings(syntax, key, label, action, removed, added)
        findings += _management_findings(syntax, key, label, before, after)
    if "nat" in touched:
        findings += _nat_findings(syntax, key, label, action, category, removed, added, before, after)
    unique: Dict[str, Finding] = {}
    for finding in findings:
        known = unique.get(finding.text)
        if known is None or _ORDER.get(finding.level or "", -1) > _ORDER.get(known.level or "", -1):
            unique[finding.text] = finding
    return sorted(unique.values(), key=lambda f: -_ORDER.get(f.level or "", -1))
