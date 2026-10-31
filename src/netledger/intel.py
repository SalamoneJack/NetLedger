"""Change intelligence: what a configuration change touched, how risky it is, in plain language.

Every changed line is placed in its configuration section, whatever the vendor syntax:
indentation (IOS, NX-OS, EOS, IOS-XR, ASA, AOS-CX, ProCurve, Huawei, ...), ``config``/``edit``
blocks (FortiOS), curly braces (Junos, VyOS), ``set`` commands (PAN-OS, Gaia) and RouterOS
exports. Sections are classified (routing, firewall, access, VPN, ...), scored, and described the
way an engineer would summarise them: "Added VLAN 40 (GUEST-WIFI)", "router bgp 65010: added
neighbor 10.255.1.5".
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from typing import Any, Optional

RISK_LEVELS = ("low", "medium", "high")
RISK_ORDER = {level: index for index, level in enumerate(RISK_LEVELS)}
RISK_WEIGHT = {"low": 6, "medium": 15, "high": 34}

CATEGORIES: dict[str, tuple[str, str]] = {
    "access": ("Access & AAA", "high"),
    "firewall": ("Firewall & ACLs", "high"),
    "nat": ("NAT", "high"),
    "routing": ("Routing", "high"),
    "vpn": ("VPN", "high"),
    "objects": ("Firewall objects", "medium"),
    "qos": ("QoS", "medium"),
    "interfaces": ("Interfaces", "medium"),
    "switching": ("VLANs & switching", "medium"),
    "system": ("System", "medium"),
    "services": ("Management services", "low"),
    "docs": ("Descriptions", "low"),
    "other": ("Other", "low"),
}

PLATFORM_SYNTAX = {"fortios": "fortios", "junos": "braces", "vyos": "braces", "edgeos": "braces", "panos": "set", "gaia": "set", "routeros": "routeros"}


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.I)


# Order matters: the first matching rule wins.
_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("access", _rx(
        r"\b(?:aaa|tacacs\+?|tacacs-server|radius(?:-server)?|username|users?|local-user|user-group|password|passwd|secret"
        r"|enable\s+(?:secret|password)|line\s+(?:vty|con|console|aux)|login|ssh|telnet|authentication|authorization"
        r"|accounting|admin|accprofile|mgt-config|community|privilege|role-based|pki|certificate|crypto\s+key|key\s+chain"
        r"|keychain|root-authentication|allowaccess|trusthost\d*)\b"
    )),
    ("vpn", _rx(
        r"\b(?:crypto|ipsec|isakmp|ike(?:v[12])?|vpn|tunnel-group|group-policy|phase[12](?:-interface)?|wireguard|dmvpn"
        r"|ssl-?vpn|l2tp|openvpn|psksecret|pre-shared-key)\b"
    )),
    ("nat", _rx(r"\b(?:nat|snat|dnat|masquerade|srcnat|dstnat|source-translation|destination-translation|vip|ippool|central-snat-map)\b")),
    ("routing", _rx(
        r"\b(?:router\s+(?:bgp|ospf|ospfv3|eigrp|isis|rip|static|pim)|ipv6\s+route|ip\s+route|route-map|prefix-list|prefix-set"
        r"|as-path(?:-set)?|community-list|route-policy|policy-options|policy-statement|routing-options|routing-instances"
        r"|static-route|virtual-router|routing-table|redistribute|router-id|bgp|ospf|ospf3|ospfv3|eigrp|isis|rip|pim|bfd)\b"
        r"|^/ip\s+route\b|^/routing\b|^route\s+\S+\s+[\d.]+\s"
    )),
    ("qos", _rx(r"\b(?:policy-map|class-map|service-policy|qos|traffic-shaper|shaping-policy|dscp|priority-queue)\b")),
    ("firewall", _rx(r"\b(?:access-list|access-group|access-class|ip\s+access-list|ipv6\s+access-list|traffic-filter)\b")),
    ("interfaces", _rx(r"^(?:interface|interfaces|/interface|config\s+system\s+interface|network\s+interface|/ip\s+address)\b")),
    ("objects", _rx(
        r"\b(?:firewall\s+(?:address6?|addrgrp6?|service\s+custom|service\s+group|schedule)|object-group|object\s+(?:network|service)"
        r"|address-group|service-group|addrgrp|address-object)\b|^(?:address|address-group|service|service-group)\s"
    )),
    ("firewall", _rx(
        r"\b(?:firewall|rulebase|security-policy|security\s+rules|zone|zones|filter|acl|ips-sensor|av-profile|webfilter-profile"
        r"|application-list|utm-status|ssl-ssh-profile|policy|policies)\b"
    )),
    ("switching", _rx(
        r"\b(?:vlan|vlans|spanning-tree|switchport|mst|stp|rstp|vtp|bridge|lacp|channel-group|link-aggregation|trunk|untagged"
        r"|tagged|mac\s+address-table|mlag|vpc|evpn|vxlan|vni)\b"
    )),
    ("routing", _rx(r"\b(?:vrf|neighbou?r|static|gateway|default-gateway)\b")),
    ("services", _rx(
        r"\b(?:ntp|ntpserver|sntp|logging|syslog|syslogd|log|snmp-server|snmp|dns|name-server|domain|domain-name|dhcp|sflow"
        r"|netflow|flow-export|lldp|cdp|clock|timezone|http|https-server|http-server|telemetry|netconf|restconf|api)\b"
    )),
    ("system", _rx(r"\b(?:hostname|host-name|version|boot|license|service|platform|system|identity|feature|global|vdom|hardware)\b")),
]

_DOC_KEYS = {"description", "alias", "remark", "comment", "comments", "name", "banner", "motd"}
_DOWN = re.compile(r"^(?:shutdown|disable|set\s+status\s+down)$", re.I)
_UP = re.compile(r"^(?:no\s+shutdown|set\s+status\s+up|enable)$", re.I)
_COMMENT_PREFIXES = ("!", "#", ";", ":", "Cryptochecksum:")
_IGNORED_LINES = {"exit", "quit", "return", "end", "exit-address-family", "exit-vrf", "exit-vlan"}
_NAME_RE = re.compile(r"^(?:set\s+)?(?:name|description|alias)\s+(.+?);?$", re.I)
_TOKEN_RE = re.compile(r'"[^"]*"|\'[^\']*\'|\S+')


# --------------------------------------------------------------------------- parsing


@dataclass
class Parsed:
    syntax: str
    lines: list[str]
    paths: list[Optional[tuple[str, ...]]]  # ancestor section headers per line (None = comment/separator)
    headers: set[int] = field(default_factory=set)  # lines that open a section

    def depth(self, index: int) -> int:
        path = self.paths[index]
        return len(path) if path is not None else -1

    def blocks(self) -> dict[int, int]:
        """Last line index of every section opened by a header line."""
        ends: dict[int, int] = {}
        open_stack: list[tuple[int, int]] = []  # (header index, depth)
        last_real = -1
        for index, path in enumerate(self.paths):
            if path is None:
                continue
            depth = len(path)
            while open_stack and open_stack[-1][1] >= depth:
                header, _ = open_stack.pop()
                ends[header] = last_real
            if index in self.headers:
                open_stack.append((index, depth))
            last_real = index
        for header, _ in open_stack:
            ends[header] = last_real
        return {h: e for h, e in ends.items() if e > h}


def detect_syntax(text: str, platform: str | None = None) -> str:
    lines = [line for line in text.splitlines()[:800] if line.strip()]
    hint = PLATFORM_SYNTAX.get(platform or "")
    if not lines:
        return hint or "indent"
    total = len(lines)
    configs = sum(1 for line in lines if line.startswith("config "))
    closers = sum(1 for line in lines if line.strip() in ("end", "next"))
    if configs and closers and any(line.lstrip().startswith(("set ", "edit ")) for line in lines):
        return "fortios"
    braces = sum(1 for line in lines if line.rstrip().endswith("{") or line.strip() in ("}", "};"))
    if braces >= 3 and braces >= total * 0.08:
        return "braces"
    sets = sum(1 for line in lines if line.startswith(("set ", "delete ", "unset ")))
    if sets >= total * 0.6:
        return "set"
    slashes = sum(1 for line in lines if line.startswith("/"))
    if slashes and slashes >= total * 0.3:
        return "routeros"
    return "indent"


def _ignorable(stripped: str) -> bool:
    return not stripped or stripped.startswith(_COMMENT_PREFIXES) or stripped in _IGNORED_LINES


def _parse_indent(lines: list[str]) -> tuple[list[Optional[tuple[str, ...]]], set[int]]:
    paths: list[Optional[tuple[str, ...]]] = []
    headers: set[int] = set()
    stack: list[tuple[int, str, int]] = []
    for index, raw in enumerate(lines):
        stripped = raw.strip()
        if _ignorable(stripped):
            paths.append(None)
            continue
        indent = len(raw) - len(raw.lstrip(" \t"))
        while stack and stack[-1][0] >= indent:
            stack.pop()
        if stack:
            headers.add(stack[-1][2])
        paths.append(tuple(item[1] for item in stack))
        stack.append((indent, stripped, index))
    return paths, headers


def _parse_fortios(lines: list[str]) -> tuple[list[Optional[tuple[str, ...]]], set[int]]:
    paths: list[Optional[tuple[str, ...]]] = []
    headers: set[int] = set()
    stack: list[str] = []
    for index, raw in enumerate(lines):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            paths.append(None)
        elif stripped in ("next", "end"):
            paths.append(None)
            opener = "edit " if stripped == "next" else "config "
            while stack and not stack[-1].startswith(opener):
                stack.pop()
            if stack:
                stack.pop()
        else:
            paths.append(tuple(stack))
            if stripped.startswith(("config ", "edit ")):
                headers.add(index)
                stack.append(stripped)
    return paths, headers


def _parse_braces(lines: list[str]) -> tuple[list[Optional[tuple[str, ...]]], set[int]]:
    paths: list[Optional[tuple[str, ...]]] = []
    headers: set[int] = set()
    stack: list[str] = []
    for index, raw in enumerate(lines):
        stripped = raw.strip()
        if not stripped or stripped.startswith(("#", "/*", "*")):
            paths.append(None)
        elif stripped.startswith("}"):
            paths.append(None)
            if stack:
                stack.pop()
        else:
            paths.append(tuple(stack))
            if stripped.endswith("{"):
                headers.add(index)
                stack.append(_clean(stripped[:-1]))
    return paths, headers


def _strip_verb(line: str) -> str:
    return re.sub(r"^(?:set|delete|unset|add)\s+", "", line.strip())


def _tokens(text: str) -> list[str]:
    return _TOKEN_RE.findall(text)


def _set_section(tokens: list[str]) -> str:
    if len(tokens) >= 4 and tokens[0] == "rulebase" and tokens[2] == "rules":
        return " ".join(tokens[:4])
    if len(tokens) >= 4 and tokens[:2] == ["network", "interface"]:
        return " ".join(tokens[:4])
    if len(tokens) >= 2 and tokens[0] in ("address", "address-group", "service", "service-group", "zone", "application-group", "tag"):
        return " ".join(tokens[:2])
    if len(tokens) >= 3 and tokens[0] == "interfaces":
        return " ".join(tokens[:3])
    if len(tokens) >= 2 and tokens[0] == "interface":
        return " ".join(tokens[:2])
    if len(tokens) >= 3 and tokens[0] in ("deviceconfig", "mgt-config", "network", "protocols", "system", "service", "firewall", "nat", "policy", "vpn"):
        return " ".join(tokens[: min(3, len(tokens) - 1)])
    return " ".join(tokens[: min(2, max(1, len(tokens) - 1))])


def _parse_set(lines: list[str]) -> tuple[list[Optional[tuple[str, ...]]], set[int]]:
    paths: list[Optional[tuple[str, ...]]] = []
    for raw in lines:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            paths.append(None)
        else:
            section = _set_section(_tokens(_strip_verb(stripped)))
            paths.append((section,) if section else ())
    return paths, set()


_ROS_PATH = re.compile(r"^(/\S+(?:\s+[a-z][\w-]*)*?)\s+(?:add|set|remove|disable|enable)\b")


def _parse_routeros(lines: list[str]) -> tuple[list[Optional[tuple[str, ...]]], set[int]]:
    paths: list[Optional[tuple[str, ...]]] = []
    current: str | None = None
    for raw in lines:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            paths.append(None)
        elif stripped.startswith("/"):
            match = _ROS_PATH.match(stripped)
            if match:
                paths.append((match.group(1),))
            else:
                current = stripped
                paths.append(None)
        else:
            paths.append((current,) if current else ())
    return paths, set()


_PARSERS = {"indent": _parse_indent, "fortios": _parse_fortios, "braces": _parse_braces, "set": _parse_set, "routeros": _parse_routeros}


def parse(text: str | None, syntax: str | None = None, platform: str | None = None) -> Parsed:
    text = text or ""
    syntax = syntax or detect_syntax(text, platform)
    lines = text.splitlines()
    paths, headers = _PARSERS.get(syntax, _parse_indent)(lines)
    return Parsed(syntax, lines, paths, headers)


# --------------------------------------------------------------------------- classification


def _clean(text: str) -> str:
    text = re.sub(r"\s+##.*$", "", text.strip())
    text = re.sub(r"^(?:inactive|protect|replace):\s*", "", text)
    return text.rstrip(";").strip()


def classify(path: tuple[str, ...], line: str, syntax: str = "indent") -> str:
    stripped = line.strip()
    free_text = _is_doc(stripped)  # descriptions and names are free text: classify by their section only
    if syntax == "set":
        text = _strip_verb(stripped)
    elif syntax == "routeros":
        text = stripped
    else:
        if free_text and not path:
            return "docs"
        text = " ".join([*path, "" if free_text else stripped])
    text = re.sub(r'"[^"]*"', '""', text)
    for category, pattern in _RULES:
        if pattern.search(text):
            return category
    return "docs" if free_text else "other"


def _is_doc(rel: str) -> bool:
    words = _strip_verb(rel).split()
    return bool(words) and words[0].lower().strip('"') in _DOC_KEYS


# --------------------------------------------------------------------------- analysis


@dataclass
class ChangeItem:
    key: tuple[str, ...]
    label: str
    action: str  # added | removed | modified
    category: str
    risk: str
    text: str
    added: int = 0
    removed: int = 0
    categories: list[str] = field(default_factory=list)
    order: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "action": self.action,
            "category": self.category,
            "category_label": CATEGORIES[self.category][0],
            "risk": self.risk,
            "text": self.text,
            "added": self.added,
            "removed": self.removed,
        }


@dataclass
class Analysis:
    risk: Optional[str]
    score: int
    added: int
    removed: int
    items: list[ChangeItem] = field(default_factory=list)
    syntax: str = "indent"
    initial: bool = False

    @property
    def ranked(self) -> list[ChangeItem]:
        return sorted(self.items, key=lambda i: (-RISK_ORDER[i.risk], i.order))

    @property
    def highlights(self) -> list[str]:
        return [item.text for item in self.ranked]

    def categories(self) -> list[dict[str, Any]]:
        stats: dict[str, dict[str, Any]] = {}
        for item in self.items:
            for category in item.categories or [item.category]:
                entry = stats.setdefault(category, {"key": category, "label": CATEGORIES[category][0], "count": 0, "risk": "low"})
                entry["count"] += 1
                level = item.risk if category == item.category else CATEGORIES[category][1]
                if RISK_ORDER[level] > RISK_ORDER[entry["risk"]]:
                    entry["risk"] = level
        return sorted(stats.values(), key=lambda c: (-RISK_ORDER[c["risk"]], -c["count"], c["label"]))

    def to_dict(self, max_items: int = 12) -> dict[str, Any]:
        return {
            "risk": self.risk,
            "score": self.score,
            "added": self.added,
            "removed": self.removed,
            "initial": self.initial,
            "syntax": self.syntax,
            "sections": len(self.items),
            "categories": self.categories(),
            "highlights": self.highlights[:8],
            "items": [item.to_dict() for item in self.ranked[:max_items]],
        }

    def summary(self) -> str:
        if self.initial:
            return "initial backup"
        if not self.risk:
            return "no configuration change"
        labels = [c["label"] for c in self.categories()[:3]]
        return f"{self.risk} risk" + (f" · {', '.join(labels)}" if labels else "")


def _value(text: str, limit: int = 38) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _item_key(syntax: str, path: tuple[str, ...], line: str, is_header: bool) -> tuple[str, ...]:
    stripped = line.strip()
    head = _clean(stripped[:-1]) if syntax == "braces" and stripped.endswith("{") else stripped
    full = path + ((head,) if is_header else ())
    if syntax == "fortios":
        if not full:
            return (stripped,)
        for index, part in enumerate(full):
            if part.startswith("edit "):
                return full[: index + 1]
        return full[:1]
    if syntax == "braces":
        if not full:
            return (_clean(head),)
        deep = full[0].split()[0] in ("protocols", "policy-options", "routing-instances", "firewall", "security", "system", "snmp", "class-of-service")
        return full[: 3 if deep else 2]
    if syntax == "set":
        return path or (stripped,)
    if syntax == "routeros":
        if path and re.search(r"(?:^|\s)add\s", stripped):
            return path + (stripped,)
        return path or (stripped,)
    return full[:1] if full else (stripped,)


def _relative(syntax: str, key: tuple[str, ...], line: str) -> str:
    stripped = line.strip()
    if syntax == "set":
        tokens = _tokens(_strip_verb(stripped))
        skip = len(key[0].split()) if key else 0
        return " ".join(tokens[skip:]) or stripped
    if syntax == "routeros" and key and stripped.startswith(key[0]):
        return stripped[len(key[0]):].strip()
    return _clean(stripped.rstrip("{")) if syntax == "braces" else stripped


def label_for(syntax: str, key: tuple[str, ...]) -> str:
    if not key:
        return "configuration"
    if syntax == "fortios":
        parts = []
        for part in key:
            if part.startswith("config "):
                parts.append(part[7:])
            elif part.startswith("edit "):
                parts.append(part[5:].strip().strip('"'))
            else:
                parts.append(part)
        label = " ".join(parts)
        for prefix, replacement in (("system interface ", "interface "), ("router static ", "static route "), ("system ", "")):
            if label.startswith(prefix):
                label = replacement + label[len(prefix):]
                break
        return _value(label, 72)
    if syntax == "braces":
        label = " ".join(_clean(p) for p in key)
        for prefix, replacement in (("interfaces ", "interface "), ("protocols ", ""), ("policy-options ", ""), ("system ", "")):
            if label.startswith(prefix) and len(key) > 1:
                label = replacement + label[len(prefix):]
                break
        return _value(label, 72)
    if syntax == "set":
        head = key[0]
        match = re.match(r"^rulebase\s+(\S+)\s+rules\s+(\S+)", head)
        if match:
            return f"{match.group(1)} rule {match.group(2).strip(chr(34))}"
        match = re.match(r"^network\s+interface\s+\S+\s+(\S+)", head)
        if match:
            return f"interface {match.group(1)}"
        match = re.match(r"^(address|address-group|service|service-group)\s+(\S+)$", head)
        if match:
            kind = {"address": "address object", "service": "service object"}.get(match.group(1), match.group(1).replace("-", " "))
            return f"{kind} {match.group(2).strip(chr(34))}"
        return _value(head, 72)
    if syntax == "routeros":
        path = key[0].lstrip("/")
        if path.startswith("ip firewall "):
            path = path[3:]
        if len(key) > 1:
            entry = key[1]
            comment = re.search(r'comment="([^"]*)"|comment=(\S+)', entry)
            if comment:
                return f'{path} rule "{comment.group(1) or comment.group(2)}"'
            name = re.search(r'\bname="?([^"\s]+)', entry)
            if name:
                return f"{path} {name.group(1)}"
            params = [p for p in re.findall(r"\b[\w-]+=\S+", entry)[:2]]
            return f"{path} ({' '.join(params)})" if params else path
        return path
    head = key[0]
    for pattern, template in (
        (r"^(?:ip|ipv6)\s+access-list\s+(?:extended\s+|standard\s+|role-based\s+)?(\S+)", "ACL {0}"),
        (r"^access-list\s+(\S+)", "ACL {0}"),
        (r"^vlan\s+(\S+)$", "VLAN {0}"),
        (r"^object(?:-group)?\s+\S+\s+(\S+)", "object {0}"),
        (r"^ip\s+prefix-list\s+(\S+)", "prefix-list {0}"),
        (r"^route-map\s+(\S+)", "route-map {0}"),
    ):
        match = re.match(pattern, head, re.I)
        if match:
            return template.format(*match.groups())
    return _value(head, 72)


def _common_prefix(a: list[str], b: list[str]) -> int:
    count = 0
    for x, y in zip(a, b):
        if x != y:
            break
        count += 1
    return count


def _pair(removed: list[str], added: list[str], minimum: int = 1) -> tuple[list[tuple[str, str, str, str, str]], list[str], list[str]]:
    """Match removed/added lines that change the same setting.

    Returns ``(old line, new line, key, old value, new value)`` pairs plus the unmatched lines.
    """
    pairs: list[tuple[str, str, str, str, str]] = []
    left_added = list(added)
    left_removed: list[str] = []
    for old in removed:
        old_tokens = _tokens(old)
        best, best_len = None, 0
        for candidate in left_added:
            length = _common_prefix(old_tokens, _tokens(candidate))
            if length > best_len:
                best, best_len = candidate, length
        if best is not None and best_len >= minimum:
            new_tokens = _tokens(best)
            if best_len < len(old_tokens) or best_len < len(new_tokens):
                size = _key_size(old_tokens, new_tokens, best_len)
                key = " ".join(old_tokens[:size])
                pairs.append((old, best, key, " ".join(old_tokens[size:]), " ".join(new_tokens[size:])))
                left_added.remove(best)
                continue
        left_removed.append(old)
    return pairs, left_removed, left_added


_KEYWORD = re.compile(r"^[a-z][a-z0-9-]*$")


def _key_size(old: list[str], new: list[str], common: int) -> int:
    """How many leading tokens name the setting (the rest is its value)."""
    size = common
    if len(old) > 1:
        size = min(size, len(old) - 1)
    if len(new) > 1:
        size = min(size, len(new) - 1)
    if old and old[0].lower() in _DOC_KEYS:
        size = min(size, 1)
    elif len(old) > 1 and old[0] == "set" and old[1].lower() in _DOC_KEYS:
        size = min(size, 2)
    while size > 1 and not _KEYWORD.match(old[size - 1]):
        size -= 1
    return max(1, size)


def _change_text(key: str, old: str, new: str) -> str:
    if not old:
        return f"{key} {_value(new)}".strip() + " set"
    if not new:
        return f"{key} {_value(old)}".strip() + " cleared"
    if new.startswith(old) and len(new) > len(old):
        return f"{key} {_value(old, 24)} → …{_value(new[len(old):].strip(), 34)}"
    return f"{key} {_value(old, 26)} → {_value(new, 30)}".strip()


def _params(text: str) -> dict[str, str]:
    return {m.group(1): m.group(2) for m in re.finditer(r'([\w-]+)=("[^"]*"|\S+)', text)}


def _pair_text(syntax: str, key: str, old: str, new: str) -> str:
    if syntax == "routeros":
        before, after = _params(f"{key} {old}"), _params(f"{key} {new}")
        changed = [k for k in dict.fromkeys([*before, *after]) if before.get(k) != after.get(k)]
        if changed:
            parts = [_change_text(k, before.get(k, ""), after.get(k, "")) for k in changed[:2]]
            return ", ".join(parts)
    return _change_text(re.sub(r"^set\s+", "", key), old, new)


def _section_name(lines: list[str], label: str) -> str:
    for line in lines:
        match = _NAME_RE.match(line.strip())
        if match:
            value = match.group(1).strip().strip('"').strip("'")
            if value and value.lower() not in label.lower():
                return f" ({_value(value, 40)})"
    return ""


def _slide(parsed: Parsed, start: int, end: int) -> tuple[int, int]:
    """Move an inserted/deleted block to its most natural position.

    Repeated lines make a diff ambiguous: inserting a FortiOS ``edit`` block after a similar one can be
    reported as starting in the middle of the previous block. Like git's indent heuristic, prefer the
    position whose first line is least indented and opens a section.
    """
    lines = parsed.lines
    if end <= start:
        return start, end
    candidates = [(start, end)]
    s, e = start, end
    while s > 0 and lines[s - 1] == lines[e - 1]:
        s, e = s - 1, e - 1
        candidates.append((s, e))
    s, e = start, end
    while e < len(lines) and lines[s] == lines[e]:
        s, e = s + 1, e + 1
        candidates.append((s, e))

    def score(candidate: tuple[int, int]) -> tuple[int, int, int]:
        first = lines[candidate[0]]
        return len(first) - len(first.lstrip()), 0 if candidate[0] in parsed.headers else 1, abs(candidate[0] - start)

    return min(candidates, key=score)


def analyze(old: str | None, new: str | None, platform: str | None = None) -> Analysis:
    """Analyse the change from ``old`` to ``new`` configuration text (both normalized, secrets masked)."""
    if old is None:
        lines = len((new or "").splitlines())
        return Analysis(risk=None, score=0, added=lines, removed=0, initial=True, syntax=detect_syntax(new or "", platform))
    syntax = detect_syntax(new or old, platform)
    before, after = parse(old, syntax), parse(new, syntax)
    keys_before = {_item_key(syntax, p, line, i in before.headers) for i, (p, line) in enumerate(zip(before.paths, before.lines)) if p is not None}
    keys_after = {_item_key(syntax, p, line, i in after.headers) for i, (p, line) in enumerate(zip(after.paths, after.lines)) if p is not None}

    groups: dict[tuple[str, ...], dict[str, Any]] = {}
    total_added = total_removed = 0
    matcher = difflib.SequenceMatcher(None, before.lines, after.lines, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        if tag == "insert":
            j1, j2 = _slide(after, j1, j2)
        elif tag == "delete":
            i1, i2 = _slide(before, i1, i2)
        for side, parsed, start, end in (("removed", before, i1, i2), ("added", after, j1, j2)):
            for index in range(start, end):
                path = parsed.paths[index]
                line = parsed.lines[index]
                if path is None or not line.strip():
                    continue
                key = _item_key(syntax, path, line, index in parsed.headers)
                group = groups.setdefault(key, {"added": [], "removed": [], "categories": [], "order": len(groups)})
                group[side].append(_relative(syntax, key, line))
                group["categories"].append(classify(path, line, syntax))
                if side == "added":
                    total_added += 1
                else:
                    total_removed += 1

    names = _block_names(syntax, after) if syntax == "fortios" else {}
    names.update({k: v for k, v in (_block_names(syntax, before) if syntax == "fortios" else {}).items() if k not in names})
    items = [_build_item(syntax, key, group, key in keys_before, key in keys_after, names.get(key)) for key, group in groups.items()]
    items = _merge_single_lines(syntax, items, groups)
    if not items:
        return Analysis(risk="low", score=0, added=total_added, removed=total_removed, syntax=syntax)
    changed = total_added + total_removed
    risk = max((item.risk for item in items), key=RISK_ORDER.__getitem__)
    if changed > 150 and risk != "high":
        risk = RISK_LEVELS[RISK_ORDER[risk] + 1]
    score = sum(RISK_WEIGHT[item.risk] for item in items) + (20 if changed > 150 else 8 if changed > 40 else 0)
    return Analysis(risk=risk, score=min(100, score), added=total_added, removed=total_removed, items=items, syntax=syntax)


def _block_names(syntax: str, parsed: Parsed) -> dict[tuple[str, ...], str]:
    names: dict[tuple[str, ...], str] = {}
    for index, (path, line) in enumerate(zip(parsed.paths, parsed.lines)):
        if path is None:
            continue
        match = re.match(r'^set\s+name\s+"?([^"]+)"?$', line.strip())
        if match:
            names.setdefault(_item_key(syntax, path, line, index in parsed.headers), match.group(1))
    return names


def _build_item(
    syntax: str, key: tuple[str, ...], group: dict[str, Any], existed: bool, exists: bool, name: str | None = None
) -> ChangeItem:
    added, removed = group["added"], group["removed"]
    label = label_for(syntax, key)
    if name and name.lower() not in label.lower():
        label = f"{label} ({_value(name, 32)})"
    head_category = classify(key[:-1], key[-1], syntax) if syntax not in ("set", "routeros") else classify((), key[-1], syntax)
    if not existed and exists:
        action = "added"
    elif existed and not exists:
        action = "removed"
    else:
        action = "modified"
    line_categories = group["categories"]
    if action != "modified":  # a whole new/removed section: only escalate for traffic-affecting content
        line_categories = [c for c in line_categories if c in ("firewall", "nat", "vpn", "routing")]
    categories = list(dict.fromkeys([head_category, *line_categories]))
    category = head_category

    risk = max((CATEGORIES[c][1] for c in categories if c != "docs"), key=RISK_ORDER.__getitem__, default="low")
    details: list[str] = []
    if action == "modified":
        pairs, only_removed, only_added = _pair(removed, added)
        changed_rel = [*removed, *added]
        if changed_rel and all(_is_doc(rel) for rel in changed_rel):
            category, risk, categories = "docs", "low", ["docs"]
        for rel in only_added:
            if _DOWN.match(rel):
                details.append("shut down")
                risk = "high"
            elif _UP.match(rel):
                details.append("enabled")
            else:
                details.append(f"added {_value(rel, 56)}")
        for rel in only_removed:
            if _DOWN.match(rel):
                details.append("enabled (shutdown removed)")
            else:
                details.append(f"removed {_value(rel, 56)}")
        details = [_pair_text(syntax, k, o, n) for _, _, k, o, n in pairs] + details
        if len(details) > 3:
            details = details[:2] + [f"{len(details) - 2} more changes"]
        text = f"{label}: {', '.join(details)}" if details else f"{label} changed"
    elif action == "added":
        text = f"Added {label}{_section_name(added, label)}"
    else:
        text = f"Removed {label}{_section_name(removed, label)}"
    return ChangeItem(key, label, action, category, risk, text, len(added), len(removed), categories, group["order"])


def _merge_single_lines(syntax: str, items: list[ChangeItem], groups: dict[tuple[str, ...], dict[str, Any]]) -> list[ChangeItem]:
    """Turn 'Removed ntp server A' + 'Added ntp server B' (top-level lines) into one modification."""
    if syntax in ("set", "routeros"):
        return items
    removed = {groups[i.key]["removed"][0]: i for i in items if i.action == "removed" and len(i.key) == 1 and i.removed == 1 and not i.added}
    added = {groups[i.key]["added"][0]: i for i in items if i.action == "added" and len(i.key) == 1 and i.added == 1 and not i.removed}
    if not removed or not added:
        return items
    pairs, _, _ = _pair(list(removed), list(added), minimum=2)
    result = list(items)
    for old_line, new_line, key, old, new in pairs:
        old_item, new_item = removed[old_line], added[new_line]
        if old_item not in result or new_item not in result:
            continue
        result.remove(old_item)
        category, risk = (("docs", "low") if _is_doc(key) else (new_item.category, new_item.risk))
        text = _change_text(key, old, new).replace(f"{key} ", f"{key}: ", 1)
        result[result.index(new_item)] = ChangeItem(
            (key,), key, "modified", category, risk, text, 1, 1, [category], min(old_item.order, new_item.order),
        )
    return result


def commit_summary(analysis: Analysis, limit: int = 6) -> list[str]:
    """Lines for the commit message body."""
    if analysis.initial or not analysis.risk or not analysis.items:
        return []
    labels = ", ".join(c["label"] for c in analysis.categories()[:4])
    lines = [f"Risk:       {analysis.risk} ({labels})", "Summary:"]
    ranked = analysis.highlights
    lines += [f"  - {text}" for text in ranked[:limit]]
    if len(ranked) > limit:
        lines.append(f"  - ... and {len(ranked) - limit} more")
    return lines
