"""Fleet-wide configuration search: text, regular expressions and IP-aware "where is" lookups.

An IP query understands how every vendor writes addresses - ``10.1.1.1 255.255.255.0``, ACL wildcards
(``10.1.1.0 0.0.0.255``), ``10.1.1.0/24``, ``host 10.1.1.1``, ``address=10.1.1.1/24`` - so searching for
``10.10.40.57`` finds the interface subnet it lives in (longest prefix first), the routes and firewall
objects that cover it, and the ACLs that mention it, across every device in the inventory.
"""

from __future__ import annotations

import ipaddress
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Iterable, Optional, Union

from netledger.intel import Parsed, parse

if TYPE_CHECKING:
    from netledger.config import Settings

Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
Address = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

MAX_PATTERN = 200
MAX_LINE = 2000
_NESTED_QUANTIFIER = re.compile(r"\((?:[^()\\]|\\.)*[+*}](?:[^()\\]|\\.)*\)\s*[+*{]")
_V4 = r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"
_V4_TOKEN = re.compile(rf"({_V4})(?:/(\d{{1,2}})(?!\d))?")
_V6_TOKEN = re.compile(r"(?<![\w:.])((?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4})(?:/(\d{1,3}))?(?![\w:])")
_GAP = re.compile(r"^\s+$")

ROLES = {
    "interface": "Interface address",
    "route": "Routing",
    "acl": "Access rule",
    "object": "Object",
    "peer": "Peer",
    "service": "Service",
    "reference": "Reference",
}
KINDS = {"exact": "Exact match", "subnet": "In subnet", "within": "Inside range", "contains": "Covers range", "text": "Match"}


class QueryError(ValueError):
    """The search query is not valid."""


@dataclass
class Query:
    raw: str
    mode: str  # ip | regex | text
    network: Optional[Network] = None
    pattern: Optional[re.Pattern[str]] = None

    @property
    def is_host(self) -> bool:
        return self.network is not None and self.network.prefixlen == self.network.max_prefixlen

    def describe(self) -> str:
        if self.mode == "ip" and self.network is not None:
            return f"IP address {self.network.network_address}" if self.is_host else f"network {self.network}"
        return "regular expression" if self.mode == "regex" else "text"


def as_network(text: str) -> Optional[Network]:
    candidate = text.strip()
    if not candidate or not any(c in candidate for c in ".:") or any(c.isalpha() and c.lower() not in "abcdef" for c in candidate.replace(" mask ", " ")):
        return None
    parts = candidate.replace(" mask ", " ").split()
    if len(parts) == 2:
        candidate = f"{parts[0]}/{parts[1]}"
    elif len(parts) != 1:
        return None
    try:
        return ipaddress.ip_network(candidate, strict=False)
    except ValueError:
        return None


def parse_query(raw: str, regex: bool = False, ignore_case: bool = True) -> Query:
    text = (raw or "").strip()
    if not text:
        raise QueryError("type something to search for")
    body = None
    if regex:
        body = text
    elif text.startswith("re:"):
        body = text[3:]
    elif len(text) > 2 and text.startswith("/") and text.endswith("/"):
        body = text[1:-1]
    if body is not None:
        if len(body) > MAX_PATTERN:
            raise QueryError(f"regular expressions are limited to {MAX_PATTERN} characters")
        if _NESTED_QUANTIFIER.search(body):
            raise QueryError("nested quantifiers such as (a+)+ are not supported")
        try:
            return Query(raw, "regex", pattern=re.compile(body, re.I if ignore_case else 0))
        except re.error as exc:
            raise QueryError(f"invalid regular expression: {exc}") from None
    network = as_network(text)
    if network is not None:
        return Query(raw, "ip", network=network)
    return Query(raw, "text", pattern=re.compile(re.escape(text), re.I if ignore_case else 0))


# --------------------------------------------------------------------------- address tokens


@dataclass
class Token:
    start: int
    end: int
    network: Network
    host: Optional[Address]


def _mask(value: str) -> Optional[tuple[str, int]]:
    """('netmask'|'wildcard', prefix length) for a dotted mask, None if it is a plain address."""
    try:
        number = int(ipaddress.IPv4Address(value))
    except ValueError:
        return None
    inverted = number ^ 0xFFFFFFFF
    if number and (inverted & (inverted + 1)) == 0:
        return "netmask", 32 - inverted.bit_length()
    if (number & (number + 1)) == 0:
        return "wildcard", 32 - number.bit_length()
    return None


def tokens(line: str) -> list[Token]:
    found: list[Token] = []
    matches = list(_V4_TOKEN.finditer(line))
    skip = -1
    for index, match in enumerate(matches):
        if index == skip:
            continue
        address, prefix = match.group(1), match.group(2)
        try:
            host = ipaddress.IPv4Address(address)
        except ValueError:
            continue
        end = match.end()
        network: Optional[Network] = None
        if prefix is not None:
            if int(prefix) > 32:
                continue
            network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
        elif index + 1 < len(matches) and _GAP.match(line[match.end(): matches[index + 1].start()]) and matches[index + 1].group(2) is None:
            mask_text = matches[index + 1].group(1)
            if mask_text == "0.0.0.0":
                kind, length = ("netmask", 0) if address == "0.0.0.0" else ("wildcard", 32)
            else:
                parsed = _mask(mask_text)
                kind, length = parsed if parsed else ("", -1)
            if length >= 0:
                network = ipaddress.ip_network(f"{address}/{length}", strict=False)
                end = matches[index + 1].end()
                skip = index + 1
        if network is None:
            network = ipaddress.ip_network(f"{address}/32")
        is_host = network.prefixlen >= 31 or host != network.network_address
        found.append(Token(match.start(), end, network, host if is_host else None))
    for match in _V6_TOKEN.finditer(line):
        try:
            host6 = ipaddress.IPv6Address(match.group(1))
        except ValueError:
            continue
        length = int(match.group(2)) if match.group(2) else 128
        if length > 128:
            continue
        network6 = ipaddress.ip_network(f"{host6}/{length}", strict=False)
        found.append(Token(match.start(), match.end(), network6, host6 if length >= 127 or host6 != network6.network_address else None))
    return found


def match_token(query: Network, token: Token) -> Optional[tuple[str, int]]:
    """(kind, rank) when the address token is relevant to the query; lower rank = better."""
    net = token.network
    if net.version != query.version:
        return None
    if query.prefixlen == query.max_prefixlen:
        address = query.network_address
        if token.host is not None and token.host == address:
            return "exact", 0
        if net.prefixlen == 0 or net.prefixlen == net.max_prefixlen:
            return None
        if address in net:
            return "subnet", 1 + net.max_prefixlen - net.prefixlen
        return None
    if net.prefixlen == 0 and query.prefixlen != 0:
        return None
    if net == query:
        return "exact", 0
    if net.subnet_of(query):  # type: ignore[arg-type]
        return "within", 40 + net.prefixlen
    if query.subnet_of(net):  # type: ignore[arg-type]
        return "contains", 1 + net.max_prefixlen - net.prefixlen
    return None


def line_role(line: str, section: Iterable[str] = ()) -> str:
    text = line.strip().lower()
    context = " ".join(section).lower()
    if re.search(r"\b(?:tacacs|radius|ntp|ntpserver|logging|syslog|snmp|dns|aaa-server|name-server)\b", context):
        return "service"
    if re.search(r"\b(?:router|bgp|ospf|eigrp|isis|rip|protocols|routing-options|virtual-router|static)\b", context):
        return "route"
    if re.search(r"\b(?:route|static-route|gateway|next-?hop|default-gateway|nexthop)\b", text):
        return "route"
    addressing = (
        re.match(r"^(?:ip(?:v6)?\s+address|address|set\s+ip6?|ip\s+static|ipv[46]-address|set\s+ipv6\s+ip6-address)\b", text)
        or text.startswith("/ip address")
        or re.search(r"\blayer3\s+ip\b", text)
    )
    if addressing and (not context or re.search(r"\b(?:interface|interfaces|unit|family|vlan|vlanif|lo\d*|loopback)\b", context) or text.startswith(("ip address", "ipv6 address", "/ip address"))):
        return "interface"
    if re.search(r"\b(?:access-list|permit|deny|rule|rules|filter|policy|access-class|src-address|dst-address|source-address|destination-address|firewall\s+filter)\b", text):
        return "acl"
    if re.search(r"\b(?:object|subnet|address-group|address-list|addrgrp|ip-netmask|ip-range|host|network)\b", text):
        return "object"
    if re.search(r"\b(?:neighbou?r|peer|remote-gw|remote-as)\b", text):
        return "peer"
    if re.search(r"\b(?:ntp|dns|name-server|logging|syslog|tacacs|radius|snmp|server|servers|primary|secondary)\b", text):
        return "service"
    return "reference"


# --------------------------------------------------------------------------- documents


@dataclass
class Document:
    device: str
    path: str
    text: str
    platform: Optional[str] = None
    info: dict[str, Any] = field(default_factory=dict)
    parsed: Optional[Parsed] = None

    def structure(self) -> Parsed:
        if self.parsed is None:
            self.parsed = parse(self.text, platform=self.platform)
        return self.parsed


@dataclass
class Match:
    line_no: int
    line: str
    section: list[str]
    kind: str
    role: str
    rank: int
    network: Optional[str] = None
    spans: list[tuple[int, int]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "line": self.line_no, "text": self.line, "section": self.section, "kind": self.kind, "role": self.role,
            "rank": self.rank, "network": self.network, "spans": self.spans,
        }


@dataclass
class DeviceHits:
    device: str
    path: str
    info: dict[str, Any]
    matches: list[Match]

    @property
    def best_rank(self) -> int:
        return min((m.rank for m in self.matches), default=10_000)


@dataclass
class SearchResult:
    query: Query
    hits: list[DeviceHits] = field(default_factory=list)
    total: int = 0
    devices: int = 0
    lines: int = 0
    truncated: bool = False
    elapsed: float = 0.0
    error: Optional[str] = None

    def best(self) -> list[tuple[DeviceHits, Match]]:
        """For an IP address: the interface subnets it lives in (longest prefix) or the device that owns it."""
        if self.query.mode != "ip" or not self.query.is_host:
            return []
        owners = [(h, m) for h in self.hits for m in h.matches if m.kind == "exact" and m.role == "interface"]
        if owners:
            return owners
        subnets = [(h, m) for h in self.hits for m in h.matches if m.kind == "subnet" and m.role == "interface"]
        if not subnets:
            return []
        best = min(m.rank for _, m in subnets)
        return [(h, m) for h, m in subnets if m.rank == best]

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query.raw,
            "mode": self.query.mode,
            "network": str(self.query.network) if self.query.network else None,
            "total": self.total,
            "devices_scanned": self.devices,
            "lines_scanned": self.lines,
            "truncated": self.truncated,
            "elapsed": round(self.elapsed, 3),
            "error": self.error,
            "best": [{"device": h.device, **m.to_dict()} for h, m in self.best()],
            "results": [
                {"device": h.device, "path": h.path, "site": h.info.get("site"), "platform": h.info.get("platform"), "matches": [m.to_dict() for m in h.matches]}
                for h in self.hits
            ],
        }


def _section(parsed: Parsed, index: int) -> list[str]:
    path = parsed.paths[index] if index < len(parsed.paths) else None
    labels = []
    for part in path or ():
        part = re.sub(r"\s*\{$", "", part).strip()
        if parsed.syntax == "fortios":
            part = re.sub(r"^(?:config|edit)\s+", "", part).strip('"')
        labels.append(part)
    return labels[-3:]


def search(
    documents: Iterable[Document],
    query: Query,
    limit: int = 1000,
    per_device: int = 60,
    budget: float = 5.0,
) -> SearchResult:
    started = time.monotonic()
    result = SearchResult(query)
    for document in documents:
        if time.monotonic() - started > budget:
            result.truncated = True
            break
        result.devices += 1
        lines = document.text.splitlines()
        result.lines += len(lines)
        matches: list[Match] = []
        parsed: Optional[Parsed] = None
        for index, line in enumerate(lines):
            if query.mode == "ip":
                assert query.network is not None
                if not any(c.isdigit() for c in line):
                    continue
                best: Optional[tuple[str, int, Token]] = None
                spans = []
                for token in tokens(line):
                    hit = match_token(query.network, token)
                    if hit:
                        spans.append((token.start, token.end))
                        if best is None or hit[1] < best[1]:
                            best = (hit[0], hit[1], token)
                if best is None:
                    continue
                parsed = parsed or document.structure()
                section = _section(parsed, index)
                role = line_role(line, section)
                rank = best[1] + (0 if role == "interface" else 200 if role in ("route", "object") else 400)
                matches.append(Match(index + 1, line, section, best[0], role, rank, str(best[2].network), spans))
            else:
                assert query.pattern is not None
                spans = [m.span() for m in query.pattern.finditer(line[:MAX_LINE]) if m.end() > m.start()]
                if not spans:
                    continue
                parsed = parsed or document.structure()
                section = _section(parsed, index)
                matches.append(Match(index + 1, line, section, "text", line_role(line, section), 1000, None, spans))
            if len(matches) >= per_device:
                result.truncated = True
                break
        if matches:
            matches.sort(key=lambda m: (m.rank, m.line_no))
            result.hits.append(DeviceHits(document.device, document.path, document.info, matches))
            result.total += len(matches)
            if result.total >= limit:
                result.truncated = True
                break
    result.hits.sort(key=lambda h: (h.best_rank, h.device.lower()))
    result.elapsed = time.monotonic() - started
    return result


# --------------------------------------------------------------------------- where the latest configs live


def config_root(settings: Settings) -> Path:
    git = settings.git
    if git.backend in ("git", "local"):
        return settings.resolve_path(git.workdir) if git.workdir else settings.data_path / "repo"
    return settings.data_path / "mirror"


class DocumentCache:
    """Masked configuration texts keyed by file identity, so repeated searches do not re-read the repository."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: dict[str, tuple[tuple[int, int], Document]] = {}

    def load(
        self,
        root: Path,
        entries: Iterable[tuple[str, str, Optional[str], dict[str, Any]]],
        transform: Callable[[str, Optional[str]], str],
    ) -> list[Document]:
        """``entries`` are (device, repository path, platform, info)."""
        documents = []
        for device, rel, platform, info in entries:
            target = root / rel
            try:
                stat = target.stat()
            except OSError:
                continue
            stamp = (stat.st_mtime_ns, stat.st_size)
            with self._lock:
                cached = self._items.get(str(target))
            if cached and cached[0] == stamp:
                document = cached[1]
                document.info = info
            else:
                try:
                    raw = target.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")
                except OSError:
                    continue
                document = Document(device, rel, transform(raw, platform), platform, info)
                with self._lock:
                    self._items[str(target)] = (stamp, document)
            documents.append(document)
        return documents
