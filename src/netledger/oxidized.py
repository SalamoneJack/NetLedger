"""Oxidized as a configuration source: Oxidized collects, NetLedger analyses, alerts and keeps the history.

Two modes:

* ``repo`` reads Oxidized's git output (one repository, or one per group with ``single_repo: false``) and
  never writes to it. Every commit since the last one processed becomes a change, with the commit's
  author and time.
* ``api`` polls oxidized-web: ``/nodes.json`` for the nodes, ``/node/fetch/...`` for a configuration and
  ``/node/version.json`` for who changed it and when.

NetLedger does not log in to these devices for a backup. Health checks still use NetLedger's own
credentials for devices that enable ``health``.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

from netledger.config import ConfigError, InventorySource, Settings
from netledger.intel import detect_syntax
from netledger.platforms import resolve_platform
from netledger.utils import deep_merge, unique

log = logging.getLogger(__name__)

# Oxidized model (its file name or Ruby class name, in any case) -> NetLedger platform
MODELS = {
    "ios": "ios", "iosxe": "ios", "iosxr": "iosxr", "nxos": "nxos", "asa": "asa", "aireos": "aireos",
    "ciscosmb": "cisco_smb", "junos": "junos", "eos": "eos", "fortios": "fortios", "fortigate": "fortios",
    "panos": "panos", "panosapi": "panos", "routeros": "routeros", "procurve": "procurve", "aoscx": "aoscx",
    "comware": "comware", "h3c": "comware", "vrp": "huawei_vrp", "ironware": "fastiron", "fastiron": "fastiron",
    "os10": "dellos10", "xos": "exos", "vyos": "vyos", "vyatta": "vyos", "edgeos": "edgeos", "gaiaos": "gaia",
}
GENERIC_AUTHORS = ("oxidized", "o@example.com")  # Oxidized's default git identity says nothing about who changed it
FAILED = ("no_connection", "fail", "failed", "timeout")


class OxidizedError(Exception):
    """Oxidized's repository or API could not be read."""


def map_model(model: str | None, overrides: Dict[str, str] | None = None) -> Optional[str]:
    """NetLedger platform for an Oxidized model: ``IOS``, ``JunOS``, ``fortigate``, ``panos_api``, ..."""
    if not model:
        return None
    for key, value in (overrides or {}).items():
        if key.lower() == model.lower():
            return resolve_platform(value) or value
    return MODELS.get(re.sub(r"[^a-z0-9]", "", model.lower()))


def guess_platform(text: str) -> Optional[str]:
    """Platform from the configuration itself, for nodes whose Oxidized model is unknown."""
    head = text[:6000]

    def has(pattern: str, where: str = head) -> bool:
        return re.search(pattern, where, re.M) is not None

    if has(r"^#config-version=FG"):
        return "fortios"
    if has(r"^# .* by RouterOS|^/system identity\b"):
        return "routeros"
    if has(r"^set deviceconfig ") or "<config version=" in head:
        return "panos"
    syntax = detect_syntax(text)
    if syntax == "fortios":
        return "fortios"
    if syntax == "routeros":
        return "routeros"
    if syntax == "braces":
        return "vyos" if has(r"vyos-config-version|/\* Warning: Do not remove", text) else "junos"
    if syntax == "set":
        return "junos" if has(r"^set (?:system|interfaces|protocols|routing-options) ") else "gaia"
    if has(r"^ASA Version |^: Saved"):
        return "asa"
    if has(r"^!Command: show running-config|^feature "):
        return "nxos"
    if has(r"^! device: |^management api http-commands", text):
        return "eos"
    if has(r"^!! IOS XR |^!! Last configuration change"):
        return "iosxr"
    if has(r"^; J\w+ Configuration Editor"):
        return "procurve"
    if has(r"^!\s*Version ArubaOS-CX"):
        return "aoscx"
    if has(r"^\s*sysname "):
        return "huawei_vrp" if has(r"Huawei|VRP") else "comware"
    if has(r"^hostname |^interface (?:GigabitEthernet|FastEthernet|TenGigabitEthernet|Vlan)\d", text):
        return "ios"
    return None


# --------------------------------------------------------------------------- git (read-only)


@dataclass
class Commit:
    sha: str
    author: str
    email: str
    time: float
    subject: str
    files: List[Tuple[str, str]] = field(default_factory=list)  # (status A/M/D, path)


class GitReader:
    """Read-only access to a repository that belongs to someone else (Oxidized's), bare or not."""

    def __init__(self, path: Path):
        self.path = Path(path)

    def _run(self, args: List[str], data: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"))}
        env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C", "LANGUAGE": "C"})
        command = ["git", "-c", "safe.directory=*", "-c", "core.quotepath=false", "-C", str(self.path), *args]
        try:
            result = subprocess.run(command, input=data, capture_output=True, env=env, timeout=600)
        except FileNotFoundError:
            raise OxidizedError("the 'git' executable was not found") from None
        except subprocess.TimeoutExpired:
            raise OxidizedError(f"git {args[0]} timed out in {self.path}") from None
        if check and result.returncode != 0:
            message = (result.stderr or result.stdout).decode("utf-8", "replace").strip()
            raise OxidizedError(f"git {' '.join(args[:2])} failed in {self.path}: {message}")
        return result

    def text(self, *args: str, check: bool = True) -> str:
        return self._run(list(args), check=check).stdout.decode("utf-8", "replace")

    def head(self) -> Optional[str]:
        return self.text("rev-parse", "--verify", "--quiet", "HEAD^{commit}", check=False).strip() or None

    def has_commit(self, sha: str) -> bool:
        return self._run(["cat-file", "-e", f"{sha}^{{commit}}"], check=False).returncode == 0

    def files(self, rev: str = "HEAD") -> Dict[str, str]:
        """Path -> blob id of every file at ``rev``."""
        found: Dict[str, str] = {}
        for line in self.text("ls-tree", "-r", rev).splitlines():
            meta, _, path = line.partition("\t")
            parts = meta.split()
            if len(parts) == 3 and parts[1] == "blob":
                found[path] = parts[2]
        return found

    def blobs(self, rev: str, paths: List[str]) -> Dict[str, str]:
        """Contents of several files at ``rev``, with one git process."""
        if not paths:
            return {}
        data = self._run(["cat-file", "--batch"], "".join(f"{rev}:{path}\n" for path in paths).encode("utf-8")).stdout
        contents: Dict[str, str] = {}
        position = 0
        for path in paths:
            end = data.index(b"\n", position)
            header = data[position:end].decode("utf-8", "replace").split()
            position = end + 1
            if len(header) != 3:  # "<name> missing"
                continue
            size = int(header[2])
            contents[path] = data[position:position + size].decode("utf-8", "replace")
            position += size + 1
        return contents

    def commit_time(self, rev: str) -> float:
        return float(self.text("log", "-1", "--format=%ct", rev).strip() or time.time())

    def commits(self, since: str) -> List[Commit]:
        """Commits after ``since`` up to HEAD, oldest first, with the files each one touched."""
        raw = self.text("log", "--reverse", "--no-renames", "--format=%x1e%H%x1f%an%x1f%ae%x1f%ct%x1f%s", "--name-status", f"{since}..HEAD")
        commits: List[Commit] = []
        for record in raw.split("\x1e"):
            lines = [line for line in record.splitlines() if line.strip()]
            if not lines:
                continue
            fields = (lines[0].split("\x1f") + [""] * 5)[:5]
            commit = Commit(fields[0], fields[1], fields[2], float(fields[3] or 0), fields[4])
            for line in lines[1:]:
                status, _, path = line.partition("\t")
                if path:
                    commit.files.append((status[:1], path))
            commits.append(commit)
        return commits


def _is_repo(path: Path) -> bool:
    return (path / ".git").exists() or ((path / "HEAD").is_file() and (path / "objects").is_dir())


def repositories(path: Path) -> List[Tuple[str, Path]]:
    """``(group, repository)``: the repository itself, or every repository in a folder (one per group)."""
    if not path.exists():
        raise OxidizedError(f"Oxidized repository {path} does not exist")
    if _is_repo(path):
        return [("", path)]
    found = sorted(child for child in path.iterdir() if child.is_dir() and _is_repo(child))
    if not found:
        raise OxidizedError(f"no git repository at {path}")
    return [(re.sub(r"\.git$", "", child.name), child) for child in found]


def read_router_db(path: Path, delimiter: str = ":") -> Dict[str, str]:
    """Node name -> model from Oxidized's CSV source (``name:model[:...]``)."""
    models: Dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ConfigError(f"cannot read Oxidized router.db {path}: {exc}") from exc
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = [part.strip() for part in line.split(delimiter)]
        if len(parts) >= 2 and parts[0]:
            models[parts[0]] = parts[1]
    return models


# --------------------------------------------------------------------------- nodes and devices


@dataclass
class Node:
    name: str
    group: str = ""
    model: str = ""
    ip: str = ""
    path: str = ""  # file in the repository (repo mode)
    repo: str = ""  # repository (repo mode)
    blob: str = ""  # blob id at HEAD (repo mode)
    status: str = ""  # last fetch status (api mode)
    stamp: str = ""  # last change marker (api mode)

    @property
    def full_name(self) -> str:
        return f"{self.group}/{self.name}" if self.group else self.name


_GUESSES: Dict[str, Optional[str]] = {}  # blob id -> guessed platform


def _repo_nodes(source: InventorySource, settings: Settings) -> List[Node]:
    models = read_router_db(settings.resolve_path(source.router_db), source.router_db_delimiter) if source.router_db else {}
    nodes: List[Node] = []
    for group, repo in repositories(settings.resolve_path(source.path or "")):
        reader = GitReader(repo)
        if reader.head() is None:
            continue
        files = reader.files()
        unknown = [p for p, blob in files.items() if not models.get(p.rsplit("/", 1)[-1]) and blob not in _GUESSES]
        for path, text in reader.blobs("HEAD", unknown).items():
            _GUESSES[files[path]] = guess_platform(text)
        for path, blob in files.items():
            name = path.rsplit("/", 1)[-1]
            if name.startswith("."):
                continue
            node_group = path.split("/", 1)[0] if "/" in path else group
            if source.groups and node_group not in source.groups:
                continue
            nodes.append(Node(name, node_group, models.get(name, ""), path=path, repo=str(repo), blob=blob))
    return nodes


def _session(source: InventorySource) -> Any:
    import requests

    session = requests.Session()
    session.headers.update({"Accept": "application/json", "User-Agent": "netledger"})
    if source.username:
        session.auth = (source.username, source.password or "")
    return session


def _get(session: Any, source: InventorySource, path: str, **params: Any) -> Any:
    import requests

    url = (source.url or "").rstrip("/") + path
    try:
        response = session.get(url, params=params or None, timeout=source.timeout, verify=source.verify_ssl)
        response.raise_for_status()
    except requests.RequestException as exc:
        raise OxidizedError(f"Oxidized API {url}: {exc}") from exc
    return response


def _api_nodes(source: InventorySource, session: Any = None) -> List[Node]:
    session = session or _session(source)
    data = _get(session, source, "/nodes.json").json()
    nodes: List[Node] = []
    for item in data if isinstance(data, list) else []:
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        group = str(item.get("group") or "")
        group = "" if group == "default" else group
        if source.groups and group not in source.groups:
            continue
        last = item.get("last") if isinstance(item.get("last"), dict) else {}
        status = str(last.get("status") or item.get("status") or "")
        stamp = str(item.get("mtime") or last.get("end") or item.get("time") or "")
        nodes.append(Node(name, group, str(item.get("model") or ""), str(item.get("ip") or ""), status=status, stamp=stamp))
    return nodes


_NODES: Dict[Tuple[str, str], List[Node]] = {}  # (config folder, source key) -> nodes of the last successful read


def load_oxidized_inventory(source: InventorySource, settings: Settings) -> List[Any]:
    """Devices for every Oxidized node: configurations come from Oxidized, health is off unless enabled.

    When Oxidized cannot be read but was read before in this process, its last known nodes are used, so an
    oxidized-web outage neither stops NetLedger's other backups nor makes those devices look removed.
    """
    from netledger.inventory import build_device

    try:
        nodes = _repo_nodes(source, settings) if source.mode == "repo" else _api_nodes(source)
        _NODES[(str(settings.base_dir), source.key)] = nodes
    except OxidizedError as exc:
        if (str(settings.base_dir), source.key) not in _NODES:
            raise ConfigError(str(exc)) from exc
        log.warning("%s; using the nodes it had before", exc)
        nodes = _NODES[(str(settings.base_dir), source.key)]
    devices = []
    seen: set[str] = set()
    for node in nodes:
        name = node.name if node.name not in seen else f"{node.group}-{node.name}"
        seen.add(name)
        override = dict(source.devices.get(name) or source.devices.get(node.name) or {})
        platform = map_model(node.model, source.platform_map) or _GUESSES.get(node.blob) or "generic"
        if node.model and not map_model(node.model, source.platform_map) and not override.get("platform"):
            log.info("Oxidized model %r of %s has no NetLedger platform; using %s (set platform_map)", node.model, name, platform)
        raw = deep_merge({"health": False}, source.defaults)
        raw = deep_merge(raw, {"name": name, "host": node.ip or node.name, "platform": platform})
        raw["groups"] = unique(list(raw.get("groups") or []) + ([node.group] if node.group else []))
        raw = deep_merge(raw, override)
        if raw.get("enabled", True) is False:
            continue
        raw.pop("enabled", None)
        device = build_device(raw, f"oxidized:{name}")
        device.source = source.key
        device.risk_origin = name if "multiplier" in (override.get("risk") or {}) else "defaults" if "multiplier" in (source.defaults.get("risk") or {}) else ""
        device.collector = "oxidized"
        device.oxidized = {
            "source": source.key, "node": node.name, "group": node.group, "full_name": node.full_name,
            "model": node.model, "path": node.path, "repo": node.repo,
        }
        devices.append(device)
    return devices


# --------------------------------------------------------------------------- reading new configurations


@dataclass
class Version:
    """One configuration version of one device, to process as a backup."""

    device: str
    text: str
    timestamp: float
    author: Optional[str] = None
    ref: str = ""
    quiet: bool = False  # first sight of this node: record it, but do not report it as a change


@dataclass
class Batch:
    versions: List[Version] = field(default_factory=list)
    failures: List[Tuple[str, str]] = field(default_factory=list)  # (device, error)
    cursor: Dict[str, Any] = field(default_factory=dict)


def _author(source: InventorySource, name: str | None, email: str | None = None) -> Optional[str]:
    if not source.use_commit_author or not name:
        return None
    if name.strip().lower() in GENERIC_AUTHORS or (email or "").strip().lower() in GENERIC_AUTHORS:
        return None
    return name.strip()


def _timestamp(value: Any) -> Optional[float]:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    try:
        return float(text)
    except ValueError:
        pass
    text = re.sub(r"\s+UTC$", "+00:00", text)
    text = re.sub(r"\s*([+-]\d{2}):?(\d{2})$", r"\1:\2", text)
    try:
        parsed = datetime.fromisoformat(text.replace(" ", "T", 1))
    except ValueError:
        return None
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).timestamp()


def _read_repo(source: InventorySource, settings: Settings, devices: List[Any], cursor: Dict[str, Any]) -> Batch:
    wanted = {(d.oxidized.get("repo"), d.oxidized.get("path")): d.name for d in devices}
    seen = dict(cursor.get("repos") or {})
    batch = Batch(cursor={"repos": dict(seen)})
    for _, repo in repositories(settings.resolve_path(source.path or "")):
        reader = GitReader(repo)
        head = reader.head()
        key = str(repo)
        if head is None:
            continue
        since = seen.get(key)
        if since and not reader.has_commit(since):
            log.warning("Oxidized repository %s no longer contains commit %s; reading it from scratch", repo, since[:12])
            since = None
        if since is None:  # first look at this repository: today's configuration of every node, quietly
            paths = [path for (where, path) in wanted if where == key]
            when = reader.commit_time(head)
            for path, text in reader.blobs(head, paths).items():
                batch.versions.append(Version(wanted[(key, path)], text, when, None, head, quiet=True))
        elif since != head:
            for commit in reader.commits(since):
                changed = [path for status, path in commit.files if status != "D" and (key, path) in wanted]
                author = _author(source, commit.author, commit.email)
                for path, text in reader.blobs(commit.sha, changed).items():
                    batch.versions.append(Version(wanted[(key, path)], text, commit.time, author, commit.sha))
        batch.cursor["repos"][key] = head
    batch.versions.sort(key=lambda v: v.timestamp)
    return batch


def _latest_version(data: Any) -> Tuple[Optional[str], Optional[str], Optional[float], str]:
    """(author, email, time, oid) of the newest entry of ``/node/version.json``."""
    entries = data if isinstance(data, list) else (data or {}).get("versions") if isinstance(data, dict) else []
    entries = [e for e in entries or [] if isinstance(e, dict)]
    if not entries:
        return None, None, None, ""

    def when(entry: Dict[str, Any]) -> float:
        author = entry.get("author") if isinstance(entry.get("author"), dict) else {}
        return _timestamp(entry.get("time") or entry.get("date") or author.get("time")) or 0.0

    latest = max(entries, key=when)
    author = latest.get("author")
    name = author.get("name") if isinstance(author, dict) else author
    email = author.get("email") if isinstance(author, dict) else None
    return (str(name) if name else None), email, (when(latest) or None), str(latest.get("oid") or "")


def _read_api(source: InventorySource, devices: List[Any], cursor: Dict[str, Any]) -> Batch:
    session = _session(source)
    by_node = {d.oxidized.get("full_name") or d.oxidized.get("node"): d for d in devices}
    known = dict(cursor.get("nodes") or {})
    batch = Batch(cursor={"nodes": dict(known)})
    for node in _api_nodes(source, session):
        device = by_node.get(node.full_name)
        if device is None:
            continue
        if node.status.lower() in FAILED:
            batch.failures.append((device.name, f"Oxidized could not fetch the configuration ({node.status})"))
            continue
        previous = known.get(node.full_name) or {}
        if node.stamp and previous.get("stamp") == node.stamp:
            continue  # nothing new since the last poll
        fetch = f"/node/fetch/{quote(node.group, safe='')}/{quote(node.name, safe='')}" if node.group else f"/node/fetch/{quote(node.name, safe='')}"
        try:
            text = _get(session, source, fetch).text
        except OxidizedError as exc:
            batch.failures.append((device.name, str(exc)))
            continue
        author = email = None
        when: Optional[float] = None
        oid = ""
        try:
            author, email, when, oid = _latest_version(_get(session, source, "/node/version.json", node_full=node.full_name).json())
        except (OxidizedError, ValueError):
            pass  # versions need Oxidized's git output; without them the poll time stands in
        if oid and previous.get("oid") == oid:
            batch.cursor["nodes"][node.full_name] = {**previous, "stamp": node.stamp}
            continue
        stamp = when or _timestamp(node.stamp) or time.time()
        batch.versions.append(Version(device.name, text, stamp, _author(source, author, email), oid, quiet=not previous))
        batch.cursor["nodes"][node.full_name] = {"stamp": node.stamp, "oid": oid}
    batch.versions.sort(key=lambda v: v.timestamp)
    return batch


def read_versions(source: InventorySource, settings: Settings, devices: List[Any], cursor: Dict[str, Any]) -> Batch:
    """New configuration versions of ``devices`` since ``cursor`` (oldest first), and the cursor after them."""
    if source.mode == "repo":
        return _read_repo(source, settings, devices, cursor)
    return _read_api(source, devices, cursor)


def oxidized_sources(settings: Settings) -> List[InventorySource]:
    return [source for source in settings.inventory_sources if source.type == "oxidized"]
