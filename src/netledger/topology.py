"""Network map from LLDP: inventory devices plus the neighbors they report, links de-duplicated.

A link only needs to be seen from one side, so devices whose drivers cannot read LLDP (or that are
down) still appear connected through their neighbors' tables.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Callable

FIREWALL_PLATFORMS = {"fortios", "panos", "asa", "gaia"}
ROUTER_PLATFORMS = {"routeros", "iosxr", "iosxr_netconf", "vyos", "edgeos"}
WIRELESS_PLATFORMS = {"aireos"}
_PORT_ABBREVIATIONS = (
    ("twentyfivegige", "twe"), ("hundredgige", "hu"), ("fortygigabitethernet", "fo"), ("tengigabitethernet", "te"),
    ("twogigabitethernet", "tw"), ("fivegigabitethernet", "fi"), ("gigabitethernet", "gi"), ("fastethernet", "fa"),
    ("port-channel", "po"), ("ethernet", "eth"), ("management", "mgmt"),
)


def norm_port(name: str | None) -> str:
    value = re.sub(r"\s+", "", (name or "").lower())
    for long, short in _PORT_ABBREVIATIONS:
        if value.startswith(long):
            return short + value[len(long):]
    return value


def norm_host(name: str | None) -> str:
    value = (name or "").strip().lower()
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        return value.split(".")[0]


def device_kind(info: dict[str, Any]) -> str:
    role = (info.get("role") or "").lower()
    platform = info.get("platform") or ""
    if re.search(r"fw|firewall|security|utm", role):
        return "firewall"
    if re.search(r"rtr|router|edge|wan|border|gateway", role):
        return "router"
    if re.search(r"\bap\b|wireless|wlc|wifi", role):
        return "wireless"
    if platform in FIREWALL_PLATFORMS:
        return "firewall"
    if platform in ROUTER_PLATFORMS:
        return "router"
    if platform in WIRELESS_PLATFORMS:
        return "wireless"
    return "switch"


def normalize_lldp(raw: dict[str, Any] | None) -> list[dict[str, str]]:
    """NAPALM ``get_lldp_neighbors()`` output as a flat, sorted list."""
    neighbors = []
    for port, entries in (raw or {}).items():
        for entry in entries or []:
            remote = str(entry.get("hostname") or entry.get("remote_system_name") or "").strip()
            if remote:
                neighbors.append({"port": str(port), "remote": remote, "remote_port": str(entry.get("port") or entry.get("remote_port") or "")})
    return sorted(neighbors, key=lambda n: (n["port"], n["remote"]))


def build_topology(
    rows: list[dict[str, Any]],
    status_of: Callable[[dict[str, Any]], str],
    max_external: int = 4,
) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    aliases: dict[str, str] = {}
    for row in rows:
        info, facts = row["info"], row["facts"]
        name = row["name"]
        change = row.get("last_change") or {}
        nodes[name] = {
            "id": name,
            "label": name,
            "site": info.get("site") or "",
            "kind": device_kind(info),
            "platform": info.get("platform") or "",
            "platform_name": info.get("platform_name") or info.get("platform") or "",
            "vendor": info.get("vendor") or facts.get("vendor") or "",
            "model": facts.get("model") or "",
            "host": info.get("host") or "",
            "status": status_of(row),
            "external": False,
            "change_ts": change.get("ts"),
            "change_risk": change.get("risk"),
            "unsaved": bool(row["backup"].get("unsaved_changes")),
        }
        for alias in (name, facts.get("hostname"), info.get("host")):
            if alias:
                aliases.setdefault(norm_host(alias), name)

    links: dict[frozenset[tuple[str, str]], dict[str, Any]] = {}
    for row in rows:
        local = row["name"]
        externals = 0
        for neighbor in (row["health"].get("neighbors") or []):
            remote_name = neighbor.get("remote") or ""
            target = aliases.get(norm_host(remote_name))
            if target == local:
                continue
            if target is None:
                ext_id = "ext:" + norm_host(remote_name)
                if ext_id not in nodes:
                    if externals >= max_external:
                        continue
                    externals += 1
                    nodes[ext_id] = {
                        "id": ext_id, "label": remote_name.split(".")[0], "site": nodes[local]["site"], "kind": "host",
                        "platform": "", "platform_name": "Discovered via LLDP", "vendor": "", "model": "", "host": "",
                        "status": "external", "external": True, "change_ts": None, "change_risk": None, "unsaved": False,
                    }
                target = ext_id
            key = frozenset({(local, norm_port(neighbor.get("port"))), (target, norm_port(neighbor.get("remote_port")))})
            if key in links:
                links[key]["seen"] = 2
                continue
            links[key] = {
                "source": local,
                "target": target,
                "source_port": neighbor.get("port") or "",
                "target_port": neighbor.get("remote_port") or "",
                "seen": 1,
            }
    degree: dict[str, int] = {}
    for link in links.values():
        for end in (link["source"], link["target"]):
            degree[end] = degree.get(end, 0) + 1
        statuses = {nodes[link["source"]]["status"], nodes[link["target"]]["status"]}
        link["status"] = "down" if "critical" in statuses else "warn" if "warning" in statuses else "ok"
    for node in nodes.values():
        node["degree"] = degree.get(node["id"], 0)
    sites = sorted({n["site"] for n in nodes.values()}, key=lambda s: (s == "", s))
    return {
        "nodes": sorted(nodes.values(), key=lambda n: (n["site"], n["external"], n["id"])),
        "links": sorted(links.values(), key=lambda link: (link["source"], link["target"])),
        "sites": sites,
        "lldp": any(row["health"].get("neighbors") for row in rows),
    }
