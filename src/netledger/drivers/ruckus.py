"""Ruckus ICX / Brocade FastIron driver."""

from __future__ import annotations

import re
from typing import Any

from netledger.drivers.base import (
    GENERIC_ERRORS,
    CLIDriver,
    add_fan,
    add_psu,
    add_temperature,
    set_cpu,
    set_memory,
)
from netledger.drivers.parsing import parse_duration, search


def parse_fastiron_version(text: str) -> dict[str, Any]:
    return {
        "os_version": search(r"SW: Version (\S+)", text) or "",
        "model": search(r"HW: (?:Stackable )?(.+?)\s*$", text) or "",
        "serial_number": search(r"Serial\s*#:\s*(\S+)", text) or "",
        "uptime": parse_duration(search(r"uptime is (.+?)\s*$", text)),
    }


def parse_fastiron_cpu(text: str) -> float | None:
    value = search(r"60\s+sec avg:\s*(\d+) percent busy", text) or search(r"(\d+) percent busy", text)
    return float(value) if value is not None else None


def parse_fastiron_memory(text: str) -> tuple[int | None, int | None]:
    totals = re.findall(r"Dynamic memory:\s*(\d+) bytes total,\s*(\d+) bytes free", text)
    if not totals:
        return None, None
    total = sum(int(t) for t, _ in totals)
    free = sum(int(f) for _, f in totals)
    return total, total - free


def parse_fastiron_chassis(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {"power": {}, "fans": {}, "temperature": {}, "warn": None, "shutdown": None}
    unit = ""
    sensor = "Chassis"
    for line in text.splitlines():
        match = re.search(r"stack unit (\d+) chassis info", line, re.I)
        if match:
            unit = f"Unit {match.group(1)} "
            continue
        match = re.match(r"^\s*Power supply (\d+)(?: \([^)]*\))?\s+(.*)$", line, re.I)
        if match:
            rest = match.group(2).lower()
            if "not present" not in rest:
                result["power"][f"{unit}PSU {match.group(1)}"] = "status ok" in rest
            continue
        match = re.match(r"^\s*Fan (\d+) (ok|failed|bad|not present)\b", line, re.I)
        if match:
            if match.group(2).lower() != "not present":
                result["fans"][f"{unit}Fan {match.group(1)}"] = match.group(2).lower() == "ok"
            continue
        match = re.match(r"^\s*(.+?) Temperature Readings:", line, re.I)
        if match:
            sensor = match.group(1).strip()
            continue
        match = re.search(r"Current temperature\s*:\s*(-?[\d.]+)\s*deg-C", line, re.I)
        if match:
            result["temperature"][f"{unit}{sensor}".strip()] = float(match.group(1))
            continue
        match = re.search(r"Warning level\.*:\s*([\d.]+)\s*deg-C,\s*shutdown level:\s*([\d.]+)", line, re.I)
        if match:
            result["warn"], result["shutdown"] = float(match.group(1)), float(match.group(2))
    return result


class FastIronDriver(CLIDriver):
    platform = "fastiron"
    vendor = "Ruckus"
    netmiko_device_type = "ruckus_fastiron"
    config_command = "show running-config"
    startup_command = "show configuration"
    needs_enable = True
    error_patterns = (*GENERIC_ERRORS, r"Invalid input ->", r"^Error -")

    def _facts(self) -> dict[str, Any]:
        return parse_fastiron_version(self._send("show version", use_cache=True))

    def _environment(self, env: dict[str, Any]) -> None:
        cpu = parse_fastiron_cpu(self._try("show cpu-utilization") or "")
        if cpu is not None:
            set_cpu(env, [cpu])
        set_memory(env, *parse_fastiron_memory(self._try("show memory") or ""))
        chassis = parse_fastiron_chassis(self._try("show chassis") or "")
        for name, value in chassis["temperature"].items():
            add_temperature(env, name, value, warn_at=chassis["warn"], crit_at=chassis["shutdown"])
        for name, ok in chassis["fans"].items():
            add_fan(env, name, ok)
        for name, ok in chassis["power"].items():
            add_psu(env, name, ok)
