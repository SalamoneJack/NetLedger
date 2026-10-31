"""Dell EMC SmartFabric OS10 driver."""

from __future__ import annotations

import re
from typing import Any

from netledger.drivers.base import CLIDriver, add_fan, add_psu, add_temperature, set_cpu, set_memory
from netledger.drivers.parsing import parse_duration, parse_kv, parse_top, search, section


def parse_os10_version(text: str) -> dict[str, Any]:
    kv = parse_kv(text)
    return {
        "os_version": kv.get("OS Version", ""),
        "model": kv.get("System Type", ""),
        "uptime": parse_duration(kv.get("Up Time")),
    }


def parse_os10_inventory(text: str) -> str:
    serial = search(r"^Product Serial Number\s*:\s*(\S+)", text)
    if serial:
        return serial
    return search(r"^\*?\s*1\s+\S+\s+\S+\s+\S+\s+\S+\s+([A-Z0-9]{7})\b", text) or ""


def parse_os10_thermal(text: str) -> dict[str, float]:
    temps: dict[str, float] = {}
    block = section(text, r"Thermal sensors") or text
    for match in re.finditer(r"^\s*(\d+)\s+(\d+)\s+(.+?)\s+(-?\d+(?:\.\d+)?)\s*$", block, re.M):
        temps[f"Unit {match.group(1)} {match.group(3).strip()}"] = float(match.group(4))
    return temps


def parse_os10_system(text: str) -> dict[str, dict[str, bool]]:
    result: dict[str, dict[str, bool]] = {"power": {}, "fans": {}}
    for label, key, prefix in (("Power Supplies", "power", "PSU"), ("Fan Status", "fans", "Fan tray")):
        block = section(text, rf"^--\s*{label}\s*--", r"^--\s+\w")
        for match in re.finditer(r"^\s*(\d+)\s+(up|down|fail|failed|absent|not-present|present)\b", block, re.M | re.I):
            state = match.group(2).lower()
            if state in ("absent", "not-present"):
                continue
            result[key][f"{prefix} {match.group(1)}"] = state in ("up", "present")
    return result


class OS10Driver(CLIDriver):
    platform = "dellos10"
    vendor = "Dell"
    netmiko_device_type = "dell_os10"
    config_command = "show running-configuration"
    startup_command = "show startup-configuration"
    error_patterns = (r"% Error:", r"Unrecognized command", r"Incomplete command")

    def _facts(self) -> dict[str, Any]:
        facts = parse_os10_version(self._send("show version", use_cache=True))
        facts["serial_number"] = parse_os10_inventory(self._try("show inventory") or "")
        return facts

    def _environment(self, env: dict[str, Any]) -> None:
        cpu, total, used = parse_top(self._try("show processes node-id 1") or "")
        if cpu is not None:
            set_cpu(env, [cpu])
        set_memory(env, total, used)
        for name, value in parse_os10_thermal(self._try("show environment") or "").items():
            add_temperature(env, name, value)
        system = parse_os10_system(self._try("show system") or "")
        for name, ok in system["fans"].items():
            add_fan(env, name, ok)
        for name, ok in system["power"].items():
            add_psu(env, name, ok)
