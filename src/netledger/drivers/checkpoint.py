"""Check Point Gaia (clish) driver."""

from __future__ import annotations

import re
from typing import Any

from netledger.drivers.base import CLIDriver, add_fan, add_psu, add_temperature
from netledger.drivers.parsing import parse_duration, search


def parse_gaia_sysenv(text: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {"temperature": {}, "fans": {}, "power": {}}
    pattern = re.compile(
        r"^\s*(?P<name>.+?)\s+(?P<value>-?[\d.]+)\s+(?P<unit>\S+)\s+(?P<type>Voltage|Temperature|Fan|PowerSupply|Power Supply)"
        r"\s+(?P<status>-?\d+)\b(?:\s+(?P<max>-?[\d.]+)\s+(?P<min>-?[\d.]+))?",
        re.M | re.I,
    )
    for match in pattern.finditer(text):
        kind = match.group("type").lower().replace(" ", "")
        ok = match.group("status") == "0"
        name = match.group("name").strip()
        if kind == "temperature":
            maximum = float(match.group("max")) if match.group("max") else None
            result["temperature"][name] = {"temperature": float(match.group("value")), "alert": not ok, "max": maximum}
        elif kind == "fan":
            result["fans"][name] = ok
        elif kind == "powersupply":
            result["power"][name] = ok
    return result


def parse_gaia_uptime(text: str) -> float | None:
    match = re.search(r"\bup\s+(.+?)(?:,\s+\d+\s+users?|,\s+load average|$)", text or "", re.M)
    return parse_duration(match.group(1)) if match else None


class GaiaDriver(CLIDriver):
    platform = "gaia"
    vendor = "Check Point"
    netmiko_device_type = "checkpoint_gaia"
    config_command = "show configuration"
    error_patterns = (r"CLINFR\d+\s+Invalid command", r"^Invalid command", r"Incomplete command")

    def _facts(self) -> dict[str, Any]:
        version = self._try("show version all") or ""
        asset = self._try("show asset all") or ""
        hostname_lines = (self._try("show hostname") or "").strip().splitlines()
        return {
            "hostname": hostname_lines[-1].strip() if hostname_lines else "",
            "os_version": search(r"Product version\s+(.+)$", version) or "",
            "model": search(r"^Platform\s*:\s*(.+)$", asset) or "",
            "serial_number": search(r"^Serial Number\s*:\s*(\S+)", asset) or "",
            "uptime": parse_gaia_uptime(self._try("show uptime") or ""),
        }

    def _environment(self, env: dict[str, Any]) -> None:
        parsed = parse_gaia_sysenv(self._try("show sysenv all") or "")
        for name, temp in parsed["temperature"].items():
            add_temperature(env, name, temp["temperature"], alert=temp["alert"], crit_at=temp["max"] or None)
        for name, ok in parsed["fans"].items():
            add_fan(env, name, ok)
        for name, ok in parsed["power"].items():
            add_psu(env, name, ok)
