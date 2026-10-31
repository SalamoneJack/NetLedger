"""Palo Alto Networks PAN-OS driver (SSH CLI)."""

from __future__ import annotations

import re
from typing import Any

from netledger.drivers.base import CLIDriver, add_fan, add_psu, add_temperature, set_cpu, set_memory
from netledger.drivers.parsing import parse_duration, parse_kv, parse_top


def parse_system_info(text: str) -> dict[str, Any]:
    kv = parse_kv(text)
    return {
        "hostname": kv.get("hostname", ""),
        "model": kv.get("model", ""),
        "serial_number": kv.get("serial", ""),
        "os_version": kv.get("sw-version", ""),
        "uptime": parse_duration(kv.get("uptime")),
    }


def parse_environmentals(text: str) -> dict[str, dict[str, Any]]:
    """Parse ``show system environmentals`` thermal, fan and power-supply tables."""
    result: dict[str, dict[str, Any]] = {"temperature": {}, "fans": {}, "power": {}}
    current = ""
    for line in text.splitlines():
        stripped = line.strip()
        heading = re.match(r"^-{2,}\s*(.+?)\s*-{2,}$", stripped)
        if heading:
            current = heading.group(1).lower()
            continue
        if not stripped or stripped.lower().startswith("slot"):
            continue
        if "thermal" in current:
            match = re.match(r"^(\S+)\s+(.+?)\s+(True|False)\s+(-?[\d.]+)\s+(-?[\d.]+)\s+(-?[\d.]+)$", stripped)
            if match:
                temp, maximum = float(match.group(4)), float(match.group(6))
                result["temperature"][match.group(2)] = {
                    "temperature": temp,
                    "alert": match.group(3) == "True",
                    "critical": maximum > 0 and temp >= maximum,
                }
        elif "fan" in current:
            match = re.match(r"^(\S+)\s+(.+?)\s+(True|False)\s+(\d+)(?:\s+(\d+))?$", stripped)
            if match:
                result["fans"][match.group(2)] = {"status": match.group(3) == "False"}
        elif "suppl" in current:
            match = re.match(r"^(\S+)\s+(.+?)\s+(True|False)\s+(True|False)$", stripped)
            if match and match.group(3) == "True":
                result["power"][match.group(2)] = {"status": match.group(4) == "False"}
    return result


class PANOSDriver(CLIDriver):
    platform = "panos"
    vendor = "Palo Alto Networks"
    netmiko_device_type = "paloalto_panos"
    config_command = "show config running"
    error_patterns = (r"^Invalid syntax", r"^Unknown command", r"^Server error", r"is not a valid")

    def _after_open(self) -> None:
        output_format = str(self.optional_args.get("config_format", "set")).lower()
        if output_format in ("set", "xml", "json"):
            self._try(f"set cli config-output-format {output_format}")

    def _facts(self) -> dict[str, Any]:
        return parse_system_info(self._send("show system info", use_cache=True))

    def _environment(self, env: dict[str, Any]) -> None:
        cpu, total, used = parse_top(self._try("show system resources") or "")
        if cpu is not None:
            set_cpu(env, [cpu])
        set_memory(env, total, used)
        parsed = parse_environmentals(self._try("show system environmentals") or "")
        for name, temp in parsed["temperature"].items():
            add_temperature(env, name, temp["temperature"], alert=temp["alert"], critical=temp["critical"])
        for name, fan in parsed["fans"].items():
            add_fan(env, name, fan["status"])
        for name, psu in parsed["power"].items():
            add_psu(env, name, psu["status"])
