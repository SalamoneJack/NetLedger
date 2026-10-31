"""MikroTik RouterOS driver (v6 and v7)."""

from __future__ import annotations

import re
from typing import Any

from netledger.drivers.base import CLIDriver, add_fan, add_psu, add_temperature, set_cpu, set_memory
from netledger.drivers.parsing import parse_duration, parse_size, to_float


def parse_routeros_kv(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for match in re.finditer(r"^\s*([\w-]+):\s*(.*?)\s*$", text, re.M):
        result.setdefault(match.group(1), match.group(2))
    return result


def parse_routeros_health(text: str) -> dict[str, dict[str, Any]]:
    """``/system health print`` for both the v6 key/value and v7 table formats."""
    result: dict[str, dict[str, Any]] = {"temperature": {}, "fans": {}, "power": {}}

    def classify(name: str, value: str, unit: str) -> None:
        lowered = name.lower()
        unit = unit.upper()
        if "temperature" in lowered or unit == "C":
            number = to_float(value)
            if number is not None:
                result["temperature"][name] = number
        elif "fan" in lowered and ("speed" in lowered or unit == "RPM"):
            number = to_float(value.upper().replace("RPM", ""))
            if number is not None:
                result["fans"][name] = number > 0
        elif "fan" in lowered and "state" in lowered:
            result["fans"][name] = value.lower() == "ok"
        elif "psu" in lowered and "state" in lowered:
            result["power"][name] = value.lower() == "ok"

    table = re.findall(r"^\s*\d+\s+([\w-]+)\s+(\S+)(?:\s+(\S+))?\s*$", text, re.M)
    if table:
        for name, value, unit in table:
            classify(name, value, unit or "")
    else:
        for name, value in parse_routeros_kv(text).items():
            match = re.match(r"^(-?[\d.]+)\s*([A-Za-z]*)$", value)
            if match:
                classify(name, match.group(1), match.group(2))
            else:
                classify(name, value, "")
    return result


class RouterOSDriver(CLIDriver):
    platform = "routeros"
    vendor = "MikroTik"
    netmiko_device_type = "mikrotik_routeros"
    config_command = "/export terse"
    full_config_command = "/export terse verbose"
    error_patterns = (r"bad command name", r"expected end of command", r"syntax error", r"no such item", r"input does not match")

    def _after_open(self) -> None:
        if self.optional_args.get("show_sensitive") and self.config_command.startswith("/export"):
            resource = parse_routeros_kv(self._send("/system resource print", use_cache=True))
            if resource.get("version", "").startswith("7"):
                self.config_command += " show-sensitive"
                if self.full_config_command:
                    self.full_config_command += " show-sensitive"

    def _facts(self) -> dict[str, Any]:
        resource = parse_routeros_kv(self._send("/system resource print", use_cache=True))
        identity = parse_routeros_kv(self._try("/system identity print") or "")
        board = parse_routeros_kv(self._try("/system routerboard print") or "")
        version = resource.get("version", "")
        return {
            "hostname": identity.get("name", ""),
            "model": board.get("model") or resource.get("board-name", ""),
            "os_version": version.split(" ")[0] if version else "",
            "serial_number": board.get("serial-number", ""),
            "uptime": parse_duration(resource.get("uptime")),
        }

    def _environment(self, env: dict[str, Any]) -> None:
        resource = parse_routeros_kv(self._send("/system resource print", use_cache=True))
        load = to_float(resource.get("cpu-load"))
        if load is not None:
            set_cpu(env, [load])
        total = parse_size(resource.get("total-memory"))
        free = parse_size(resource.get("free-memory"))
        if total and free is not None:
            set_memory(env, total, total - free)
        health = parse_routeros_health(self._try("/system health print") or "")
        for name, value in health["temperature"].items():
            add_temperature(env, name, value)
        for name, ok in health["fans"].items():
            add_fan(env, name, ok)
        for name, ok in health["power"].items():
            add_psu(env, name, ok)
