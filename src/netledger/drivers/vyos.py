"""VyOS and Ubiquiti EdgeOS drivers.

Both run a Linux shell in operational mode, so health data comes from ``/proc`` and ``top``
which are stable across releases.
"""

from __future__ import annotations

from typing import Any

from netledger.drivers.base import CLIDriver, add_temperature, set_cpu, set_memory
from netledger.drivers.parsing import parse_kv, parse_meminfo, parse_top, search, to_float


def parse_proc_uptime(text: str) -> float | None:
    value = search(r"^\s*([\d.]+)\s", text or "")
    return float(value) if value is not None else None


def parse_thermal_zones(text: str) -> dict[str, float]:
    temps: dict[str, float] = {}
    for index, line in enumerate(row for row in (text or "").splitlines() if row.strip()):
        value = to_float(line)
        if value is None:
            continue
        temps[f"thermal_zone{index}"] = value / 1000 if value > 1000 else value
    return temps


class VyOSDriver(CLIDriver):
    platform = "vyos"
    vendor = "VyOS"
    netmiko_device_type = "vyos"
    config_command = "show configuration commands"
    error_patterns = (r"^Invalid command:", r"is not valid", r"^Incomplete command", r"command not found")

    def _facts(self) -> dict[str, Any]:
        kv = parse_kv(self._send("show version", use_cache=True))
        version = kv.get("Version", "")
        return {
            "os_version": version.replace("VyOS", "").strip() or version,
            "model": kv.get("Hardware model", "") or kv.get("System type", ""),
            "serial_number": kv.get("Hardware S/N", ""),
            "uptime": parse_proc_uptime(self._try("cat /proc/uptime") or ""),
        }

    def _environment(self, env: dict[str, Any]) -> None:
        cpu, _, _ = parse_top(self._try("top -b -n 1 | head -n 5") or "")
        if cpu is not None:
            set_cpu(env, [cpu])
        set_memory(env, *parse_meminfo(self._try("cat /proc/meminfo") or ""))
        zones = self._try("cat /sys/class/thermal/thermal_zone*/temp 2>/dev/null") or ""
        for name, value in parse_thermal_zones(zones).items():
            add_temperature(env, name, value)


class EdgeOSDriver(VyOSDriver):
    platform = "edgeos"
    vendor = "Ubiquiti"
    netmiko_device_type = "ubiquiti_edgerouter"

    def _facts(self) -> dict[str, Any]:
        kv = parse_kv(self._send("show version", use_cache=True))
        return {
            "os_version": kv.get("Version", ""),
            "model": kv.get("HW model", ""),
            "serial_number": kv.get("HW S/N", ""),
            "uptime": parse_proc_uptime(self._try("cat /proc/uptime") or ""),
        }
