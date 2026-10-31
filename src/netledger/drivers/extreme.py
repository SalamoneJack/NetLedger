"""Extreme Networks EXOS / Switch Engine driver."""

from __future__ import annotations

import re
from typing import Any

from netledger.drivers.base import CLIDriver, add_fan, add_psu, add_temperature, set_cpu, set_memory
from netledger.drivers.parsing import parse_duration, parse_kv, search


def parse_exos_switch(text: str) -> dict[str, Any]:
    kv = parse_kv(text)
    booted = kv.get("Image Booted", "primary").lower()
    version = kv.get("Primary ver") if booted.startswith("primary") else kv.get("Secondary ver")
    return {
        "hostname": kv.get("SysName", "").strip('"'),
        "model": kv.get("System Type", ""),
        "os_version": (version or kv.get("Primary ver", "")).split(" ")[0],
        "uptime": parse_duration(kv.get("System UpTime")),
    }


def parse_exos_cpu(text: str) -> float | None:
    match = re.search(r"^\s*(?:\S+\s+)?System\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)", text, re.M)
    return float(match.group(4)) if match else None


def parse_exos_memory(text: str) -> tuple[int | None, int | None]:
    total = search(r"Total DRAM \(KB\):\s*(\d+)", text)
    free = search(r"Free \(KB\):\s*(\d+)", text)
    if total is None or free is None:
        return None, None
    return int(total) * 1024, (int(total) - int(free)) * 1024


def parse_exos_temperature(text: str) -> dict[str, tuple[float, str, float | None]]:
    temps: dict[str, tuple[float, str, float | None]] = {}
    pattern = re.compile(
        r"^\s*(?P<name>\S[^:\n]*?)\s*:\s*\S+\s+(?P<temp>-?\d+(?:\.\d+)?)\s+(?P<status>Normal|Warning|Alarm|Error|Critical|Fault)\b"
        r"(?:\s+(?P<min>-?\d+)\s+\S+\s+(?P<max>-?\d+))?",
        re.M,
    )
    for match in pattern.finditer(text):
        maximum = float(match.group("max")) if match.group("max") else None
        temps[match.group("name").strip()] = (float(match.group("temp")), match.group("status").lower(), maximum)
    return temps


def parse_exos_fans(text: str) -> dict[str, bool]:
    fans: dict[str, bool] = {}
    prefix = ""
    for line in text.splitlines():
        header = re.match(r"^\s*(.*?)\s*information:\s*$", line, re.I)
        if header:
            prefix = header.group(1).replace("FanTray", "").strip()
            continue
        match = re.match(r"^\s*(Fan-\d+):\s+(\w+(?: \w+)?)", line)
        if match:
            state = match.group(2).lower()
            if state.startswith("empty"):
                continue
            name = f"{prefix} {match.group(1)}".strip()
            fans[name] = state.startswith("operational")
    return fans


def parse_exos_power(text: str) -> dict[str, bool]:
    psus: dict[str, bool] = {}
    for match in re.finditer(r"^\s*((?:Slot-\d+ )?PowerSupply \d+) information:\s*\n\s*State\s*:\s*(.+?)\s*$", text, re.M):
        state = match.group(2).lower()
        if state.startswith("empty"):
            continue
        psus[match.group(1)] = state.startswith("powered on")
    return psus


class EXOSDriver(CLIDriver):
    platform = "exos"
    vendor = "Extreme Networks"
    netmiko_device_type = "extreme_exos"
    config_command = "show configuration"
    error_patterns = (r"%% Invalid input detected", r"%% Incomplete command", r"%% Unrecognized command", r"^Error:")

    def _facts(self) -> dict[str, Any]:
        facts = parse_exos_switch(self._send("show switch", use_cache=True))
        facts["serial_number"] = search(r"^Switch\s*:\s*\S+\s+(\S+)", self._try("show version") or "") or ""
        return facts

    def _environment(self, env: dict[str, Any]) -> None:
        cpu = parse_exos_cpu(self._try("show cpu-monitoring") or "")
        if cpu is not None:
            set_cpu(env, [cpu])
        set_memory(env, *parse_exos_memory(self._try("show memory") or ""))
        for name, (value, status, maximum) in parse_exos_temperature(self._try("show temperature") or "").items():
            add_temperature(env, name, value, alert=status != "normal", critical=status in ("alarm", "critical", "fault"), crit_at=maximum)
        for name, ok in parse_exos_fans(self._try("show fans") or "").items():
            add_fan(env, name, ok)
        for name, ok in parse_exos_power(self._try("show power") or "").items():
            add_psu(env, name, ok)
