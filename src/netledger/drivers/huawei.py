"""Huawei VRP driver."""

from __future__ import annotations

import re
from typing import Any

from netledger.drivers.base import CLIDriver, add_fan, add_psu, add_temperature, set_cpu, set_memory
from netledger.drivers.parsing import parse_duration, search

_STATUS_WORDS = r"NORMAL|ABNORMAL|Normal|Abnormal|MINOR|MAJOR|FATAL|Minor|Major|Fatal"


def parse_vrp_version(text: str) -> dict[str, Any]:
    facts: dict[str, Any] = {}
    match = re.search(r"VRP \(R\) software, Version (\S+)(?:\s+\((?P<model>\S+)\s+(?P<release>[^)]+)\))?", text)
    if match:
        facts["os_version"] = match.group("release") or match.group(1)
        if match.group("model"):
            facts["model"] = match.group("model")
    match = re.search(r"^\s*(?:HUAWEI|Huawei|Quidway)\s+(?P<model>\S+).*?\buptime is (?P<uptime>.+?)\s*$", text, re.M)
    if match:
        facts["model"] = match.group("model")
        facts["uptime"] = parse_duration(match.group("uptime"))
    return facts


def parse_vrp_cpu(text: str) -> float | None:
    value = (
        search(r"CPU utilization for five seconds:\s*\d+%:?\s*one minute:\s*(\d+)%", text)
        or search(r"CPU Usage\s*:\s*(\d+)%", text)
        or search(r"CPU utilization for five seconds:\s*(\d+)%", text)
    )
    return float(value) if value is not None else None


def parse_vrp_memory(text: str) -> tuple[int | None, int | None, float | None]:
    def amount(label: str) -> int | None:
        match = re.search(rf"{label}\s*:?\s*(\d+)\s*(bytes|Kbytes|kbytes|KB|MB)?", text, re.I)
        if not match:
            return None
        factor = {"kbytes": 1024, "kb": 1024, "mb": 1024**2}.get((match.group(2) or "").lower(), 1)
        return int(match.group(1)) * factor

    total = amount(r"System Total Memory Is")
    used = amount(r"Total Memory Used Is")
    percent = search(r"Memory Using Percentage Is\s*:?\s*(\d+)%", text)
    return total, used, float(percent) if percent is not None else None


def parse_vrp_temperature(text: str) -> dict[str, tuple[float, bool]]:
    temps: dict[str, tuple[float, bool]] = {}
    pattern = re.compile(rf"^\s*(?P<slot>\S+)\s+(?P<rest>.*?)\b(?P<status>{_STATUS_WORDS})\s+(?P<cur>-?\d+)\b", re.M)
    for match in pattern.finditer(text):
        rest = " ".join(t for t in match.group("rest").split() if t.upper() != "NA")
        name = f"Slot {match.group('slot')}" + (f" {rest}" if rest else "")
        temps[name] = (float(match.group("cur")), match.group("status").upper() != "NORMAL")
    return temps


def parse_vrp_fans(text: str) -> dict[str, bool]:
    fans: dict[str, bool] = {}
    pattern = re.compile(r"^\s*(?P<slot>\d+)\s+(?P<id>\S+)\s+.*?\b(?P<status>Normal|Abnormal|NORMAL|ABNORMAL|Fault|Absent)\b", re.M)
    for match in pattern.finditer(text):
        if match.group("status").lower() == "absent":
            continue
        fans[f"Slot {match.group('slot')} Fan {match.group('id')}"] = match.group("status").lower() == "normal"
    return fans


def parse_vrp_power(text: str) -> dict[str, bool]:
    psus: dict[str, bool] = {}
    for line in text.splitlines():
        match = re.search(r"\b(PWR\d+|PS\d+|PSU\d*)\b", line)
        if not match or re.search(r"\b(?:Absent|NO)\b", line):
            continue
        failed = re.search(r"NotSupply|No Supply|Abnormal|Fault|Fail", line, re.I)
        ok = re.search(r"\b(?:Supply|Normal|OK)\b", line, re.I)
        if failed or ok:
            psus[match.group(1)] = not bool(failed)
    return psus


class HuaweiVRPDriver(CLIDriver):
    platform = "huawei_vrp"
    vendor = "Huawei"
    netmiko_device_type = "huawei"
    config_command = "display current-configuration"
    startup_command = "display saved-configuration"
    error_patterns = (r"^Error: ", r"Unrecognized command", r"Wrong parameter", r"Incomplete command", r"Too many parameters")

    def _facts(self) -> dict[str, Any]:
        facts = parse_vrp_version(self._send("display version", use_cache=True))
        facts["serial_number"] = search(r"ESN of [^:]*:\s*(\S+)", self._try("display esn") or "") or ""
        return facts

    def _environment(self, env: dict[str, Any]) -> None:
        cpu = parse_vrp_cpu(self._try("display cpu-usage") or "")
        if cpu is not None:
            set_cpu(env, [cpu])
        total, used, percent = parse_vrp_memory(self._try("display memory-usage") or "")
        set_memory(env, total, used, percent)
        for name, (value, alert) in parse_vrp_temperature(self._try("display temperature all") or "").items():
            add_temperature(env, name, value, alert=alert)
        for name, ok in parse_vrp_fans(self._try("display fan") or "").items():
            add_fan(env, name, ok)
        for name, ok in parse_vrp_power(self._try("display power") or "").items():
            add_psu(env, name, ok)
