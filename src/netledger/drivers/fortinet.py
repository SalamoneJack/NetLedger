"""Fortinet FortiOS (FortiGate) driver."""

from __future__ import annotations

import re
from typing import Any

from netledger.drivers.base import CLIDriver, add_fan, add_psu, add_temperature, set_cpu, set_memory
from netledger.drivers.parsing import parse_duration, search


def parse_system_status(text: str) -> dict[str, Any]:
    facts: dict[str, Any] = {}
    match = re.search(r"^Version:\s*(?P<model>\S+)\s+v?(?P<version>[\d.]+)(?:,build(?P<build>\d+))?", text, re.M)
    if match:
        facts["model"] = match.group("model")
        version = f"v{match.group('version')}"
        if match.group("build"):
            version += f" build{match.group('build')}"
        facts["os_version"] = version
    facts["serial_number"] = search(r"^Serial-Number:\s*(\S+)", text) or ""
    facts["hostname"] = search(r"^Hostname:\s*(\S+)", text) or ""
    return facts


def parse_performance_status(text: str) -> tuple[dict[int, float], dict[str, Any], float | None]:
    """CPU per core, memory dict and uptime from ``get system performance status``."""
    cpus: dict[int, float] = {}
    for match in re.finditer(r"^CPU(\d+) states:.*?(\d+)% idle", text, re.M):
        cpus[int(match.group(1))] = 100.0 - float(match.group(2))
    if not cpus:
        idle = search(r"^CPU states:.*?(\d+)% idle", text)
        if idle is not None:
            cpus[0] = 100.0 - float(idle)
    memory: dict[str, Any] = {}
    match = re.search(r"^Memory:\s*(\d+)k total,\s*(\d+)k used", text, re.M)
    if match:
        memory = {"total": int(match.group(1)) * 1024, "used": int(match.group(2)) * 1024}
    else:
        percent = search(r"^Memory states:\s*(\d+)% used", text)
        if percent is not None:
            memory = {"percent": float(percent)}
    uptime = parse_duration(search(r"^Uptime:\s*(.+)$", text))
    return cpus, memory, uptime


_VOLTAGE = re.compile(r"(?:^\+|\d+(?:\.\d+)?\s*v\b|\bv(?:cc|dd|in|core|bat|tt|ccp|out)\w*|\bvolt|\bp\d+v\d*|_v\d|\bvol\b)", re.I)
_CURRENT_POWER = re.compile(r"\b(?:i|p)(?:in|out)\b|\bcurr|\bwatt|\bamp", re.I)
_TEMP_HINT = re.compile(
    r"temp|therm|\b(?:td|ts|dts|cpu|npu|soc|asic|board|ambient|inlet|outlet|exhaust|lm\d+|np\d+|cp\d+|mac|phy|sensor|hs)\d*\b",
    re.I,
)


def parse_sensor_list(text: str) -> dict[str, dict[str, Any]]:
    """Classify ``execute sensor list`` rows into fans, PSUs and temperatures."""
    result: dict[str, dict[str, Any]] = {"fans": {}, "power": {}, "temperature": {}}
    pattern = re.compile(
        r"^\s*\d+\s+(?P<name>.+?)\s+alarm=(?P<alarm>\d+)\s+value=(?P<value>-?[\d.]+)(?:\s+threshold_status=(?P<ts>\d+))?",
        re.M,
    )
    for match in pattern.finditer(text):
        name = match.group("name").strip()
        alarm = match.group("alarm") != "0"
        value = float(match.group("value"))
        lowered = name.lower()
        if "fan" in lowered:
            result["fans"][name] = {"status": not alarm, "rpm": value}
        elif _VOLTAGE.search(name) or _CURRENT_POWER.search(name):
            continue
        elif re.search(r"\b(?:ps|psu|pwr)\s*\d*\b", lowered) and re.search(r"status|alarm|present|state", lowered):
            result["power"][name] = {"status": not alarm}
        elif _TEMP_HINT.search(name) and -40 < value < 200:
            result["temperature"][name] = {"temperature": value, "alarm": alarm}
    return result


class FortiOSDriver(CLIDriver):
    platform = "fortios"
    vendor = "Fortinet"
    netmiko_device_type = "fortinet"
    config_command = "show"
    full_config_command = "show full-configuration"
    error_patterns = (
        r"Command fail\. Return code",
        r"Unknown action",
        r"command parse error",
        r"^Invalid command",
        r"^-?\d*\s*Unknown command",
    )

    def _after_open(self) -> None:
        self._multi_vdom = bool(getattr(self.device, "_vdoms", False))

    def _global(self, command: str, raise_on_error: bool = True) -> str | None:
        """Run a command in the global context when VDOMs are enabled."""
        if not self._multi_vdom:
            return self._send(command, raise_on_error=raise_on_error) if raise_on_error else self._try(command)
        pattern = getattr(self.device, "prompt_pattern", r"[#$]\s*$")
        self.device.send_command("config global", expect_string=pattern, read_timeout=30)
        try:
            return self._send(command, raise_on_error=raise_on_error) if raise_on_error else self._try(command)
        finally:
            self.device.send_command("end", expect_string=pattern, read_timeout=30)

    def _facts(self) -> dict[str, Any]:
        facts = parse_system_status(self._global("get system status") or "")
        perf = self._global("get system performance status", raise_on_error=False)
        if perf:
            _, _, uptime = parse_performance_status(perf)
            facts["uptime"] = uptime
            self._cache["perf"] = perf
        return facts

    def _environment(self, env: dict[str, Any]) -> None:
        perf = self._cache.pop("perf", None) or self._global("get system performance status") or ""
        cpus, memory, _ = parse_performance_status(perf)
        set_cpu(env, cpus)
        set_memory(env, memory.get("total"), memory.get("used"), memory.get("percent"))
        sensors = self._global("execute sensor list", raise_on_error=False)
        if sensors:
            parsed = parse_sensor_list(sensors)
            for name, fan in parsed["fans"].items():
                add_fan(env, name, fan["status"])
            for name, psu in parsed["power"].items():
                add_psu(env, name, psu["status"])
            for name, temp in parsed["temperature"].items():
                add_temperature(env, name, temp["temperature"], alert=temp["alarm"])
