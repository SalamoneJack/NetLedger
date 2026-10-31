"""Cisco ASA, AireOS WLC and Small Business (SG/CBS) drivers."""

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
from netledger.drivers.parsing import parse_duration, parse_kv, search, status_ok

# --------------------------------------------------------------------------- shared parsing

_TEMP_LINE = re.compile(
    r"^\s*(?P<name>[^:\n]+?):\s+(?P<value>[-+]?\d+(?:\.\d+)?)\s*(?:C|deg(?:rees)? C|Celsius)\b"
    r"(?:\s*-\s*(?P<status>[A-Za-z]+))?",
    re.M,
)
_FAN_LINE = re.compile(r"^\s*(?P<name>[^:\n]+?):\s+(?P<rpm>\d+)\s*RPM\b(?:\s*-\s*(?P<status>[A-Za-z]+))?", re.M)
_PSU_LINE = re.compile(
    r"^\s*(?P<name>(?:Power Supply|PSU|PS)\s*[^:\n]*|[^:\n]*\(PS\d+\)):\s*(?P<status>[A-Za-z][A-Za-z ]*?)\s*$",
    re.M | re.I,
)


def parse_colon_environment(text: str) -> dict[str, dict[str, Any]]:
    """Parse ``name: 45.0 C - OK`` / ``name: 4800 RPM - OK`` / ``Power Supply 1: OK`` style output."""
    result: dict[str, dict[str, Any]] = {"temperature": {}, "fans": {}, "power": {}}
    for match in _TEMP_LINE.finditer(text):
        status = (match.group("status") or "").lower()
        result["temperature"][match.group("name").strip()] = {
            "temperature": float(match.group("value")),
            "alert": status not in ("", "ok", "normal", "good"),
            "critical": status in ("critical", "shutdown", "failed", "alarm"),
        }
    for match in _FAN_LINE.finditer(text):
        status = match.group("status")
        ok = status_ok(status) if status else int(match.group("rpm")) > 0
        result["fans"][match.group("name").strip()] = {"status": ok if ok is not None else True}
    for match in _PSU_LINE.finditer(text):
        status = match.group("status").strip().lower()
        if "not present" in status or "absent" in status or "empty" in status:
            continue
        ok = True if status in ("present", "ok", "normal", "good", "on") else status_ok(status)
        if ok is not None:
            result["power"][match.group("name").strip()] = {"status": ok}
    return result


# --------------------------------------------------------------------------- ASA


def parse_asa_version(text: str) -> dict[str, Any]:
    facts: dict[str, Any] = {
        "os_version": search(r"Software Version (\S+)", text) or "",
        "model": search(r"^Hardware:\s+([^,]+),", text) or "",
        "serial_number": search(r"^Serial Number:\s*(\S+)", text) or "",
    }
    match = re.search(r"^(\S+) up (.+?)\s*$", text, re.M)
    if match:
        facts["hostname"] = match.group(1)
        facts["uptime"] = parse_duration(match.group(2))
    return facts


def parse_asa_cpu(text: str) -> float | None:
    value = search(r"1 minute:\s*(\d+)%", text) or search(r"for 5 seconds = (\d+)%", text)
    return float(value) if value is not None else None


def parse_asa_memory(text: str) -> tuple[int | None, int | None]:
    free = search(r"^Free memory:\s+(\d+) bytes", text)
    used = search(r"^Used memory:\s+(\d+) bytes", text)
    if free is None or used is None:
        return None, None
    return int(free) + int(used), int(used)


class ASADriver(CLIDriver):
    platform = "asa"
    vendor = "Cisco"
    netmiko_device_type = "cisco_asa"
    config_command = "show running-config"
    full_config_command = "show running-config all"
    startup_command = "show startup-config"
    needs_enable = True
    error_patterns = (*GENERIC_ERRORS, r"^ERROR: % Invalid")

    def _facts(self) -> dict[str, Any]:
        return parse_asa_version(self._send("show version", use_cache=True))

    def _environment(self, env: dict[str, Any]) -> None:
        cpu = parse_asa_cpu(self._try("show cpu usage") or "")
        if cpu is not None:
            set_cpu(env, [cpu])
        total, used = parse_asa_memory(self._try("show memory") or "")
        set_memory(env, total, used)
        parsed = parse_colon_environment(self._try("show environment") or "")
        for name, temp in parsed["temperature"].items():
            add_temperature(env, name, temp["temperature"], alert=temp["alert"], critical=temp["critical"])
        for name, fan in parsed["fans"].items():
            add_fan(env, name, fan["status"])
        for name, psu in parsed["power"].items():
            add_psu(env, name, psu["status"])


# --------------------------------------------------------------------------- AireOS


def parse_aireos_sysinfo(text: str) -> dict[str, Any]:
    kv = parse_kv(text)
    facts: dict[str, Any] = {
        "os_version": kv.get("Product Version", ""),
        "hostname": kv.get("System Name", ""),
        "uptime": parse_duration(kv.get("System Up Time")),
    }
    temp = search(r"Internal Temperature\.*\s*:?\s*([+-]?\d+(?:\.\d+)?)\s*C", text)
    limits = re.search(r"Internal Temp Alarm Limits\.*\s*:?\s*(-?\d+) to (-?\d+) C", text, re.I)
    facts["_temperature"] = float(temp) if temp is not None else None
    facts["_temp_max"] = float(limits.group(2)) if limits else None
    return facts


class AireOSDriver(CLIDriver):
    platform = "aireos"
    vendor = "Cisco"
    netmiko_device_type = "cisco_wlc"
    config_command = "show run-config commands"
    error_patterns = (*GENERIC_ERRORS, r"Incorrect usage", r"Incorrect input")

    def _facts(self) -> dict[str, Any]:
        facts = {k: v for k, v in parse_aireos_sysinfo(self._send("show sysinfo", use_cache=True)).items() if not k.startswith("_")}
        inventory = self._try("show inventory") or ""
        facts["model"] = search(r"PID:\s*([^,\s]+)", inventory) or ""
        facts["serial_number"] = search(r"SN:\s*(\S+)", inventory) or ""
        return facts

    def _environment(self, env: dict[str, Any]) -> None:
        cpu = search(r"(?:Current CPU\(s\) load|Current Usage)\s*:?\s*(\d+)%", self._try("show cpu") or "")
        if cpu is not None:
            set_cpu(env, [float(cpu)])
        memory = self._try("show memory statistics") or ""
        total = search(r"Total System Memory\.*\s*:?\s*(\d+)\s*kbytes", memory)
        used = search(r"Used System Memory\.*\s*:?\s*(\d+)\s*kbytes", memory)
        if total and used:
            set_memory(env, int(total) * 1024, int(used) * 1024)
        info = parse_aireos_sysinfo(self._send("show sysinfo", use_cache=True))
        add_temperature(env, "Internal", info["_temperature"], crit_at=info["_temp_max"])


# --------------------------------------------------------------------------- Cisco Small Business


def parse_smb_system(text: str) -> dict[str, Any]:
    facts: dict[str, Any] = {
        "hostname": search(r"^System Name:\s*(\S+)", text) or "",
        "model": (search(r"^System Description:\s*(\S+)", text) or ""),
    }
    match = re.search(r"System Up Time \(days,hour:min:sec\):\s*(\d+),(\d+):(\d+):(\d+)", text)
    if match:
        days, hours, minutes, seconds = (int(x) for x in match.groups())
        facts["uptime"] = float(days * 86400 + hours * 3600 + minutes * 60 + seconds)
    return facts


def parse_smb_temperatures(text: str) -> dict[str, tuple[float, bool]]:
    temps: dict[str, tuple[float, bool]] = {}
    for match in re.finditer(r"^\s*(\d+)\s+(-?\d+)\s+(OK|FAILURE|WARNING|NORMAL|ALARM|CRITICAL)\s*$", text, re.M | re.I):
        temps[f"Unit {match.group(1)}"] = (float(match.group(2)), match.group(3).upper() not in ("OK", "NORMAL"))
    return temps


class CiscoSMBDriver(CLIDriver):
    platform = "cisco_smb"
    vendor = "Cisco"
    netmiko_device_type = "cisco_s300"
    config_command = "show running-config"
    startup_command = "show startup-config"
    needs_enable = True

    def _facts(self) -> dict[str, Any]:
        facts = parse_smb_system(self._send("show system", use_cache=True))
        version = self._try("show version") or ""
        facts["os_version"] = search(r"SW version\s+(\S+)", version) or ""
        inventory = self._try("show inventory") or ""
        facts["model"] = search(r"PID:\s*(\S+)", inventory) or facts.get("model", "")
        facts["serial_number"] = search(r"SN:\s*(\S+)", inventory) or ""
        return facts

    def _environment(self, env: dict[str, Any]) -> None:
        cpu = search(r"one minute:\s*(\d+)%", self._try("show cpu utilization") or "")
        if cpu is not None:
            set_cpu(env, [float(cpu)])
        for name, (value, alert) in parse_smb_temperatures(self._send("show system", use_cache=True)).items():
            add_temperature(env, name, value, alert=alert)
