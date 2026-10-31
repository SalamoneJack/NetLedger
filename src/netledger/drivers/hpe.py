"""HPE Comware / H3C, HPE Aruba AOS-S (ProCurve) and HPE Aruba AOS-CX drivers."""

from __future__ import annotations

import re
from typing import Any

from netledger.drivers.base import CLIDriver, add_fan, add_psu, add_temperature, set_cpu, set_memory
from netledger.drivers.parsing import parse_duration, parse_kv, parse_size, search, status_ok

# --------------------------------------------------------------------------- Comware


def parse_comware_version(text: str) -> dict[str, Any]:
    facts: dict[str, Any] = {}
    match = re.search(r"Comware Software, Version (\S+?),?\s+Release (\S+)", text)
    if match:
        facts["os_version"] = f"{match.group(1)} Release {match.group(2)}"
    match = re.search(r"^(?:HPE?|H3C)\s+(?P<model>.+?)\s+uptime is (?P<uptime>.+?)\s*$", text, re.M)
    if match:
        facts["model"] = match.group("model")
        facts["uptime"] = parse_duration(match.group("uptime"))
    return facts


def parse_comware_cpu(text: str) -> list[float]:
    return [float(v) for v in re.findall(r"(\d+)% in last 1 minute", text)]


def parse_comware_memory(text: str) -> tuple[int | None, int | None]:
    match = re.search(r"^-/\+ Buffers/Cache:\s+(\d+)\s+(\d+)", text, re.M)
    if match:
        used, free = int(match.group(1)), int(match.group(2))
        return (used + free) * 1024, used * 1024
    match = re.search(r"^Mem:\s+(\d+)\s+(\d+)\s+(\d+)", text, re.M)
    if match:
        total, free = int(match.group(1)), int(match.group(3))
        return total * 1024, (total - free) * 1024
    total = search(r"System Total Memory\(bytes\):\s*(\d+)", text)
    used = search(r"Total Used Memory\(bytes\):\s*(\d+)", text)
    if total and used:
        return int(total), int(used)
    return None, None


def parse_comware_environment(text: str) -> dict[str, dict[str, Any]]:
    temps: dict[str, dict[str, Any]] = {}
    row7 = re.compile(
        r"^\s*(?P<slot>\d+)\s+(?P<sensor>[A-Za-z][\w-]*(?:\s+\d+)?)\s+(?P<temp>-?\d+)\s+(?P<lower>-?\d+|NA)"
        r"\s+(?P<warn>-?\d+|NA)\s+(?P<alarm>-?\d+|NA)",
        re.M,
    )
    for match in row7.finditer(text):
        temp = float(match.group("temp"))
        warn = float(match.group("warn")) if match.group("warn") != "NA" else None
        alarm = float(match.group("alarm")) if match.group("alarm") != "NA" else None
        temps[f"Slot {match.group('slot')} {match.group('sensor')}"] = {"temperature": temp, "warn": warn, "crit": alarm}
    if not temps:
        row5 = re.compile(r"^\s*(?P<slot>\d+)\s+(?P<temp>-?\d+)\s+(?P<lower>-?\d+)\s+(?P<upper>-?\d+)\s*$", re.M)
        for match in row5.finditer(text):
            temps[f"Board {match.group('slot')}"] = {
                "temperature": float(match.group("temp")),
                "warn": None,
                "crit": float(match.group("upper")),
            }
    return temps


def parse_comware_fans(text: str) -> dict[str, bool]:
    fans: dict[str, bool] = {}
    for match in re.finditer(r"Fan\s*(\d+)\s*:?\s*(?:\n\s*)?State\s*:\s*(\w+)", text, re.I):
        ok = status_ok(match.group(2))
        if ok is not None:
            fans[f"Fan {match.group(1)}"] = ok
    return fans


def parse_comware_power(text: str) -> dict[str, bool]:
    psus: dict[str, bool] = {}
    for match in re.finditer(r"^\s*(?:Power\s*|PSU\s*)?(\d+)\s+(?:State\s*:\s*)?(Normal|Absent|Fault|Abnormal|Failed)\b", text, re.M | re.I):
        if match.group(2).lower() == "absent":
            continue
        psus[f"PSU {match.group(1)}"] = match.group(2).lower() == "normal"
    return psus


class ComwareDriver(CLIDriver):
    platform = "comware"
    vendor = "HPE"
    netmiko_device_type = "hp_comware"
    config_command = "display current-configuration"
    startup_command = "display saved-configuration"
    error_patterns = (r"% Unrecognized command", r"% Wrong parameter", r"% Incomplete command", r"% Too many parameters")

    def _facts(self) -> dict[str, Any]:
        facts = parse_comware_version(self._send("display version", use_cache=True))
        facts["serial_number"] = search(r"DEVICE_SERIAL_NUMBER\s*:\s*(\S+)", self._try("display device manuinfo") or "") or ""
        return facts

    def _environment(self, env: dict[str, Any]) -> None:
        cpus = parse_comware_cpu(self._try("display cpu-usage") or "")
        if cpus:
            set_cpu(env, cpus)
        total, used = parse_comware_memory(self._try("display memory") or "")
        set_memory(env, total, used)
        for name, temp in parse_comware_environment(self._try("display environment") or "").items():
            add_temperature(env, name, temp["temperature"], warn_at=temp["warn"], crit_at=temp["crit"])
        for name, ok in parse_comware_fans(self._try("display fan") or "").items():
            add_fan(env, name, ok)
        for name, ok in parse_comware_power(self._try("display power") or "").items():
            add_psu(env, name, ok)


# --------------------------------------------------------------------------- ProCurve / AOS-S


def parse_procurve_system(text: str) -> dict[str, Any]:
    facts: dict[str, Any] = {
        "hostname": search(r"System Name\s*:\s*(\S+)", text) or "",
        "os_version": search(r"Software revision\s*:\s*(\S+)", text) or "",
        "serial_number": search(r"Serial Number\s*:\s*(\S+)", text) or "",
        "uptime": parse_duration(search(r"Up Time\s*:\s*(.+?)(?:\s{2,}|$)", text)),
    }
    cpu = search(r"CPU Util \(%\)\s*:\s*(\d+)", text)
    facts["_cpu"] = float(cpu) if cpu is not None else None
    match = re.search(r"Memory\s+-\s+Total\s*:\s*([\d,]+).*?Free\s*:\s*([\d,]+)", text, re.S)
    if match:
        total, free = parse_size(match.group(1)), parse_size(match.group(2))
        facts["_mem"] = (total, (total or 0) - (free or 0))
    return facts


def parse_procurve_temperature(text: str) -> dict[str, tuple[float, float | None, bool]]:
    temps: dict[str, tuple[float, float | None, bool]] = {}
    pattern = re.compile(
        r"^\s*(?P<name>[A-Za-z][\w\- ]*?)\s*\|?\s*(?P<cur>-?\d+)C\s+(?:-?\d+C\s+){0,2}(?P<thr>-?\d+)C?\s+(?P<over>YES|NO)\b",
        re.M | re.I,
    )
    for match in pattern.finditer(text):
        temps[match.group("name").strip()] = (float(match.group("cur")), float(match.group("thr")), match.group("over").upper() == "YES")
    return temps


def parse_procurve_fans(text: str) -> dict[str, bool]:
    fans: dict[str, bool] = {}
    for match in re.finditer(r"^\s*(?P<name>[\w-]+)\s*\|\s*(?P<state>[^|]+?)\s*\|\s*(?P<fail>\d+)\s*$", text, re.M):
        state = match.group("state").lower()
        if "not installed" in state or "absent" in state:
            continue
        fans[match.group("name")] = "ok" in state
    return fans


def parse_procurve_power(text: str) -> dict[str, bool]:
    psus: dict[str, bool] = {}
    pattern = re.compile(r"^\s*(?P<num>\d+)\s+.*?\b(?P<state>Powered|Not Powered|Not Present|Failed|Fault|Aux Not Powered|Permanent Failure)\b", re.M)
    for match in pattern.finditer(text):
        if match.group("state") == "Not Present":
            continue
        psus[f"PS {match.group('num')}"] = match.group("state") == "Powered"
    return psus


class ProCurveDriver(CLIDriver):
    platform = "procurve"
    vendor = "HPE Aruba"
    netmiko_device_type = "hp_procurve"
    config_command = "show running-config"
    startup_command = "show config"
    error_patterns = (r"Invalid input:", r"Ambiguous input", r"Incomplete input")

    def _facts(self) -> dict[str, Any]:
        facts = {k: v for k, v in parse_procurve_system(self._send("show system", use_cache=True)).items() if not k.startswith("_")}
        running = self._cache.get("__running__", "")
        facts["model"] = search(r"^; (\S+) Configuration Editor", running) or ""
        return facts

    def _environment(self, env: dict[str, Any]) -> None:
        system = parse_procurve_system(self._send("show system", use_cache=True))
        if system.get("_cpu") is not None:
            set_cpu(env, [system["_cpu"]])
        if system.get("_mem"):
            set_memory(env, *system["_mem"])
        for name, (cur, threshold, over) in parse_procurve_temperature(self._try("show system temperature") or "").items():
            add_temperature(env, name, cur, alert=over, crit_at=threshold)
        for name, ok in parse_procurve_fans(self._try("show system fans") or "").items():
            add_fan(env, name, ok)
        for name, ok in parse_procurve_power(self._try("show system power-supply") or "").items():
            add_psu(env, name, ok)


# --------------------------------------------------------------------------- AOS-CX


def parse_aoscx_system(text: str) -> dict[str, Any]:
    kv = parse_kv(text)
    cpu = kv.get("CPU Util (%)")
    memory = kv.get("Memory Usage (%)")
    return {
        "hostname": kv.get("Hostname", ""),
        "model": kv.get("Product Name", ""),
        "serial_number": kv.get("Chassis Serial Nbr", "") or kv.get("Chassis Serial Number", ""),
        "uptime": parse_duration(kv.get("Up Time")),
        "_cpu": float(cpu) if cpu and re.fullmatch(r"[\d.]+", cpu) else None,
        "_mem": float(memory) if memory and re.fullmatch(r"[\d.]+", memory) else None,
    }


def parse_aoscx_temperature(text: str) -> dict[str, tuple[float, str]]:
    temps: dict[str, tuple[float, str]] = {}
    for match in re.finditer(r"^\s*(?P<name>\S+)\s+(?P<module>[\w-]+)\s+(?P<temp>-?\d+(?:\.\d+)?)\s*C\s+(?P<status>[\w-]+)", text, re.M):
        temps[match.group("name")] = (float(match.group("temp")), match.group("status").lower())
    return temps


def parse_aoscx_status_rows(text: str) -> dict[str, bool]:
    """Fan / power-supply rows like ``1/1  JL085A  CN123  OK ...`` (absent entries skipped)."""
    rows: dict[str, bool] = {}
    for match in re.finditer(r"^\s*(?P<name>\d+/\S+)\s+(?P<rest>.+)$", text, re.M):
        rest = match.group("rest")
        if re.search(r"\b(?:absent|empty|not present)\b", rest, re.I):
            continue
        if re.search(r"\b(?:fault|failed|failure|input fault|output fault|warning)\b", rest, re.I):
            rows[match.group("name")] = False
        elif re.search(r"\b(?:ok|normal|good)\b", rest, re.I):
            rows[match.group("name")] = True
    return rows


class AOSCXDriver(CLIDriver):
    platform = "aoscx"
    vendor = "HPE Aruba"
    netmiko_device_type = "aruba_aoscx"
    config_command = "show running-config"
    startup_command = "show startup-config"
    error_patterns = (r"Invalid input:", r"% Command incomplete", r"Command not found", r"Invalid command")

    def _facts(self) -> dict[str, Any]:
        facts = {k: v for k, v in parse_aoscx_system(self._send("show system", use_cache=True)).items() if not k.startswith("_")}
        facts["os_version"] = search(r"^Version\s*:\s*(\S+)", self._try("show version") or "") or ""
        return facts

    def _environment(self, env: dict[str, Any]) -> None:
        system = parse_aoscx_system(self._send("show system", use_cache=True))
        if system["_cpu"] is not None:
            set_cpu(env, [system["_cpu"]])
        if system["_mem"] is not None:
            set_memory(env, None, None, system["_mem"])
        for name, (value, status) in parse_aoscx_temperature(self._try("show environment temperature") or "").items():
            add_temperature(
                env, name, value,
                alert=status not in ("normal", "ok"),
                critical=status in ("critical", "fault", "emergency", "shutdown"),
            )
        for name, ok in parse_aoscx_status_rows(self._try("show environment fan") or "").items():
            add_fan(env, name, ok)
        for name, ok in parse_aoscx_status_rows(self._try("show environment power-supply") or "").items():
            add_psu(env, name, ok)
