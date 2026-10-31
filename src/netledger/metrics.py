"""Prometheus metrics rendered from the state store (text exposition format 0.0.4)."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from netledger import __version__

HEALTH_CODES = {"ok": 0, "warning": 1, "critical": 2, "unknown": 3}


def _escape(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


class _Registry:
    def __init__(self) -> None:
        self.meta: dict[str, tuple[str, str]] = {}
        self.samples: dict[str, list[str]] = defaultdict(list)

    def add(self, name: str, kind: str, help_text: str, labels: dict[str, Any], value: Any) -> None:
        if value is None:
            return
        try:
            number = float(value)
        except (TypeError, ValueError):
            return
        self.meta.setdefault(name, (kind, help_text))
        label_text = ",".join(f'{k}="{_escape(v)}"' for k, v in labels.items() if v is not None)
        rendered = f"{number:.6g}" if not number.is_integer() else str(int(number))
        self.samples[name].append(f"{name}{{{label_text}}} {rendered}" if label_text else f"{name} {rendered}")

    def render(self) -> str:
        lines = []
        for name, (kind, help_text) in self.meta.items():
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} {kind}")
            lines.extend(self.samples[name])
        return "\n".join(lines) + "\n"


def render_metrics(snapshot: dict[str, Any]) -> str:
    r = _Registry()
    r.add("netledger_info", "gauge", "NetLedger build information", {"version": __version__}, 1)
    for job, run in (snapshot.get("runs") or {}).items():
        labels = {"job": job}
        r.add("netledger_run_last_timestamp_seconds", "gauge", "When the last run finished", labels, run.get("finished"))
        r.add("netledger_run_duration_seconds", "gauge", "Duration of the last run", labels, run.get("duration"))
        r.add("netledger_run_devices", "gauge", "Devices processed in the last run", labels, run.get("devices"))
        if job == "backup":
            r.add("netledger_backup_run_failed_devices", "gauge", "Devices that failed in the last backup run", {}, run.get("failed"))
            r.add("netledger_backup_run_commits", "gauge", "Commits created by the last backup run", {}, run.get("commits"))
            r.add("netledger_backup_run_error", "gauge", "1 if the last backup run hit a repository error", {}, 1 if run.get("error") else 0)

    for name, data in sorted((snapshot.get("devices") or {}).items()):
        info = data.get("info") or {}
        base = {"device": name, "site": info.get("site") or "", "platform": info.get("platform") or ""}
        backup = data.get("backup") or {}
        if backup:
            r.add("netledger_backup_success", "gauge", "1 if the last backup attempt succeeded", base, 1 if backup.get("status") == "ok" else 0)
            r.add("netledger_backup_last_success_timestamp_seconds", "gauge", "Last successful backup", base, backup.get("last_success"))
            r.add("netledger_backup_last_change_timestamp_seconds", "gauge", "Last detected configuration change", base, backup.get("last_change"))
            r.add("netledger_backup_duration_seconds", "gauge", "Duration of the last backup", base, backup.get("duration"))
            r.add("netledger_backup_consecutive_failures", "gauge", "Consecutive failed backups", base, backup.get("consecutive_failures"))
            r.add("netledger_config_changes_total", "counter", "Configuration changes detected", base, backup.get("changes_total") or 0)
            if backup.get("unsaved_changes") is not None:
                r.add("netledger_config_unsaved", "gauge", "1 if running and startup configuration differ", base, 1 if backup.get("unsaved_changes") else 0)
        health = data.get("health") or {}
        if health:
            r.add("netledger_device_up", "gauge", "1 if the device answered the last health check", base, 1 if health.get("reachable") else 0)
            r.add("netledger_health_status", "gauge", "Health status (0=ok 1=warning 2=critical 3=unknown)", base, HEALTH_CODES.get(health.get("status"), 3))
            r.add("netledger_cpu_usage_percent", "gauge", "Highest CPU utilization", base, health.get("cpu"))
            r.add("netledger_memory_usage_percent", "gauge", "Memory utilization", base, health.get("memory_pct"))
            r.add("netledger_memory_used_bytes", "gauge", "Memory in use", base, health.get("memory_used"))
            r.add("netledger_memory_total_bytes", "gauge", "Total memory", base, health.get("memory_total"))
            r.add("netledger_device_uptime_seconds", "gauge", "Device uptime at the last check", base, health.get("uptime"))
            for sensor, temp in (health.get("temperatures") or {}).items():
                labels = {**base, "sensor": sensor}
                r.add("netledger_temperature_celsius", "gauge", "Temperature sensor reading", labels, temp.get("value"))
                r.add("netledger_temperature_alert", "gauge", "1 if the sensor is above a threshold or alarming", labels, 0 if temp.get("status") == "ok" else 1)
            for fan, ok in (health.get("fans") or {}).items():
                r.add("netledger_fan_ok", "gauge", "1 if the fan is working", {**base, "fan": fan}, 1 if ok else 0)
            for psu, ok in (health.get("psus") or {}).items():
                r.add("netledger_power_supply_ok", "gauge", "1 if the power supply is working", {**base, "psu": psu}, 1 if ok else 0)
            for metric, fc in (health.get("forecast") or {}).items():
                labels = {**base, "metric": metric, "level": fc.get("level") or ""}
                r.add("netledger_forecast_seconds_to_threshold", "gauge", "Predicted time until a rising metric crosses its threshold", labels, fc.get("eta_seconds"))
        compliance = (data.get("compliance") or {}).get("rules") or {}
        for rule, result in compliance.items():
            r.add("netledger_compliance_ok", "gauge", "1 if the compliance rule passes", {**base, "rule": rule}, 1 if result.get("passed") else 0)
    return r.render()
