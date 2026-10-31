"""Health checks: CPU, memory, temperature, fans, power supplies, reachability and reboot detection."""

from __future__ import annotations

import logging
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

from netledger.config import HealthThresholds, Settings, ThresholdPair
from netledger.connection import DeviceError, describe_error, device_session, run_parallel
from netledger.events import Event
from netledger.history import MetricsHistory, Sample, forecast
from netledger.inventory import Device
from netledger.state import StateStore
from netledger.topology import normalize_lldp
from netledger.utils import deep_merge, format_duration, now

log = logging.getLogger(__name__)

STATUS_ORDER = {"ok": 0, "unknown": 1, "warning": 2, "critical": 3}
EXIT_CODES = {"ok": 0, "warning": 1, "critical": 2, "unknown": 3}


def worst(*statuses: str) -> str:
    present = [s for s in statuses if s]
    return max(present, key=lambda s: STATUS_ORDER.get(s, 0)) if present else "unknown"


@dataclass
class Check:
    name: str
    status: str
    message: str
    value: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HealthCollected:
    reachable: bool = False
    facts: dict[str, Any] = field(default_factory=dict)
    env: dict[str, Any] | None = None
    supported: bool = True
    error: str | None = None
    error_kind: str | None = None
    env_error: str | None = None
    duration: float = 0.0
    neighbors: list[dict[str, str]] | None = None


@dataclass
class DeviceHealth:
    device: Device
    status: str = "unknown"
    reachable: bool = False
    error: str | None = None
    checks: list[Check] = field(default_factory=list)
    cpu: float | None = None
    cpus: dict[str, float] = field(default_factory=dict)
    memory_pct: float | None = None
    memory_used: int | None = None
    memory_total: int | None = None
    temperatures: dict[str, dict[str, Any]] = field(default_factory=dict)
    fans: dict[str, bool] = field(default_factory=dict)
    psus: dict[str, bool] = field(default_factory=dict)
    uptime: float | None = None
    rebooted: bool = False
    duration: float = 0.0
    facts: dict[str, Any] = field(default_factory=dict)
    env_supported: bool = True

    @property
    def max_temperature(self) -> float | None:
        values = [t["value"] for t in self.temperatures.values() if t.get("value") is not None]
        return max(values) if values else None

    @property
    def problems(self) -> list[Check]:
        return [c for c in self.checks if c.status in ("warning", "critical")]


@dataclass
class HealthReport:
    started: float
    finished: float = 0.0
    results: list[DeviceHealth] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)

    def count(self, status: str) -> int:
        return sum(1 for r in self.results if r.status == status)

    @property
    def status(self) -> str:
        return worst(*(r.status for r in self.results)) if self.results else "ok"

    @property
    def exit_code(self) -> int:
        return EXIT_CODES.get(self.status, 3)

    @property
    def duration(self) -> float:
        return max(0.0, (self.finished or now()) - self.started)


def thresholds_for(device: Device, settings: Settings) -> HealthThresholds:
    override = device.health_settings.get("thresholds") or {}
    if not override:
        return settings.health.thresholds
    return HealthThresholds.model_validate(deep_merge(settings.health.thresholds.model_dump(), override))


def grade(value: float | None, pair: ThresholdPair) -> str:
    if value is None:
        return "unknown"
    if pair.critical is not None and value >= pair.critical:
        return "critical"
    if pair.warning is not None and value >= pair.warning:
        return "warning"
    return "ok"


def memory_usage(memory: dict[str, Any], free_semantics: bool = False) -> tuple[float | None, int | None, int | None]:
    """Memory usage %, used and total bytes from a NAPALM memory dict.

    NAPALM documents ``available_ram`` as the total, but some drivers report free memory there.
    """
    if memory.get("%usage") is not None:
        return round(float(memory["%usage"]), 1), None, None
    available, used = memory.get("available_ram"), memory.get("used_ram")
    if available is None or used is None or available < 0 or used < 0:
        return None, None, None
    total = available + used if (free_semantics or used > available) else available
    if total <= 0:
        return None, None, None
    return round(used / total * 100, 1), int(used), int(total)


def _threshold_hint(value: float, pair: ThresholdPair, status: str, unit: str) -> str:
    limit = pair.critical if status == "critical" else pair.warning if status == "warning" else None
    return f" (>= {limit:g}{unit})" if limit is not None else ""


def evaluate(device: Device, collected: HealthCollected, settings: Settings) -> DeviceHealth:
    health = DeviceHealth(
        device=device,
        reachable=collected.reachable,
        error=collected.error,
        duration=collected.duration,
        facts=collected.facts,
        env_supported=collected.supported,
    )
    if not collected.reachable:
        return health
    health.checks.append(Check("reachability", "ok", f"answered in {format_duration(collected.duration)}", collected.duration))
    uptime = collected.facts.get("uptime")
    if isinstance(uptime, (int, float)) and uptime >= 0:
        health.uptime = float(uptime)

    env = collected.env
    if env is None:
        if collected.env_error:
            health.checks.append(Check("environment", "unknown", f"environment data unavailable: {collected.env_error}"))
        health.status = worst(*(c.status for c in health.checks))
        return health

    limits = thresholds_for(device, settings)
    ignore = [re.compile(p, re.I) for p in settings.health.ignore_sensors + list(device.health_settings.get("ignore_sensors") or [])]

    def ignored(name: str) -> bool:
        return any(p.search(name) for p in ignore)

    def severity(setting: str) -> str:
        return "ok" if setting == "info" else setting

    cpus = {str(k): float(v.get("%usage")) for k, v in (env.get("cpu") or {}).items() if isinstance(v, dict) and v.get("%usage") is not None and float(v.get("%usage")) >= 0}
    if cpus:
        health.cpus = cpus
        health.cpu = round(max(cpus.values()), 1)
        status = grade(health.cpu, limits.cpu)
        health.checks.append(Check("cpu", status, f"CPU {health.cpu:.0f}%{_threshold_hint(health.cpu, limits.cpu, status, '%')}", health.cpu))

    pct, used, total = memory_usage(env.get("memory") or {}, device.platform_info.memory_free_semantics)
    if pct is not None:
        health.memory_pct, health.memory_used, health.memory_total = pct, used, total
        status = grade(pct, limits.memory)
        health.checks.append(Check("memory", status, f"Memory {pct:.0f}%{_threshold_hint(pct, limits.memory, status, '%')}", pct))

    temps: list[tuple[str, float, str]] = []
    for name, data in (env.get("temperature") or {}).items():
        if ignored(name) or not isinstance(data, dict):
            continue
        value = data.get("temperature")
        if value is None or float(value) == -1.0:
            continue
        value = float(value)
        status = "critical" if data.get("is_critical") else "warning" if data.get("is_alert") else "ok"
        graded = grade(value, limits.temperature)
        status = worst(status, graded if graded != "unknown" else "ok")
        health.temperatures[name] = {"value": value, "status": status}
        temps.append((name, value, status))
    if temps:
        status = worst(*(s for _, _, s in temps))
        hottest = max(temps, key=lambda t: (STATUS_ORDER[t[2]], t[1]))
        message = f"{hottest[0]} {hottest[1]:.1f}°C"
        if status != "ok":
            alarms = [t for t in temps if t[2] != "ok"]
            message = ", ".join(f"{n} {v:.1f}°C" for n, v, _ in alarms[:3]) + _threshold_hint(hottest[1], limits.temperature, status, "°C")
        health.checks.append(Check("temperature", status, message, hottest[1]))

    for key, label, setting, store in (
        ("fans", "fan", settings.health.fan_failure, health.fans),
        ("power", "power supply", settings.health.psu_failure, health.psus),
    ):
        items = {n: bool(d.get("status")) for n, d in (env.get(key) or {}).items() if isinstance(d, dict) and not ignored(n)}
        if not items:
            continue
        store.update(items)
        failed = [n for n, ok in items.items() if not ok]
        if failed:
            word = label.split()[0]
            names = [n if word in n.lower() or n.lower().startswith(("ps", "pwr")) else f"{label.capitalize()} {n}" for n in failed]
            health.checks.append(Check(key, severity(setting), f"{', '.join(names)} failed ({len(items) - len(failed)} of {len(items)} OK)"))
        else:
            noun = label if len(items) == 1 else {"fan": "fans", "power supply": "power supplies"}[label]
            health.checks.append(Check(key, "ok", f"{len(items)} {noun} OK"))

    health.status = worst(*(c.status for c in health.checks))
    return health


FORECAST_METRICS = (("memory", "Memory", "%"), ("temperature", "Temperature", "°C"))


class HealthRunner:
    def __init__(self, settings: Settings, state: StateStore, dispatcher: Any | None = None, history: MetricsHistory | None = None):
        self.settings = settings
        self.state = state
        self.dispatcher = dispatcher
        self.history = history
        self._own_history = False

    def collect(self, device: Device) -> HealthCollected:
        started = time.monotonic()
        out = HealthCollected()
        try:
            with device_session(device, self.settings, timeout=self.settings.health.timeout, retries=0) as driver:
                out.reachable = True
                try:
                    out.facts = dict(driver.get_facts())
                except Exception as exc:  # noqa: BLE001
                    out.facts = {}
                    out.env_error = f"facts: {describe_error(exc)}"
                try:
                    out.env = dict(driver.get_environment())
                except NotImplementedError:
                    out.supported = False
                except Exception as exc:  # noqa: BLE001
                    out.env_error = describe_error(exc)
                if self.settings.health.lldp:
                    try:
                        out.neighbors = normalize_lldp(driver.get_lldp_neighbors())
                    except NotImplementedError:
                        pass
                    except Exception as exc:  # noqa: BLE001 - LLDP is optional
                        log.debug("%s: LLDP neighbors unavailable: %s", device.name, describe_error(exc))
        except DeviceError as exc:
            out.error, out.error_kind = str(exc), exc.kind
        except Exception as exc:  # noqa: BLE001
            out.error, out.error_kind = f"{type(exc).__name__}: {describe_error(exc)}", "error"
        out.duration = time.monotonic() - started
        return out

    def run(self, devices: list[Device], progress: Callable[[DeviceHealth], None] | None = None, notify: bool = True) -> HealthReport:
        report = HealthReport(started=now())
        targets = [d for d in devices if d.health]
        if self.history is None and self.settings.health.history:
            self.history = MetricsHistory.for_settings(self.settings)
            self._own_history = True
        try:
            for device, collected in run_parallel(targets, self.collect, self.settings.health.workers):
                health = evaluate(device, collected, self.settings)
                self._apply_state(device, health, collected, report.events)
                report.results.append(health)
                if progress:
                    progress(health)
        finally:
            if self._own_history and self.history is not None:
                self.history.close()
                self.history = None
                self._own_history = False
        report.results.sort(key=lambda r: r.device.name.lower())
        report.finished = now()
        self.state.record_events(report.events)
        self.state.set_run("health", {
            "started": report.started,
            "finished": report.finished,
            "duration": round(report.duration, 2),
            "devices": len(report.results),
            **{status: report.count(status) for status in STATUS_ORDER},
        })
        self.state.save()
        if notify and self.dispatcher and report.events:
            self.dispatcher.dispatch(report.events)
        return report

    def _apply_state(self, device: Device, health: DeviceHealth, collected: HealthCollected, events: list[Event]) -> None:
        stamp = now()
        previous = self.state.section(device.name, "health")
        info = self.state.section(device.name, "info")
        if not info:
            self.state.set_info(device.name, device.summary())
        last_known = previous.get("last_known_status")
        failures = int(previous.get("consecutive_failures") or 0)
        after = self.settings.health.unreachable_after
        values: dict[str, Any] = {"checked_at": stamp, "duration": round(health.duration, 2)}

        if not health.reachable:
            failures += 1
            what = "login failed" if collected.error_kind == "auth" else "unreachable"
            if failures >= after:
                health.status = "critical"
                plural = "s" if failures != 1 else ""
                health.checks = [Check("reachability", "critical", f"{what}: {health.error} ({failures} consecutive failure{plural})")]
            else:
                health.status = "unknown"
                health.checks = [Check("reachability", "unknown", f"{what} ({failures}/{after} before alerting): {health.error}")]
            values.update({"reachable": False, "error": health.error, "status": health.status})
        else:
            failures = 0
            uptime_prev, uptime_at = previous.get("uptime"), previous.get("uptime_at")
            if health.uptime is not None and uptime_prev is not None and uptime_at:
                elapsed = stamp - float(uptime_at)
                if health.uptime + 60 < elapsed:
                    health.rebooted = True
            values.update({
                "status": health.status,
                "reachable": True,
                "error": None,
                "cpu": health.cpu,
                "cpus": health.cpus,
                "memory_pct": health.memory_pct,
                "memory_used": health.memory_used,
                "memory_total": health.memory_total,
                "temperatures": health.temperatures,
                "fans": health.fans,
                "psus": health.psus,
                "env_supported": health.env_supported,
            })
            if collected.neighbors is not None:
                values.update({"neighbors": collected.neighbors, "neighbors_at": stamp})
            if health.uptime is not None:
                values.update({"uptime": health.uptime, "uptime_at": stamp, "boot_time": stamp - health.uptime})
            if health.rebooted:
                values["last_reboot"] = stamp - (health.uptime or 0)
                events.append(Event(
                    "device_rebooted", self.settings.health.reboot, f"{device.name}: device rebooted",
                    f"Uptime is {format_duration(health.uptime)}.", device=device.name, site=device.site or None,
                    platform=device.platform, details={"uptime": health.uptime}, timestamp=stamp,
                ))
        values["checks"] = [c.to_dict() for c in health.checks]
        values["consecutive_failures"] = failures

        status = health.status
        if status in ("warning", "critical") and status != last_known:
            problems = health.problems or health.checks
            events.append(Event(
                f"health_{status}", status, f"{device.name}: health {status}",
                "; ".join(c.message for c in problems),
                device=device.name, site=device.site or None, platform=device.platform,
                details={"checks": [c.to_dict() for c in problems]}, timestamp=stamp,
            ))
        elif status == "ok" and last_known in ("warning", "critical"):
            events.append(Event(
                "health_recovered", "info", f"{device.name}: health recovered",
                "All health checks are OK again.", device=device.name, site=device.site or None, platform=device.platform,
                timestamp=stamp,
            ))
        if status != "unknown":
            values["last_known_status"] = status
            if status != last_known:
                values["status_since"] = stamp
        if self.history is not None:
            self.history.record([Sample(
                device.name, stamp, status, health.cpu, health.memory_pct, health.max_temperature,
                round(health.duration, 3) if health.reachable else None,
            )])
            if health.reachable:
                values.update(self._forecasts(device, previous, events, stamp))
        self.state.update(device.name, "health", values)

    def _forecasts(self, device: Device, previous: dict[str, Any], events: list[Event], stamp: float) -> dict[str, Any]:
        """Trend memory and temperature over the last week; alert once when a threshold will be crossed soon."""
        assert self.history is not None
        limits = thresholds_for(device, self.settings)
        horizon = self.settings.health.forecast_days
        alerted = dict(previous.get("forecast_alerted") or {})
        found: dict[str, Any] = {}
        for metric, label, unit in FORECAST_METRICS:
            pair = limits.memory if metric == "memory" else limits.temperature
            if pair.warning is None and pair.critical is None:
                continue
            result = forecast(self.history.hourly(device.name, metric, stamp - 7 * 86400), pair.warning, pair.critical, metric)
            if result is None:
                alerted.pop(metric, None)
                continue
            found[metric] = result.to_dict()
            soon = horizon > 0 and result.eta_days <= horizon
            if soon and not alerted.get(metric):
                when = time.strftime("%a %b %d", time.localtime(result.breach_at))
                events.append(Event(
                    "capacity_forecast", "warning",
                    f"{device.name}: {label.lower()} predicted to reach {result.threshold:g}{unit} in ~{format_duration(result.eta_seconds, coarse=True)}",
                    f"{label} is rising {result.slope_per_day:.1f}{unit}/day (now {result.current:.0f}{unit}); at this rate it crosses "
                    f"the {result.level} threshold of {result.threshold:g}{unit} around {when}.",
                    device=device.name, site=device.site or None, platform=device.platform,
                    details={"metric": metric, **result.to_dict()}, timestamp=stamp,
                ))
            if soon:
                alerted[metric] = True
            else:
                alerted.pop(metric, None)
        return {"forecast": found, "forecast_alerted": alerted}
