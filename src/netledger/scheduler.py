"""Job scheduling: 5-field cron expressions, ``@hourly``-style macros and ``every 15m`` intervals."""

from __future__ import annotations

import logging
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, tzinfo
from typing import Callable

log = logging.getLogger(__name__)

MACROS = {
    "@yearly": "0 0 1 1 *",
    "@annually": "0 0 1 1 *",
    "@monthly": "0 0 1 * *",
    "@weekly": "0 0 * * 0",
    "@daily": "0 0 * * *",
    "@midnight": "0 0 * * *",
    "@hourly": "0 * * * *",
}
MONTHS = {m: i for i, m in enumerate(["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}
DAYS = {d: i for i, d in enumerate(["sun", "mon", "tue", "wed", "thu", "fri", "sat"])}
_INTERVAL = re.compile(r"^every\s+(\d+)\s*(s|sec|secs|seconds?|m|min|mins|minutes?|h|hr|hrs|hours?|d|days?)$", re.I)


class ScheduleError(ValueError):
    pass


def _parse_field(text: str, low: int, high: int, names: dict[str, int] | None = None) -> set[int]:
    values: set[int] = set()
    for part in text.lower().split(","):
        step = 1
        if "/" in part:
            part, step_text = part.split("/", 1)
            if not step_text.isdigit() or int(step_text) == 0:
                raise ScheduleError(f"invalid step in {text!r}")
            step = int(step_text)
        if part in ("*", ""):
            start, end = low, high
        elif "-" in part:
            a, b = part.split("-", 1)
            start, end = _value(a, names), _value(b, names)
        else:
            start = _value(part, names)
            end = high if step > 1 else start
        if start < low or end > high or start > end:
            raise ScheduleError(f"value out of range in {text!r} (allowed {low}-{high})")
        values.update(range(start, end + 1, step))
    return values


def _value(text: str, names: dict[str, int] | None) -> int:
    if names and text in names:
        return names[text]
    if not text.isdigit():
        raise ScheduleError(f"invalid value {text!r}")
    return int(text)


class Schedule:
    def next_after(self, ts: float) -> float:
        raise NotImplementedError


@dataclass
class IntervalSchedule(Schedule):
    seconds: float
    expression: str = ""

    def next_after(self, ts: float) -> float:
        return ts + self.seconds


@dataclass
class CronSchedule(Schedule):
    expression: str
    tz: tzinfo | None = None
    minutes: set[int] = field(default_factory=set)
    hours: set[int] = field(default_factory=set)
    days: set[int] = field(default_factory=set)
    months: set[int] = field(default_factory=set)
    weekdays: set[int] = field(default_factory=set)
    dom_any: bool = True
    dow_any: bool = True

    @classmethod
    def parse(cls, expression: str, tz: tzinfo | None = None) -> CronSchedule:
        expr = MACROS.get(expression.strip().lower(), expression.strip())
        parts = expr.split()
        if len(parts) != 5:
            raise ScheduleError(f"cron expression {expression!r} must have 5 fields (minute hour day month weekday)")
        minute, hour, dom, month, dow = parts
        weekdays = _parse_field(dow, 0, 7, DAYS)
        if 7 in weekdays:
            weekdays = (weekdays - {7}) | {0}
        return cls(
            expression=expression,
            tz=tz,
            minutes=_parse_field(minute, 0, 59),
            hours=_parse_field(hour, 0, 23),
            days=_parse_field(dom, 1, 31),
            months=_parse_field(month, 1, 12, MONTHS),
            weekdays=weekdays,
            dom_any=dom.strip() in ("*", "?"),
            dow_any=dow.strip() in ("*", "?"),
        )

    def _day_matches(self, dt: datetime) -> bool:
        dom_ok = dt.day in self.days
        dow_ok = ((dt.weekday() + 1) % 7) in self.weekdays
        if self.dom_any and self.dow_any:
            return True
        if self.dom_any:
            return dow_ok
        if self.dow_any:
            return dom_ok
        return dom_ok or dow_ok

    def next_after(self, ts: float) -> float:
        dt = datetime.fromtimestamp(ts, tz=self.tz).replace(second=0, microsecond=0) + timedelta(minutes=1)
        naive = dt.replace(tzinfo=None)
        for _ in range(366 * 24 * 60 * 5):
            if naive.month not in self.months:
                naive = (naive.replace(day=1, hour=0, minute=0) + timedelta(days=32)).replace(day=1)
                continue
            if not self._day_matches(naive):
                naive = naive.replace(hour=0, minute=0) + timedelta(days=1)
                continue
            if naive.hour not in self.hours:
                naive = naive.replace(minute=0) + timedelta(hours=1)
                continue
            if naive.minute not in self.minutes:
                naive += timedelta(minutes=1)
                continue
            if self.tz is not None:
                return naive.replace(tzinfo=self.tz).timestamp()
            return time.mktime(naive.timetuple())
        raise ScheduleError(f"cron expression {self.expression!r} never fires")


def parse_schedule(expression: str, tz: tzinfo | None = None) -> Schedule:
    text = expression.strip()
    match = _INTERVAL.match(text)
    if match:
        amount, unit = int(match.group(1)), match.group(2).lower()
        factor = 1 if unit.startswith("s") else 60 if unit.startswith("m") else 3600 if unit.startswith("h") else 86400
        if amount <= 0:
            raise ScheduleError("interval must be positive")
        return IntervalSchedule(amount * factor, text)
    return CronSchedule.parse(text, tz)


def load_timezone(name: str | None) -> tzinfo | None:
    if not name:
        return None
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(name)
    except Exception as exc:  # noqa: BLE001
        raise ScheduleError(f"unknown time zone {name!r}: {exc}") from exc


@dataclass
class Job:
    name: str
    schedule: Schedule
    func: Callable[[], object]
    next_run: float = 0.0
    running: bool = False
    last_started: float | None = None
    last_finished: float | None = None
    last_error: str | None = None


class Scheduler:
    """Runs jobs on their schedules in background threads; a job never overlaps with itself."""

    def __init__(self) -> None:
        self.jobs: dict[str, Job] = {}
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._lock = threading.Lock()

    def add(self, name: str, schedule: Schedule, func: Callable[[], object], run_now: bool = False) -> None:
        start = time.time()
        self.jobs[name] = Job(name, schedule, func, next_run=start if run_now else schedule.next_after(start))

    def trigger(self, name: str) -> bool:
        """Start a job immediately. Returns False if it is already running."""
        job = self.jobs.get(name)
        if job is None:
            raise KeyError(name)
        with self._lock:
            if job.running:
                return False
            self._start(job)
            return True

    def _start(self, job: Job) -> None:
        job.running = True
        job.last_started = time.time()
        threading.Thread(target=self._run, args=(job,), name=f"job-{job.name}", daemon=True).start()

    def _run(self, job: Job) -> None:
        try:
            job.func()
            job.last_error = None
        except Exception as exc:  # noqa: BLE001
            job.last_error = str(exc)
            log.exception("job %s failed", job.name)
        finally:
            job.last_finished = time.time()
            job.running = False

    def run_forever(self) -> None:
        while not self._stop.is_set():
            current = time.time()
            for job in self.jobs.values():
                if job.next_run <= current:
                    with self._lock:
                        if job.running:
                            log.warning("job %s is still running; skipping this run", job.name)
                        else:
                            self._start(job)
                    job.next_run = job.schedule.next_after(current)
            wait = min((job.next_run for job in self.jobs.values()), default=current + 60) - time.time()
            self._wake.wait(timeout=max(0.5, min(wait, 60)))
            self._wake.clear()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def status(self) -> dict[str, dict[str, object]]:
        return {
            name: {
                "running": job.running,
                "next_run": job.next_run,
                "last_started": job.last_started,
                "last_finished": job.last_finished,
                "last_error": job.last_error,
                "schedule": getattr(job.schedule, "expression", ""),
            }
            for name, job in self.jobs.items()
        }
