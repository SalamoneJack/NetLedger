"""Change windows: when configuration changes are expected (``changes.windows``).

A window is ``<days> <HH:MM>-[<day>] <HH:MM>``::

    sat 22:00-sun 04:00      Saturday night into Sunday morning
    weekdays 19:00-21:00     Monday to Friday evenings
    daily 02:00-03:30        every night
    mon,wed 12:00-13:00      lunchtime on Mondays and Wednesdays
    fri 23:00-02:00          an end time before the start wraps past midnight

A change is *unplanned* when no window overlaps the period in which it could have
happened (between the previous successful backup and the one that found it).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, tzinfo
from typing import Iterable

DAY_NAMES = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}
DAY_LABELS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
_WINDOW = re.compile(
    r"^\s*(?P<days>[a-z*][a-z*,\-]*)\s+(?P<start>\d{1,2}:\d{2})\s*-\s*(?:(?P<endday>[a-z]+)\s+)?(?P<end>\d{1,2}:\d{2})\s*$",
    re.I,
)


class WindowError(ValueError):
    """Invalid change window expression."""


@dataclass(frozen=True)
class Window:
    weekday: int  # 0 = Monday
    start: int  # minutes after midnight
    duration: int  # minutes
    text: str


def _day(token: str, text: str) -> int:
    key = token.strip().lower()[:3]
    if key not in DAY_NAMES:
        raise WindowError(f"change window {text!r}: unknown day {token!r} (use mon..sun, weekdays, weekends or daily)")
    return DAY_NAMES[key]


def _days(spec: str, text: str) -> list[int]:
    spec = spec.lower()
    if spec in ("daily", "everyday", "*", "all"):
        return list(range(7))
    if spec in ("weekdays", "weekday"):
        return [0, 1, 2, 3, 4]
    if spec in ("weekends", "weekend"):
        return [5, 6]
    days: list[int] = []
    for part in spec.split(","):
        if "-" in part:
            first, last = (_day(p, text) for p in part.split("-", 1))
            days.extend(range(first, last + 1) if first <= last else [*range(first, 7), *range(0, last + 1)])
        elif part:
            days.append(_day(part, text))
    return sorted(set(days))


def _minutes(value: str, text: str) -> int:
    hours, minutes = (int(v) for v in value.split(":"))
    if hours > 24 or minutes > 59 or (hours == 24 and minutes):
        raise WindowError(f"change window {text!r}: invalid time {value!r}")
    return hours * 60 + minutes


def parse_window(text: str) -> list[Window]:
    match = _WINDOW.match(text or "")
    if not match:
        raise WindowError(f"change window {text!r} must look like 'sat 22:00-sun 04:00' or 'weekdays 19:00-21:00'")
    days = _days(match.group("days"), text)
    start, end = _minutes(match.group("start"), text), _minutes(match.group("end"), text)
    if match.group("endday"):
        if len(days) != 1:
            raise WindowError(f"change window {text!r}: an end day needs exactly one start day")
        span_days = (_day(match.group("endday"), text) - days[0]) % 7
        duration = span_days * 1440 + end - start
        if duration <= 0:
            duration += 7 * 1440
    else:
        duration = end - start if end > start else end + 1440 - start
    return [Window(day, start, duration, text.strip()) for day in days]


def parse_windows(texts: Iterable[str]) -> list[Window]:
    windows: list[Window] = []
    for text in texts:
        windows.extend(parse_window(text))
    return windows


class ChangeCalendar:
    """Answers "was this change made inside an approved window?"."""

    def __init__(self, windows: Iterable[str], tz: tzinfo | None = None):
        self.texts = [w.strip() for w in windows if w and w.strip()]
        self.windows = parse_windows(self.texts)
        self.tz = tz

    @property
    def enabled(self) -> bool:
        return bool(self.windows)

    def describe(self) -> str:
        return "; ".join(self.texts) if self.texts else "no change windows configured"

    def occurrences(self, start: float, end: float) -> list[tuple[float, float]]:
        """Window instances intersecting ``[start, end]`` as (open, close) timestamps."""
        found: list[tuple[float, float]] = []
        if not self.windows or end < start:
            return found
        first = datetime.fromtimestamp(start, tz=self.tz).date() - timedelta(days=8)
        last = datetime.fromtimestamp(end, tz=self.tz).date()
        day = first
        while day <= last:
            for window in self.windows:
                if day.weekday() != window.weekday:
                    continue
                opened = datetime(day.year, day.month, day.day, tzinfo=self.tz) + timedelta(minutes=window.start)
                opens = opened.timestamp()
                closes = opens + window.duration * 60
                if opens <= end and closes >= start:
                    found.append((opens, closes))
            day += timedelta(days=1)
        return sorted(found)

    def overlaps(self, start: float, end: float) -> bool:
        if not self.windows:
            return True
        if end - start >= 7 * 86400:
            return True
        return bool(self.occurrences(start, end))

    def contains(self, ts: float) -> bool:
        return self.overlaps(ts, ts)

    def next_open(self, ts: float) -> float | None:
        """Start of the next window after ``ts`` (None if a window is open now or none are configured)."""
        if not self.windows or self.contains(ts):
            return None
        upcoming = [o for o, _ in self.occurrences(ts, ts + 8 * 86400) if o > ts]
        return min(upcoming) if upcoming else None


def describe_window(window: Window) -> str:
    start = f"{window.start // 60:02d}:{window.start % 60:02d}"
    end_minutes = (window.start + window.duration) % 1440
    end = f"{end_minutes // 60:02d}:{end_minutes % 60:02d}"
    return f"{DAY_LABELS[window.weekday]} {start}-{end}"
