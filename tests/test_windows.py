"""Change windows: parsing and 'could this change have happened inside a window?'."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from netledger.config import ConfigError, settings_from_dict
from netledger.windows import ChangeCalendar, WindowError, describe_window, parse_window

UTC = timezone.utc


def ts(text: str) -> float:
    return datetime.strptime(text, "%Y-%m-%d %H:%M").replace(tzinfo=UTC).timestamp()


def test_parse_window_forms() -> None:
    assert [w.weekday for w in parse_window("daily 02:00-03:30")] == list(range(7))
    assert [w.weekday for w in parse_window("weekdays 19:00-21:00")] == [0, 1, 2, 3, 4]
    assert [w.weekday for w in parse_window("fri-mon 01:00-02:00")] == [0, 4, 5, 6]
    overnight = parse_window("fri 23:00-02:00")[0]
    assert overnight.weekday == 4 and overnight.duration == 180
    weekend = parse_window("sat 22:00-sun 04:00")[0]
    assert weekend.weekday == 5 and weekend.duration == 360 and describe_window(weekend) == "Sat 22:00-04:00"
    for bad in ("someday 01:00-02:00", "mon 25:00-26:00", "mon,tue 22:00-wed 01:00", "every night"):
        with pytest.raises(WindowError):
            parse_window(bad)


def test_overlap_rules() -> None:
    calendar = ChangeCalendar(["sat 22:00-sun 04:00", "weekdays 19:00-21:00"], UTC)
    assert calendar.enabled
    # 2026-10-31 is a Saturday
    assert calendar.contains(ts("2026-10-31 23:30")) and calendar.contains(ts("2026-11-01 03:59"))
    assert not calendar.contains(ts("2026-10-31 14:00"))
    assert calendar.contains(ts("2026-10-29 19:30"))  # Thursday evening
    # a change found at 14:10, previous backup at 13:10: no window in between -> unplanned
    assert not calendar.overlaps(ts("2026-10-29 13:10"), ts("2026-10-29 14:10"))
    # the previous backup was before last night's window: it may have been made inside it
    assert calendar.overlaps(ts("2026-10-29 18:00"), ts("2026-10-29 22:00"))
    assert calendar.overlaps(ts("2026-10-01 00:00"), ts("2026-10-20 00:00"))  # a week or more always overlaps
    assert calendar.next_open(ts("2026-10-29 14:00")) == ts("2026-10-29 19:00")
    assert calendar.next_open(ts("2026-10-29 19:30")) is None  # open now
    assert ChangeCalendar([], None).overlaps(0, 1) and not ChangeCalendar([], None).enabled


def test_windows_are_validated_with_the_settings() -> None:
    settings = settings_from_dict({"changes": {"windows": ["daily 01:00-04:00"], "timezone": "UTC"}})
    assert settings.changes.windows == ["daily 01:00-04:00"]
    with pytest.raises(ConfigError, match="changes.windows"):
        settings_from_dict({"changes": {"windows": ["whenever"]}})
