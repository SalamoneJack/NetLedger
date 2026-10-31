from __future__ import annotations

import threading
import time
from datetime import datetime, timezone

import pytest

from netledger.scheduler import CronSchedule, IntervalSchedule, ScheduleError, Scheduler, parse_schedule

UTC = timezone.utc


def ts(*args: int) -> float:
    return datetime(*args, tzinfo=UTC).timestamp()


def nxt(expr: str, *start: int) -> datetime:
    return datetime.fromtimestamp(CronSchedule.parse(expr, UTC).next_after(ts(*start)), tz=UTC)


def test_cron_basics() -> None:
    assert nxt("*/15 * * * *", 2026, 1, 1, 10, 7) == datetime(2026, 1, 1, 10, 15, tzinfo=UTC)
    assert nxt("0 * * * *", 2026, 1, 1, 10, 0) == datetime(2026, 1, 1, 11, 0, tzinfo=UTC)
    assert nxt("0 2 * * *", 2026, 1, 1, 3, 0) == datetime(2026, 1, 2, 2, 0, tzinfo=UTC)
    assert nxt("30 8 * * mon-fri", 2026, 1, 2, 9, 0) == datetime(2026, 1, 5, 8, 30, tzinfo=UTC)  # Fri -> Mon
    assert nxt("0 0 1 jan *", 2026, 6, 1, 0, 0) == datetime(2027, 1, 1, 0, 0, tzinfo=UTC)
    assert nxt("@hourly", 2026, 1, 1, 10, 59) == datetime(2026, 1, 1, 11, 0, tzinfo=UTC)
    assert nxt("5/20 * * * *", 2026, 1, 1, 10, 6) == datetime(2026, 1, 1, 10, 25, tzinfo=UTC)
    assert nxt("0 12 * * 7", 2026, 1, 1, 0, 0) == datetime(2026, 1, 4, 12, 0, tzinfo=UTC)  # 7 == Sunday


def test_cron_day_of_month_or_day_of_week() -> None:
    # Vixie cron: when both are restricted, either may match (the 13th OR any Friday)
    assert nxt("0 0 13 * fri", 2026, 1, 1, 0, 0) == datetime(2026, 1, 2, 0, 0, tzinfo=UTC)
    assert nxt("0 0 13 * *", 2026, 1, 1, 0, 0) == datetime(2026, 1, 13, 0, 0, tzinfo=UTC)


@pytest.mark.parametrize("expr", ["* * * *", "61 * * * *", "* 24 * * *", "*/0 * * * *", "0 0 * foo *", "a b c d e"])
def test_invalid_cron(expr: str) -> None:
    with pytest.raises(ScheduleError):
        CronSchedule.parse(expr)


def test_intervals() -> None:
    assert parse_schedule("every 15m") == IntervalSchedule(900, "every 15m")
    assert parse_schedule("every 2 hours").seconds == 7200
    assert parse_schedule("every 30s").next_after(100.0) == 130.0
    assert isinstance(parse_schedule("@daily"), CronSchedule)


def test_scheduler_trigger_never_overlaps() -> None:
    scheduler = Scheduler()
    release = threading.Event()
    runs = []

    def job() -> None:
        runs.append(time.time())
        release.wait(5)

    scheduler.add("backup", IntervalSchedule(3600), job)
    assert scheduler.trigger("backup") is True
    time.sleep(0.05)
    assert scheduler.trigger("backup") is False
    release.set()
    for _ in range(100):
        if not scheduler.jobs["backup"].running:
            break
        time.sleep(0.02)
    assert len(runs) == 1 and scheduler.status()["backup"]["last_error"] is None


def test_scheduler_runs_due_jobs_and_stops() -> None:
    scheduler = Scheduler()
    done = threading.Event()
    scheduler.add("health", IntervalSchedule(3600), done.set, run_now=True)
    thread = threading.Thread(target=scheduler.run_forever, daemon=True)
    thread.start()
    assert done.wait(5)
    scheduler.stop()
    thread.join(5)
    assert not thread.is_alive()
