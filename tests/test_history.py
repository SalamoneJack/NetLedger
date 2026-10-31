"""Health history (SQLite), forecasts and the health runner's forecast alerts."""

from __future__ import annotations

import time

import pytest

from netledger.health import HealthRunner
from netledger.history import MetricsHistory, Sample, forecast, linear_fit
from netledger.inventory import load_inventory
from netledger.state import StateStore

from .conftest import simulated


def test_series_strips_sparks_and_fleet(tmp_path) -> None:  # noqa: ANN001
    history = MetricsHistory(tmp_path / "history.db")
    now = time.time()
    samples = []
    for step in range(48):
        at = now - 86400 + step * 1800 + 60
        samples.append(Sample("a", at, "ok" if step < 40 else "warning", cpu=10 + step, memory=50.0, temperature=40.0, latency=0.5))
        samples.append(Sample("b", at, "critical" if step == 47 else "ok", cpu=5.0, memory=None, temperature=None))
    history.record(samples)
    series = history.series("a", now - 86400, now, points=24)
    assert len(series["t"]) == 24 and series["cpu"][0] == 10.5 and series["status"][-1] == 2
    strips = history.strips(now - 86400, 48, now)
    assert strips["a"][0] == 0 and strips["a"][-1] == 2 and strips["b"][-1] == 3
    sparks = history.sparks("cpu", now - 86400, 24, now)
    assert len(sparks["a"]) == 24 and sparks["b"][0] == 5.0
    fleet = history.fleet(now - 86400, 48, now)
    assert fleet[0] == {"ok": 2, "unknown": 0, "warning": 0, "critical": 0} and fleet[-1]["critical"] == 1
    assert history.devices() == ["a", "b"]
    with pytest.raises(ValueError):
        history.sparks("cpu; drop table samples", now - 60)
    history.forget(["b"])
    assert history.devices() == ["a"]
    history.close()


def test_retention_and_broken_database(tmp_path) -> None:  # noqa: ANN001
    history = MetricsHistory(tmp_path / "h.db", retention_days=1)
    history.record([Sample("old", time.time() - 3 * 86400, "ok", cpu=1)])
    history._last_prune = 0
    history.record([Sample("new", time.time(), "ok", cpu=1)])
    assert history.devices() == ["new"]
    history.close()
    broken = tmp_path / "broken.db"
    broken.write_bytes(b"this is not a database" * 100)
    damaged = MetricsHistory(broken)
    damaged.record([Sample("x", time.time(), "ok")])  # logged, never raised
    assert damaged.series("x", 0)["t"] == []


def test_forecast_math() -> None:
    assert linear_fit([(0, 1), (1, 3), (2, 5)]) == (2.0, 1.0, 1.0)
    now = time.time()
    leak = [(now - 7 * 86400 + h * 3600, 75 + 2.0 * h / 24) for h in range(168)]
    result = forecast(leak, warning=85, critical=95)
    assert result is not None and result.level == "critical" and result.threshold == 95
    assert result.slope_per_day == pytest.approx(2.0, abs=0.01) and result.eta_days == pytest.approx((95 - 88.917) / 2, abs=0.05)
    assert forecast(leak, warning=None, critical=None) is None
    flat = [(now - 7 * 86400 + h * 3600, 50 + (h % 5)) for h in range(168)]
    assert forecast(flat, 85, 95) is None
    assert forecast(leak[:10], 85, 95) is None  # too few points
    falling = [(t, 200 - v) for t, v in leak]
    assert forecast(falling, 85, 95) is None


def test_health_runner_records_history_and_alerts_on_forecast(make_env) -> None:  # noqa: ANN001
    settings = make_env([simulated("asa1", "asa", memory=89, memory_leak=2.0), simulated("ok1", "ios")], health={"forecast_days": 7})
    state = StateStore(settings.data_path / "state.json")
    history = MetricsHistory.for_settings(settings)
    now = time.time()
    history.record([Sample("asa1", now - 7 * 86400 + h * 3600, "ok", memory=75 + 2.0 * h / 24) for h in range(168)])
    report = HealthRunner(settings, state, history=history).run(load_inventory(settings))
    events = [e for e in report.events if e.type == "capacity_forecast"]
    assert len(events) == 1 and events[0].device == "asa1" and "memory predicted to reach 95%" in events[0].title
    health = state.section("asa1", "health")
    assert health["forecast"]["memory"]["threshold"] == 95 and health["forecast_alerted"] == {"memory": True}
    again = HealthRunner(settings, state, history=history).run(load_inventory(settings))
    assert not [e for e in again.events if e.type == "capacity_forecast"]  # alerts once per episode
    assert history._query("SELECT count(*) FROM samples WHERE device = 'ok1'", ()) == [(2,)]
    assert state.activity(limit=5)[0]["type"] == "capacity_forecast"
    history.close()


def test_runner_without_history(make_env) -> None:  # noqa: ANN001
    settings = make_env([simulated("x", "ios")], health={"history": False})
    report = HealthRunner(settings, StateStore.in_memory()).run(load_inventory(settings))
    assert report.results[0].status == "ok" and not (settings.data_path / "history.db").exists()
