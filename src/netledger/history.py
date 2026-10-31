"""Health history in SQLite: trends, 24-hour status strips and exhaustion forecasts.

One row per device per health check (status, CPU, memory, hottest sensor, response time) in
``<data_dir>/history.db``. Retention defaults to 30 days; a fleet of 1,000 devices checked every
five minutes needs roughly 200 MB.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable, Optional, Sequence

if TYPE_CHECKING:
    from netledger.config import Settings

log = logging.getLogger(__name__)

STATUS_CODES = {"ok": 0, "unknown": 1, "warning": 2, "critical": 3}
STATUS_NAMES = {code: name for name, code in STATUS_CODES.items()}
METRICS = ("cpu", "memory", "temperature", "latency")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    device TEXT NOT NULL,
    ts INTEGER NOT NULL,
    status INTEGER,
    cpu REAL,
    memory REAL,
    temperature REAL,
    latency REAL
);
CREATE INDEX IF NOT EXISTS samples_device_ts ON samples (device, ts);
CREATE INDEX IF NOT EXISTS samples_ts ON samples (ts);
"""


@dataclass
class Sample:
    device: str
    ts: float
    status: Optional[str] = None
    cpu: Optional[float] = None
    memory: Optional[float] = None
    temperature: Optional[float] = None
    latency: Optional[float] = None


@dataclass
class Forecast:
    metric: str
    current: float
    slope_per_day: float
    threshold: float
    level: str  # the threshold that will be crossed: warning or critical
    eta_seconds: float
    r2: float
    samples: int
    fitted_at: float

    @property
    def eta_days(self) -> float:
        return self.eta_seconds / 86400

    @property
    def breach_at(self) -> float:
        return self.fitted_at + self.eta_seconds

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.update({k: round(v, 3) for k, v in data.items() if isinstance(v, float)})
        data["breach_at"] = round(self.breach_at)
        return data


def linear_fit(points: Sequence[tuple[float, float]]) -> tuple[float, float, float] | None:
    """Least squares ``y = a + b·x``: returns (slope, intercept, r²)."""
    n = len(points)
    if n < 2:
        return None
    mean_x = sum(x for x, _ in points) / n
    mean_y = sum(y for _, y in points) / n
    sxx = sum((x - mean_x) ** 2 for x, _ in points)
    if sxx == 0:
        return None
    slope = sum((x - mean_x) * (y - mean_y) for x, y in points) / sxx
    intercept = mean_y - slope * mean_x
    ss_tot = sum((y - mean_y) ** 2 for _, y in points)
    ss_res = sum((y - (intercept + slope * x)) ** 2 for x, y in points)
    r2 = 1 - ss_res / ss_tot if ss_tot > 0 else 0.0
    return slope, intercept, r2


def forecast(
    points: Sequence[tuple[float, float]],
    warning: float | None,
    critical: float | None,
    metric: str = "memory",
    min_points: int = 24,
    min_r2: float = 0.5,
    min_slope: float = 0.05,
    horizon_days: float = 60,
) -> Forecast | None:
    """When a steadily rising metric crosses its next threshold (None if it is not trending up)."""
    clean = [(t, v) for t, v in points if v is not None]
    if len(clean) < min_points or clean[-1][0] - clean[0][0] < 86400:
        return None
    last = clean[-1][0]
    fit = linear_fit([((t - last) / 86400, v) for t, v in clean])
    if fit is None:
        return None
    slope, current, r2 = fit
    if slope < min_slope or r2 < min_r2:
        return None
    targets = [(level, value) for level, value in (("warning", warning), ("critical", critical)) if value is not None and value > current]
    if not targets:
        return None
    level, threshold = min(targets, key=lambda item: item[1])
    eta_days = (threshold - current) / slope
    if eta_days > horizon_days:
        return None
    return Forecast(metric, current, slope, threshold, level, eta_days * 86400, r2, len(clean), last)


class MetricsHistory:
    """Thread-safe sample store. Errors are logged, never raised: history must not break a health run."""

    def __init__(self, path: Path | None, retention_days: int = 30):
        self.path = path
        self.retention = retention_days * 86400
        self._lock = threading.Lock()
        self._db: sqlite3.Connection | None = None
        self._last_prune = 0.0
        self._failed = False

    @classmethod
    def for_settings(cls, settings: Settings) -> MetricsHistory | None:
        if not settings.health.history:
            return None
        return cls(settings.data_path / "history.db", settings.health.history_days)

    def _conn(self) -> sqlite3.Connection:
        if self._db is None:
            if self.path is not None:
                self.path.parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(str(self.path) if self.path else ":memory:", timeout=15, check_same_thread=False)
            self._db.executescript(_SCHEMA)
        return self._db

    def close(self) -> None:
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None

    def _query(self, sql: str, params: Sequence[Any]) -> list[tuple[Any, ...]]:
        if self._failed:
            return []
        try:
            with self._lock:
                return list(self._conn().execute(sql, tuple(params)))
        except sqlite3.Error as exc:
            log.warning("health history unavailable (%s): %s", self.path, exc)
            self._failed = True
            return []

    def record(self, samples: Iterable[Sample]) -> None:
        rows = [
            (s.device, int(s.ts), STATUS_CODES.get(s.status) if s.status else None, s.cpu, s.memory, s.temperature, s.latency)
            for s in samples
        ]
        if not rows or self._failed:
            return
        try:
            with self._lock:
                db = self._conn()
                db.executemany("INSERT INTO samples VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
                current = time.time()
                if current - self._last_prune > 3600:
                    db.execute("DELETE FROM samples WHERE ts < ?", (int(current - self.retention),))
                    self._last_prune = current
                db.commit()
        except sqlite3.Error as exc:
            log.warning("could not record health history in %s: %s", self.path, exc)

    def devices(self) -> list[str]:
        return [row[0] for row in self._query("SELECT DISTINCT device FROM samples ORDER BY device", ())]

    def forget(self, names: Iterable[str]) -> None:
        names = list(names)
        if not names:
            return
        try:
            with self._lock:
                db = self._conn()
                db.executemany("DELETE FROM samples WHERE device = ?", [(n,) for n in names])
                db.commit()
        except sqlite3.Error as exc:
            log.warning("could not prune health history: %s", exc)

    # ------------------------------------------------------------------ queries

    def series(self, device: str, since: float, until: float | None = None, points: int = 96) -> dict[str, Any]:
        """Bucketed averages (and worst status) for one device."""
        until = until or time.time()
        bucket = max(60, int((until - since) / max(1, points)))
        rows = self._query(
            "SELECT (ts - ?) / ? AS b, avg(cpu), avg(memory), max(temperature), max(status), avg(latency) FROM samples "
            "WHERE device = ? AND ts >= ? AND ts <= ? GROUP BY b ORDER BY b",
            (int(since), bucket, device, int(since), int(until)),
        )
        out: dict[str, Any] = {"start": since, "end": until, "bucket": bucket, "t": [], "cpu": [], "memory": [], "temperature": [], "status": [], "latency": []}
        for b, cpu, memory, temperature, status, latency in rows:
            out["t"].append(since + b * bucket + bucket / 2)
            out["cpu"].append(_round(cpu))
            out["memory"].append(_round(memory))
            out["temperature"].append(_round(temperature))
            out["status"].append(status)
            out["latency"].append(_round(latency, 3))
        return out

    def strips(self, since: float, buckets: int = 48, until: float | None = None) -> dict[str, list[Optional[int]]]:
        """Worst status per device per bucket (for the 24-hour status strips)."""
        until = until or time.time()
        size = max(1, int((until - since) / buckets))
        rows = self._query(
            "SELECT device, (ts - ?) / ? AS b, max(status) FROM samples WHERE ts >= ? AND ts <= ? AND status IS NOT NULL GROUP BY device, b",
            (int(since), size, int(since), int(until)),
        )
        out: dict[str, list[Optional[int]]] = {}
        for device, b, status in rows:
            if 0 <= b < buckets:
                out.setdefault(device, [None] * buckets)[b] = status
        return out

    def sparks(self, metric: str, since: float, points: int = 24, until: float | None = None) -> dict[str, list[Optional[float]]]:
        if metric not in METRICS:
            raise ValueError(metric)
        until = until or time.time()
        size = max(1, int((until - since) / points))
        rows = self._query(
            f"SELECT device, (ts - ?) / ? AS b, avg({metric}) FROM samples WHERE ts >= ? AND ts <= ? GROUP BY device, b",  # noqa: S608 - metric is whitelisted
            (int(since), size, int(since), int(until)),
        )
        out: dict[str, list[Optional[float]]] = {}
        for device, b, value in rows:
            if 0 <= b < points:
                out.setdefault(device, [None] * points)[b] = _round(value)
        return out

    def fleet(self, since: float, buckets: int = 48, until: float | None = None) -> list[dict[str, int]]:
        """Number of devices in each status per bucket."""
        until = until or time.time()
        size = max(1, int((until - since) / buckets))
        rows = self._query(
            "SELECT b, s, count(*) FROM (SELECT device, (ts - ?) / ? AS b, max(status) AS s FROM samples "
            "WHERE ts >= ? AND ts <= ? AND status IS NOT NULL GROUP BY device, b) GROUP BY b, s",
            (int(since), size, int(since), int(until)),
        )
        out = [{name: 0 for name in STATUS_CODES} for _ in range(buckets)]
        for b, status, count in rows:
            if 0 <= b < buckets and status in STATUS_NAMES:
                out[b][STATUS_NAMES[status]] = count
        return out

    def hourly(self, device: str, metric: str, since: float) -> list[tuple[float, float]]:
        if metric not in METRICS:
            raise ValueError(metric)
        rows = self._query(
            f"SELECT avg(ts), avg({metric}) FROM samples WHERE device = ? AND ts >= ? AND {metric} IS NOT NULL "  # noqa: S608
            "GROUP BY ts / 3600 ORDER BY 1",
            (device, int(since)),
        )
        return [(float(t), float(v)) for t, v in rows if v is not None]


def _round(value: Any, digits: int = 1) -> Optional[float]:
    return round(float(value), digits) if value is not None else None
