"""Persistent run state (last backup/health result per device) used by alerts, the dashboard and metrics."""

from __future__ import annotations

import copy
import json
import logging
import threading
import time
from pathlib import Path
from typing import Any

from netledger.utils import atomic_write

log = logging.getLogger(__name__)

STATE_VERSION = 1
ACTIVITY_KEEP = 300
DIFFS_KEPT = 100


class StateStore:
    """Thread-safe JSON state file. Losing it is harmless: it only drives de-duplication and display."""

    def __init__(self, path: Path | None):
        self.path = path
        self._lock = threading.RLock()
        self._data = self._load()
        self.revision = 0  # bumped on every change; lets dashboards poll cheaply

    @classmethod
    def in_memory(cls) -> StateStore:
        return cls(None)

    def _empty(self) -> dict[str, Any]:
        return {"version": STATE_VERSION, "devices": {}, "runs": {}, "changes": [], "activity": [], "activity_seq": 0, "cursors": {}}

    def _load(self) -> dict[str, Any]:
        if self.path is None or not self.path.exists():
            return self._empty()
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or "devices" not in data:
                raise ValueError("unexpected structure")
            data.setdefault("runs", {})
            data.setdefault("changes", [])
            data.setdefault("activity", [])
            data.setdefault("cursors", {})
            data.setdefault("activity_seq", max((int(a.get("id") or 0) for a in data["activity"]), default=0))
            return data
        except (OSError, ValueError) as exc:
            backup = self.path.with_suffix(f".corrupt-{int(time.time())}")
            log.warning("state file %s is unreadable (%s); starting fresh (old copy: %s)", self.path, exc, backup.name)
            try:
                self.path.replace(backup)
            except OSError:
                pass
            return self._empty()

    def reload(self) -> None:
        with self._lock:
            self._data = self._load()
            self.revision += 1

    def _touch(self) -> None:
        self.revision += 1

    def device(self, name: str) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._data["devices"].get(name, {}))

    def section(self, name: str, section: str) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._data["devices"].get(name, {}).get(section, {}))

    def update(self, name: str, section: str, values: dict[str, Any], replace: bool = False) -> None:
        with self._lock:
            device = self._data["devices"].setdefault(name, {})
            if replace or not isinstance(device.get(section), dict):
                device[section] = {}
            device[section].update(copy.deepcopy(values))
            self._touch()

    def set_info(self, name: str, info: dict[str, Any]) -> None:
        self.update(name, "info", info, replace=True)

    def set_run(self, job: str, info: dict[str, Any]) -> None:
        with self._lock:
            self._data["runs"][job] = copy.deepcopy(info)
            self._touch()

    # ------------------------------------------------------------------ change ledger and activity feed

    def record_change(self, entry: dict[str, Any], keep: int = 1000) -> None:
        """Append a configuration change to the ledger (newest last); only recent entries keep their diff."""
        with self._lock:
            changes = self._data.setdefault("changes", [])
            changes.append(copy.deepcopy(entry))
            if keep >= 0 and len(changes) > keep:
                del changes[: len(changes) - keep]
            for old in changes[:-DIFFS_KEPT]:
                old.pop("diff", None)
            self._touch()

    def changes(self, limit: int | None = None, device: str | None = None) -> list[dict[str, Any]]:
        """Newest first."""
        with self._lock:
            items = [c for c in reversed(self._data.get("changes") or []) if device is None or c.get("device") == device]
            return copy.deepcopy(items[:limit] if limit else items)

    def record_events(self, events: list[Any]) -> None:
        if not events:
            return
        with self._lock:
            feed = self._data.setdefault("activity", [])
            for event in events:
                self._data["activity_seq"] = int(self._data.get("activity_seq") or 0) + 1
                feed.append({
                    "id": self._data["activity_seq"],
                    "ts": event.timestamp,
                    "type": event.type,
                    "severity": event.severity,
                    "title": event.title,
                    "message": (event.message or "")[:500],
                    "device": event.device,
                    "site": event.site,
                    "risk": (event.details or {}).get("risk"),
                })
            if len(feed) > ACTIVITY_KEEP:
                del feed[: len(feed) - ACTIVITY_KEEP]
            self._touch()

    def activity(self, after: int = 0, limit: int = 50) -> list[dict[str, Any]]:
        """Newest first."""
        with self._lock:
            items = [a for a in reversed(self._data.get("activity") or []) if int(a.get("id") or 0) > after]
            return copy.deepcopy(items[:limit])

    @property
    def activity_cursor(self) -> int:
        with self._lock:
            return int(self._data.get("activity_seq") or 0)

    # ------------------------------------------------------------------ cursors (how far an external source was read)

    def cursor(self, name: str) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy((self._data.get("cursors") or {}).get(name) or {})

    def set_cursor(self, name: str, value: dict[str, Any]) -> None:
        with self._lock:
            self._data.setdefault("cursors", {})[name] = copy.deepcopy(value)
            self._touch()

    def runs(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._data["runs"])

    def device_names(self) -> list[str]:
        with self._lock:
            return sorted(self._data["devices"])

    def forget(self, names: set[str]) -> None:
        with self._lock:
            for name in names:
                self._data["devices"].pop(name, None)
            self._touch()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._data)

    def save(self) -> None:
        if self.path is None:
            return
        with self._lock:
            payload = json.dumps(self._data, indent=1, sort_keys=True, default=str)
        try:
            atomic_write(self.path, payload + "\n")
        except OSError as exc:
            log.error("could not write state file %s: %s", self.path, exc)
