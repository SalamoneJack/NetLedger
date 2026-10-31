"""Events emitted by backup, health and compliance runs and delivered by notifiers."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}
RECOVERY_EVENTS = {"backup_recovered", "health_recovered", "compliance_passed"}


def severity_at_least(severity: str, minimum: str) -> bool:
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(minimum, 0)


@dataclass
class Event:
    type: str
    severity: str
    title: str
    message: str = ""
    device: str | None = None
    site: str | None = None
    platform: str | None = None
    diff: str | None = None
    links: dict[str, str] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    @property
    def is_recovery(self) -> bool:
        return self.type in RECOVERY_EVENTS

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
