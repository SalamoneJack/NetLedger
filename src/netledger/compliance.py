"""Configuration compliance ("golden config") checks evaluated on every backup."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

from netledger.config import ComplianceRule
from netledger.inventory import Device
from netledger.platforms import resolve_platform


@dataclass
class ComplianceResult:
    rule: str
    passed: bool
    severity: str
    description: str = ""
    findings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _globs(patterns: list[str], values: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(v.lower(), p.lower()) for p in patterns for v in values if v)


def applies(rule: ComplianceRule, device: Device) -> bool:
    if rule.platforms and device.platform not in {resolve_platform(p) or p.lower() for p in rule.platforms}:
        return False
    if rule.sites and not _globs(rule.sites, [device.site]):
        return False
    if rule.groups and not _globs(rule.groups, device.groups):
        return False
    if rule.tags and not _globs(rule.tags, device.tags):
        return False
    return not (rule.devices and not _globs(rule.devices, [device.name]))


def evaluate(
    rules: list[ComplianceRule],
    device: Device,
    config: str,
    mask: Callable[[str], str] | None = None,
) -> list[ComplianceResult]:
    """Evaluate all applicable rules against a (normalized, unmasked) configuration."""
    results = []
    for rule in rules:
        if not applies(rule, device):
            continue
        findings: list[str] = []
        passed = True
        if rule.must_match and not re.search(rule.must_match, config, re.M):
            passed = False
            findings.append(f"missing: /{rule.must_match}/")
        if rule.must_not_match:
            hits = [m.group(0).strip() for m in re.finditer(rule.must_not_match, config, re.M)]
            if hits:
                passed = False
                lines = []
                for hit in hits[:5]:
                    line = next((text for text in config.splitlines() if hit and hit in text), hit)
                    lines.append(mask(line).strip() if mask else line.strip())
                findings.extend(f"found: {line}" for line in lines)
                if len(hits) > 5:
                    findings.append(f"... and {len(hits) - 5} more")
        results.append(ComplianceResult(rule.name, passed, rule.severity, rule.description, findings))
    return results
