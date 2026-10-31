"""Parsing helpers shared by the built-in drivers."""

from __future__ import annotations

import re
from typing import Any

_UNIT_SECONDS = [
    (r"years?|yrs?|y", 365 * 86400),
    (r"months?|mo", 30 * 86400),
    (r"weeks?|wks?|w", 7 * 86400),
    (r"days?|d", 86400),
    (r"hours?|hrs?|h", 3600),
    (r"minutes?|mins?|m", 60),
    (r"seconds?|secs?|s", 1),
]
_DURATION_TOKEN = re.compile(
    r"(\d+(?:\.\d+)?)\s*(" + "|".join(unit for unit, _ in _UNIT_SECONDS) + r")(?![a-z])", re.I
)
_CLOCK = re.compile(r"(?<![\d:])(\d{1,3}):(\d{2})(?::(\d{2}))?(?![\d:])")


def parse_duration(text: str | None) -> float | None:
    """Parse uptime strings such as ``10 days, 3 hours, 5 minutes``, ``1w2d3h4m5s`` or ``2 days 03:25:10``."""
    if not text:
        return None
    total = 0.0
    found = False
    remaining = text
    clock = _CLOCK.search(remaining)
    if clock:
        hours, minutes, seconds = clock.group(1), clock.group(2), clock.group(3) or "0"
        total += int(hours) * 3600 + int(minutes) * 60 + int(seconds)
        remaining = remaining[: clock.start()] + " " + remaining[clock.end() :]
        found = True
    for amount, unit in _DURATION_TOKEN.findall(remaining):
        unit = unit.lower()
        for pattern, seconds in _UNIT_SECONDS:
            if re.fullmatch(pattern, unit):
                total += float(amount) * seconds
                found = True
                break
    return total if found else None


_SIZE_RE = re.compile(r"^\s*([\d.,]+)\s*([kmgt]?)(i?)(b|bytes?)?\s*$", re.I)
_SIZE_FACTORS = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}


def parse_size(text: str | None, default_unit: str = "") -> int | None:
    """Parse ``852.4MiB``, ``1907272k``, ``333,447,168`` or ``4 GB`` into bytes (binary multiples)."""
    if text is None:
        return None
    text = str(text).strip()
    if text.lower().endswith(("kbytes", "mbytes", "gbytes")):
        text = text[:-5] + "B"
    match = _SIZE_RE.match(text)
    if not match:
        return None
    number = float(match.group(1).replace(",", ""))
    prefix = (match.group(2) or default_unit).lower()
    return int(number * _SIZE_FACTORS.get(prefix, 1))


def to_float(value: Any) -> float | None:
    try:
        return float(str(value).strip().rstrip("%CcVv").replace(",", ""))
    except (TypeError, ValueError):
        return None


def search(pattern: str, text: str | None, group: int | str = 1, flags: int = re.M | re.I) -> str | None:
    if not text:
        return None
    match = re.search(pattern, text, flags)
    if not match:
        return None
    value = match.group(group)
    return value.strip() if isinstance(value, str) else value


def parse_kv(text: str | None, separator: str = ":") -> dict[str, str]:
    """Parse ``Key : value`` lines (also handles dot leaders: ``Key........ value``)."""
    result: dict[str, str] = {}
    if not text:
        return result
    pattern = re.compile(rf"^\s*([^{re.escape(separator)}\n]+?)\s*(?:\.{{2,}}\s*)?{re.escape(separator)}\s*(.*?)\s*$")
    dotted = re.compile(r"^\s*([^.\n]+?)\.{2,}\s*:?\s*(.*?)\s*$")
    for line in text.splitlines():
        match = dotted.match(line) or pattern.match(line)
        if match:
            key = match.group(1).strip()
            if key and key not in result:
                result[key] = match.group(2).strip()
    return result


def parse_top(text: str | None) -> tuple[float | None, int | None, int | None]:
    """CPU usage %, total and used memory (bytes) from Linux ``top`` style output."""
    if not text:
        return None, None, None
    cpu = None
    idle = search(r"Cpu\(s\):.*?([\d.]+)\s*%?\s*id", text)
    if idle is not None:
        cpu = round(100.0 - float(idle), 1)
    total = used = None
    match = re.search(
        r"^\s*(KiB|MiB|GiB)?\s*Mem\s*:\s*([\d.]+)k?\s+total,\s*([\d.]+)k?\s+(free|used),\s*([\d.]+)k?\s+(free|used)",
        text,
        re.M | re.I,
    )
    if match:
        factor = {"kib": 1024, "mib": 1024**2, "gib": 1024**3}.get((match.group(1) or "kib").lower(), 1024)
        values = {match.group(4).lower(): float(match.group(3)), match.group(6).lower(): float(match.group(5))}
        total = int(float(match.group(2)) * factor)
        if "used" in values:
            used = int(values["used"] * factor)
        elif "free" in values:
            used = total - int(values["free"] * factor)
    return cpu, total, used


def parse_meminfo(text: str | None) -> tuple[int | None, int | None]:
    """Total and used memory (bytes) from ``/proc/meminfo``."""
    if not text:
        return None, None
    total = search(r"^MemTotal:\s*(\d+)\s*kB", text)
    available = search(r"^MemAvailable:\s*(\d+)\s*kB", text)
    if available is None:
        free = search(r"^MemFree:\s*(\d+)\s*kB", text)
        buffers = search(r"^Buffers:\s*(\d+)\s*kB", text) or "0"
        cached = search(r"^Cached:\s*(\d+)\s*kB", text) or "0"
        if free is not None:
            available = str(int(free) + int(buffers) + int(cached))
    if total is None or available is None:
        return None, None
    return int(total) * 1024, (int(total) - int(available)) * 1024


def status_ok(value: str | None) -> bool | None:
    """Map vendor status words to ok (True) / failed (False) / unknown (None)."""
    if value is None:
        return None
    word = value.strip().lower()
    if word in ("ok", "good", "normal", "up", "on", "operational", "powered", "powered on", "present", "running", "active", "green", "true", "fan ok"):
        return True
    if any(token in word for token in ("fail", "fault", "bad", "error", "down", "abnormal", "alarm", "critical", "off", "red", "not powered", "no supply")):
        return False
    return None


def section(text: str | None, start: str, end: str | None = None) -> str:
    """Text between a line matching ``start`` and the next line matching ``end``."""
    if not text:
        return ""
    lines = text.splitlines()
    out: list[str] = []
    active = False
    start_re = re.compile(start, re.I)
    end_re = re.compile(end, re.I) if end else None
    for line in lines:
        if not active:
            if start_re.search(line):
                active = True
            continue
        if end_re and end_re.search(line):
            break
        out.append(line)
    return "\n".join(out)


def hostname_from_prompt(prompt: str | None) -> str:
    """Extract a hostname from a CLI prompt like ``router1#``, ``<HUAWEI>``, ``[admin@MikroTik] >``."""
    if not prompt:
        return ""
    value = prompt.strip()
    value = re.sub(r"\s*[#>$%]\s*$", "", value).strip()
    value = value.strip("<>[]").strip()
    value = re.sub(r"\s*\([^)]*\)\s*$", "", value)
    if "@" in value:
        value = value.split("@", 1)[1]
    value = value.strip("<>[] ")
    return value.split()[0] if value.split() else ""
