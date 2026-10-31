"""Small helpers shared across NetLedger."""

from __future__ import annotations

import difflib
import hashlib
import os
import re
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

_SLUG_RE = re.compile(r"[^a-z0-9]+")
_UNSAFE_PATH_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_WIN_RESERVED = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}


def slugify(value: str, max_length: int = 80) -> str:
    """Lower-case, dash-separated identifier suitable for file names."""
    slug = _SLUG_RE.sub("-", value.lower()).strip("-")
    return slug[:max_length].rstrip("-") or "item"


def safe_path_component(value: str) -> str:
    """Make a string safe to use as a single path component on both Linux and Windows."""
    cleaned = _UNSAFE_PATH_CHARS.sub("_", str(value)).strip().rstrip(".")
    if not cleaned or cleaned in {".", ".."}:
        cleaned = "_"
    if cleaned.split(".")[0].lower() in _WIN_RESERVED:
        cleaned = f"_{cleaned}"
    return cleaned


def now() -> float:
    return time.time()


def iso(ts: float | None) -> str | None:
    """Format an epoch timestamp as an ISO-8601 UTC string (``2024-01-31T12:00:00Z``)."""
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_iso(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def git_blob_sha(data: bytes) -> str:
    """SHA-1 that git would assign to a blob with this content."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def atomic_write(path: Path, data: str | bytes, mode: int | None = None) -> None:
    """Write a file atomically (write to a temp file in the same directory, then rename)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        if isinstance(data, bytes):
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
        else:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge ``override`` into a copy of ``base``."""
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def unified_diff(old: str | None, new: str | None, path: str, context: int = 3) -> str:
    old_lines = (old or "").splitlines(keepends=True)
    new_lines = (new or "").splitlines(keepends=True)
    if old_lines and not old_lines[-1].endswith("\n"):
        old_lines[-1] += "\n"
    if new_lines and not new_lines[-1].endswith("\n"):
        new_lines[-1] += "\n"
    diff = difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile="/dev/null" if old is None else f"a/{path}",
        tofile="/dev/null" if new is None else f"b/{path}",
        n=context,
    )
    return "".join(diff)


def diff_stats(diff: str) -> tuple[int, int]:
    """Count added and removed lines in a unified diff."""
    added = removed = 0
    for line in diff.splitlines():
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            added += 1
        elif line.startswith("-"):
            removed += 1
    return added, removed


def truncate_lines(text: str, max_lines: int, max_chars: int | None = None) -> str:
    """Trim text to a number of lines (and characters), noting how much was cut."""
    lines = text.splitlines()
    cut = len(lines) - max_lines
    if cut > 0:
        lines = lines[:max_lines] + [f"... ({cut} more lines)"]
    result = "\n".join(lines)
    if max_chars is not None and len(result) > max_chars:
        result = result[: max(0, max_chars - 20)].rstrip() + "\n... (truncated)"
    return result


def format_duration(seconds: float | None, coarse: bool = False) -> str:
    """Compact human duration: ``2.4s``, ``12m 5s`` (``12m`` when coarse), ``3h 20m``, ``3d 4h``, ``197d``."""
    if seconds is None or seconds < 0:
        return "-"
    if seconds < 10 and not coarse:
        return f"{seconds:.1f}s"
    seconds = int(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days >= 10:
        return f"{days}d"
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m" if coarse else f"{minutes}m {secs}s"
    return f"{secs}s"


def humanize_ago(ts: float | None, reference: float | None = None) -> str:
    if not ts:
        return "never"
    delta = (reference or time.time()) - ts
    if delta < 5:
        return "just now"
    if delta < 60:
        return f"{int(delta)}s ago"
    return f"{format_duration(delta, coarse=True)} ago"


def unique(items: Iterable[str]) -> list[str]:
    """De-duplicate while preserving order."""
    seen: set[str] = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def first_line(text: str, limit: int = 200) -> str:
    for line in str(text).splitlines():
        line = line.strip()
        if line:
            return line[:limit]
    return ""
