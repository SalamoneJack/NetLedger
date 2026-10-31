"""Building blocks for the dashboard: icons, pills, inline SVG charts, gauges, faceplates, code and diffs.

Everything is rendered on the server as plain HTML + SVG (no external assets), so pages work on
air-gapped management networks and look the same in screenshots and in the browser.
"""

from __future__ import annotations

import difflib
import html
import json
import math
import re
import time
from typing import Any, Iterable, Optional, Sequence

from netledger.intel import RISK_ORDER, Parsed, parse
from netledger.utils import format_duration, humanize_ago

STATUS_LABEL = {
    "ok": "Healthy", "warning": "Warning", "critical": "Critical", "unknown": "Unknown", "failed": "Failed",
    "pending": "Pending", "passed": "Pass", "external": "Discovered",
}
TONE = {"ok": "ok", "passed": "ok", "warning": "warn", "critical": "crit", "failed": "crit", "unknown": "unk", "pending": "unk", "external": "unk"}
RISK_TONE = {"high": "crit", "medium": "warn", "low": "low"}
CHECK_NAMES = {
    "reachability": "Reachability", "cpu": "CPU", "memory": "Memory", "temperature": "Temperature",
    "fans": "Fans", "power": "Power supplies", "environment": "Environment",
}

LOGO = (
    '<svg class="logo" viewBox="0 0 32 32" width="32" height="32" aria-hidden="true">'
    '<defs><linearGradient id="nlg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#7c8cff"/>'
    '<stop offset="1" stop-color="#2fd5e6"/></linearGradient></defs>'
    '<rect x="1.5" y="1.5" width="29" height="29" rx="8" fill="url(#nlg)"/>'
    '<path d="M9 10.5h14M9 16h8.5M9 21.5h11" stroke="#0a0f1e" stroke-width="2.6" stroke-linecap="round"/>'
    '<circle cx="22.5" cy="16" r="2.7" fill="#0a0f1e"/></svg>'
)

# 24x24 stroke icons (drawn for NetLedger).
ICONS: dict[str, str] = {
    "grid": '<rect x="3.5" y="3.5" width="7" height="7" rx="1.6"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.6"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.6"/><rect x="13.5" y="13.5" width="7" height="7" rx="1.6"/>',
    "map": '<circle cx="6" cy="6.5" r="2.5"/><circle cx="18" cy="6.5" r="2.5"/><circle cx="12" cy="17.5" r="2.5"/><path d="M8.3 7.6 10.6 15.3M15.7 7.6 13.4 15.3M8.5 6.5h7"/>',
    "commit": '<circle cx="12" cy="12" r="3.5"/><path d="M3 12h5.5M15.5 12H21"/>',
    "target": '<circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="4"/><path d="M12 1.5v4M12 18.5v4M1.5 12h4M18.5 12h4"/>',
    "search": '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m15.5 15.5 5 5"/>',
    "tv": '<rect x="2.5" y="4.5" width="19" height="12.5" rx="2"/><path d="M8 20.5h8M12 17v3.5"/>',
    "cpu": '<rect x="6.5" y="6.5" width="11" height="11" rx="2"/><rect x="9.5" y="9.5" width="5" height="5" rx=".8"/><path d="M9.5 3v3.5M14.5 3v3.5M9.5 17.5V21M14.5 17.5V21M3 9.5h3.5M3 14.5h3.5M17.5 9.5H21M17.5 14.5H21"/>',
    "memory": '<rect x="3" y="7" width="18" height="10" rx="1.5"/><path d="M7 10.5v3M11 10.5v3M15 10.5v3M6 17v2.5M18 17v2.5M12 17v2.5"/>',
    "thermo": '<path d="M14 14.8V5a2 2 0 0 0-4 0v9.8a4 4 0 1 0 4 0Z"/><path d="M12 9v7"/>',
    "fan": '<circle cx="12" cy="12" r="1.8"/><path d="M12 10.2C11 6 12.3 3.5 15 3.5c2.6 0 3 3.6-3 6.7M13.8 12c4.2-1 6.7.3 6.7 3 0 2.6-3.6 3-6.7-3M12 13.8c1 4.2-.3 6.7-3 6.7-2.6 0-3-3.6 3-6.7M10.2 12C6 13 3.5 11.7 3.5 9c0-2.6 3.6-3 6.7 3"/>',
    "power": '<path d="M13 2.5 5 13.5h6.5L10.5 21.5 19 10.5h-6.5L13 2.5Z"/>',
    "shield": '<path d="M12 2.8 4.5 5.6v6.1c0 4.6 3.1 8.1 7.5 9.5 4.4-1.4 7.5-4.9 7.5-9.5V5.6L12 2.8Z"/><path d="M4.8 10.5h14.4M12 10.5v10.6"/>',
    "router": '<circle cx="12" cy="12" r="8.5"/><path d="M8.5 8.5 11 11M15.5 15.5 13 13M15.5 8.5 13 11M8.5 15.5 11 13M7.8 11.3V8h3.3M16.2 12.7V16h-3.3M12.7 7.8H16v3.3M11.3 16.2H8v-3.3"/>',
    "switch": '<rect x="2.5" y="6.5" width="19" height="11" rx="2"/><path d="M6 10.5h9l-2-2M18 13.5H9l2 2"/>',
    "wireless": '<path d="M4 9.5a11.5 11.5 0 0 1 16 0M7 12.6a7.3 7.3 0 0 1 10 0M9.8 15.6a3.2 3.2 0 0 1 4.4 0"/><circle cx="12" cy="18.6" r="1.1"/>',
    "host": '<rect x="4" y="3.5" width="16" height="7" rx="1.5"/><rect x="4" y="13.5" width="16" height="7" rx="1.5"/><path d="M7.5 7h.01M7.5 17h.01"/>',
    "alert": '<path d="M10.3 4.2 2.6 17.6A2 2 0 0 0 4.3 20.5h15.4a2 2 0 0 0 1.7-2.9L13.7 4.2a2 2 0 0 0-3.4 0Z"/><path d="M12 9.5v4M12 17h.01"/>',
    "check": '<circle cx="12" cy="12" r="9"/><path d="m8 12.3 2.7 2.7L16 9.7"/>',
    "x": '<path d="M6 6l12 12M18 6 6 18"/>',
    "xcircle": '<circle cx="12" cy="12" r="9"/><path d="m9 9 6 6M15 9l-6 6"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5.2l3.2 2"/>',
    "history": '<path d="M3.5 12a8.5 8.5 0 1 0 2.5-6"/><path d="M3 4v4h4M12 7.5v4.7l3 1.8"/>',
    "user": '<circle cx="12" cy="8" r="3.8"/><path d="M4.5 20.5c1.2-3.6 4-5.5 7.5-5.5s6.3 1.9 7.5 5.5"/>',
    "play": '<path d="M7 4.8v14.4L19 12 7 4.8Z"/>',
    "refresh": '<path d="M20 11.5a8 8 0 0 0-14.3-4.7L3.5 9.5M4 12.5a8 8 0 0 0 14.3 4.7l2.2-2.7"/><path d="M3.5 4.5v5h5M20.5 19.5v-5h-5"/>',
    "download": '<path d="M12 3.5v12M7 10.5l5 5 5-5M4.5 20.5h15"/>',
    "external": '<path d="M14 4h6v6M20 4l-9 9M18 14v5a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 4 19V7.5A1.5 1.5 0 0 1 5.5 6H10"/>',
    "chev": '<path d="m9 6 6 6-6 6"/>',
    "chevdown": '<path d="m6 9 6 6 6-6"/>',
    "sun": '<circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M4.6 4.6 6 6M18 18l1.4 1.4M2.5 12h2M19.5 12h2M4.6 19.4 6 18M18 6l1.4-1.4"/>',
    "moon": '<path d="M20 14.5A8.5 8.5 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5Z"/>',
    "pulse": '<path d="M2.5 12.5h4l2.5-6 4 12 3-8 1.5 2h4"/>',
    "database": '<ellipse cx="12" cy="5.5" rx="7.5" ry="3"/><path d="M4.5 5.5v13c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3v-13M4.5 12c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3"/>',
    "sparkle": '<path d="M12 3.5 13.7 9 19 10.7 13.7 12.4 12 18l-1.7-5.6L5 10.7 10.3 9 12 3.5ZM18.5 15.5l.7 2.1 2.1.7-2.1.7-.7 2.1-.7-2.1-2.1-.7 2.1-.7.7-2.1Z"/>',
    "trend": '<path d="M3 17.5 9 11.5l4 4 8-8.5"/><path d="M15 7h6v6"/>',
    "calendar": '<rect x="3.5" y="5" width="17" height="15.5" rx="2"/><path d="M3.5 10h17M8 3v4M16 3v4"/>',
    "layers": '<path d="m12 3.5 9 4.8-9 4.8-9-4.8 9-4.8Z"/><path d="m3 12.4 9 4.8 9-4.8M3 16.4l9 4.8 9-4.8"/>',
    "code": '<path d="m8.5 7-5 5 5 5M15.5 7l5 5-5 5M13.5 4.5l-3 15"/>',
    "split": '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M12 4v16"/>',
    "file": '<path d="M14 3.5H7a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8.5L14 3.5Z"/><path d="M14 3.5v5h5M8.5 13h7M8.5 16.5h5"/>',
    "lock": '<rect x="5" y="10.5" width="14" height="10" rx="2"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/>',
    "link": '<path d="M10 14a4.5 4.5 0 0 0 6.4 0l2.8-2.8a4.5 4.5 0 0 0-6.4-6.4L11.6 6"/><path d="M14 10a4.5 4.5 0 0 0-6.4 0l-2.8 2.8a4.5 4.5 0 0 0 6.4 6.4l1.2-1.2"/>',
    "bolt": '<path d="M13 2.5 5 13.5h6.5L10.5 21.5 19 10.5h-6.5L13 2.5Z"/>',
    "filter": '<path d="M3.5 5h17l-6.5 8v6l-4 1.5V13L3.5 5Z"/>',
    "eye": '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z"/><circle cx="12" cy="12" r="3"/>',
    "plug": '<path d="M9 2.5v5M15 2.5v5M6.5 7.5h11V11a5.5 5.5 0 0 1-11 0V7.5ZM12 16.5v5"/>',
    "keyboard": '<rect x="2.5" y="6" width="19" height="12" rx="2"/><path d="M6 10h.01M9 10h.01M12 10h.01M15 10h.01M18 10h.01M7 14h10"/>',
    "site": '<path d="M3.5 20.5h17M5.5 20.5V8l6.5-4.5L18.5 8v12.5"/><path d="M9.5 20.5v-5h5v5M9.5 10.5h.01M14.5 10.5h.01"/>',
    "dot": '<circle cx="12" cy="12" r="4"/>',
    "window": '<rect x="3" y="4.5" width="18" height="15" rx="2"/><path d="M3 9h18M7 6.8h.01M10 6.8h.01"/>',
}
KIND_ICON = {"switch": "switch", "router": "router", "firewall": "shield", "wireless": "wireless", "host": "host"}


def e(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def icon(name: str, cls: str = "") -> str:
    return f'<svg class="ic{(" " + cls) if cls else ""}" aria-hidden="true"><use href="#i-{name}"/></svg>'


def sprite() -> str:
    symbols = "".join(f'<symbol id="i-{name}" viewBox="0 0 24 24">{body}</symbol>' for name, body in ICONS.items())
    return f'<svg class="sprite" aria-hidden="true" focusable="false">{symbols}</svg>'


def data_json(value: Any) -> str:
    """JSON that is safe inside <script type="application/json">."""
    return json.dumps(value, separators=(",", ":"), default=str).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def ago(ts: float | None, now: float | None = None, empty: str = "never") -> str:
    if not ts:
        return f'<span class="muted">{e(empty)}</span>'
    stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    return f'<time data-ts="{ts:.0f}" title="{e(stamp)}">{e(humanize_ago(ts, now))}</time>'


def clock_time(ts: float | None, fmt: str = "%b %d, %H:%M") -> str:
    return time.strftime(fmt, time.localtime(ts)) if ts else ""


def pill(status: str | None, label: str | None = None, title: str | None = None) -> str:
    status = status or "unknown"
    tone = TONE.get(status, "unk")
    attr = f' title="{e(title)}"' if title else ""
    return f'<span class="pill t-{tone}"{attr}>{e(label or STATUS_LABEL.get(status, status.title()))}</span>'


def risk_pill(risk: str | None, short: bool = False) -> str:
    if not risk:
        return '<span class="risk risk-none">initial</span>'
    return f'<span class="risk risk-{e(risk)}">{e(risk if short else risk + " risk")}</span>'


def dot(status: str | None, pulse: bool = False) -> str:
    tone = TONE.get(status or "unknown", "unk")
    return f'<span class="dot t-{tone}{" pulse" if pulse and tone in ("warn", "crit") else ""}"></span>'


def tag(text: str, tone: str = "", title: str | None = None) -> str:
    attr = f' title="{e(title)}"' if title else ""
    return f'<span class="tag{(" t-" + tone) if tone else ""}"{attr}>{e(text)}</span>'


def initials(name: str | None) -> str:
    if not name:
        return "?"
    parts = re.split(r"[\s._-]+", name.strip())
    letters = "".join(p[0] for p in parts if p)[:2]
    return (letters if len(letters) == 2 else name[:2]).upper()


def avatar(name: str | None) -> str:
    hue = sum(ord(c) for c in (name or "?")) * 47 % 360
    return f'<span class="avatar" style="--h:{hue}" title="{e(name or "unknown")}">{e(initials(name))}</span>'


def tone_for(value: float | None, warning: float | None, critical: float | None) -> str:
    if value is None:
        return "unk"
    if critical is not None and value >= critical:
        return "crit"
    if warning is not None and value >= warning:
        return "warn"
    return "ok"


# --------------------------------------------------------------------------- small charts


def _fmt(value: float) -> str:
    return f"{value:.1f}".rstrip("0").rstrip(".")


def sparkline(values: Sequence[Optional[float]] | None, tone: str = "ok", width: int = 84, height: int = 22, top: float | None = 100.0) -> str:
    points = [(i, v) for i, v in enumerate(values or []) if v is not None]
    if len(points) < 2:
        return f'<svg class="spark empty" viewBox="0 0 {width} {height}"><path d="M0 {height - 1}H{width}"/></svg>'
    count = len(values or [])
    peak = top if top is not None else max(v for _, v in points) * 1.15 or 1
    floor = 0.0 if top is not None else min(v for _, v in points) * 0.85

    def xy(i: int, v: float) -> tuple[float, float]:
        x = i / max(1, count - 1) * width
        span = (peak - floor) or 1
        y = height - 2 - (min(v, peak) - floor) / span * (height - 4)
        return x, y

    segments: list[list[tuple[float, float]]] = [[]]
    previous = None
    for i, v in points:
        if previous is not None and i != previous + 1:
            segments.append([])
        segments[-1].append(xy(i, v))
        previous = i
    line = " ".join("M" + " L".join(f"{_fmt(x)} {_fmt(y)}" for x, y in seg) for seg in segments if seg)
    longest = max(segments, key=len)
    area = f"M{_fmt(longest[0][0])} {height} L" + " L".join(f"{_fmt(x)} {_fmt(y)}" for x, y in longest) + f" L{_fmt(longest[-1][0])} {height}Z"
    end_x, end_y = segments[-1][-1]
    return (
        f'<svg class="spark t-{tone}" viewBox="0 0 {width} {height}" preserveAspectRatio="none">'
        f'<path class="a" d="{area}"/><path class="l" d="{line}"/><circle cx="{_fmt(end_x)}" cy="{_fmt(end_y)}" r="1.8"/></svg>'
    )


def status_strip(codes: Sequence[Optional[int]] | None, start: float | None = None, bucket: float = 1800, cells: int = 48) -> str:
    codes = list(codes or [None] * cells)
    names = {0: "ok", 1: "unknown", 2: "warning", 3: "critical"}
    rects = []
    for index, code in enumerate(codes):
        cls = f"s{code}" if code is not None else "sx"
        label = ""
        if start is not None:
            label = f"<title>{clock_time(start + index * bucket, '%a %H:%M')} · {names.get(code, 'no data') if code is not None else 'no data'}</title>"
        rects.append(f'<rect class="{cls}" x="{index * 4}" y="0" width="3" height="12" rx=".8">{label}</rect>')
    return f'<svg class="strip" viewBox="0 0 {len(codes) * 4 - 1} 12" preserveAspectRatio="none">{"".join(rects)}</svg>'


def segbar(parts: Sequence[tuple[str, float]], title: str = "") -> str:
    total = sum(v for _, v in parts) or 1
    spans = "".join(f'<span class="t-{tone}" style="width:{v / total * 100:.2f}%"></span>' for tone, v in parts if v > 0)
    return f'<div class="segbar" title="{e(title)}">{spans}</div>'


def bars(values: Sequence[float], tones: Sequence[str] | None = None, width: int = 140, height: int = 26) -> str:
    count = len(values) or 1
    peak = max(values) if values and max(values) > 0 else 1
    step = width / count
    rects = []
    for index, value in enumerate(values):
        h = max(1.5, value / peak * (height - 2)) if value else 1.2
        tone = tones[index] if tones else ("acc" if value else "none")
        rects.append(f'<rect class="b-{tone}" x="{_fmt(index * step + 0.6)}" y="{_fmt(height - h)}" width="{_fmt(max(1.0, step - 1.6))}" height="{_fmt(h)}" rx="1"/>')
    return f'<svg class="bars" viewBox="0 0 {width} {height}" preserveAspectRatio="none">{"".join(rects)}</svg>'


def _polar(cx: float, cy: float, r: float, degrees: float) -> tuple[float, float]:
    rad = math.radians(degrees)
    return cx + r * math.cos(rad), cy + r * math.sin(rad)


def _arc(cx: float, cy: float, r: float, start: float, end: float) -> str:
    x1, y1 = _polar(cx, cy, r, start)
    x2, y2 = _polar(cx, cy, r, end)
    large = 1 if end - start > 180 else 0
    return f"M{_fmt(x1)} {_fmt(y1)} A{r} {r} 0 {large} 1 {_fmt(x2)} {_fmt(y2)}"


def gauge(
    value: float | None, label: str, unit: str = "%", warning: float | None = None, critical: float | None = None,
    maximum: float = 100.0, sub: str = "", note: str = "", note_tone: str = "warn",
) -> str:
    tone = tone_for(value, warning, critical)
    start, sweep = 135.0, 270.0
    track = _arc(60, 60, 46, start, start + sweep)
    fill = ""
    if value is not None:
        fraction = max(0.0, min(1.0, value / maximum))
        if fraction > 0.004:
            fill = f'<path class="g-val" d="{_arc(60, 60, 46, start, start + sweep * fraction)}"/>'
    ticks = ""
    for level, limit in (("warn", warning), ("crit", critical)):
        if limit is not None and 0 < limit < maximum:
            angle = start + sweep * limit / maximum
            x1, y1 = _polar(60, 60, 40, angle)
            x2, y2 = _polar(60, 60, 52, angle)
            ticks += f'<path class="g-tick {level}" d="M{_fmt(x1)} {_fmt(y1)} L{_fmt(x2)} {_fmt(y2)}"/>'
    shown = "–" if value is None else (f"{value:.0f}" if abs(value) >= 10 or unit == "%" else f"{value:.1f}")
    note_html = f'<div class="g-note t-{note_tone}">{icon("trend")}{e(note)}</div>' if note else ""
    return (
        f'<div class="gauge t-{tone}"><svg viewBox="0 0 120 106"><path class="g-track" d="{track}"/>{fill}{ticks}'
        f'<text class="g-num" x="60" y="62">{e(shown)}<tspan class="g-unit" dx="2">{e(unit if value is not None else "")}</tspan></text>'
        f'<text class="g-lbl" x="60" y="82">{e(label)}</text></svg>'
        f'<div class="g-sub">{e(sub)}</div>{note_html}</div>'
    )


def trend_chart(
    series: dict[str, Any], key: str, label: str, unit: str, warning: float | None = None, critical: float | None = None,
    forecast: dict[str, Any] | None = None, maximum: float | None = 100.0, width: int = 680, height: int = 128,
) -> str:
    times: list[float] = series.get("t") or []
    values: list[Optional[float]] = series.get(key) or []
    start, end = float(series.get("start") or 0), float(series.get("end") or 0)
    present = [v for v in values if v is not None]
    left, right, top_pad, bottom = 34.0, 64.0, 10.0, 20.0
    plot_w, plot_h = width - left - right, height - top_pad - bottom
    if not present:
        return (
            f'<div class="chart"><div class="chart-h"><b>{e(label)}</b><span class="muted">no data yet</span></div>'
            f'<svg viewBox="0 0 {width} {height}" class="chart-svg"><text class="ax" x="{width / 2}" y="{height / 2}" text-anchor="middle">'
            "Collected on every health check</text></svg></div>"
        )
    extra = [v for v in (warning, critical) if v is not None]
    if maximum is None:
        hi = max(present + extra) * 1.12
        lo = max(0.0, min(present) * 0.8)
        lo = math.floor(lo / 5) * 5
        hi = math.ceil(hi / 5) * 5
    else:
        lo, hi = 0.0, maximum
    span_t = (end - start) or 1

    def x_of(ts: float) -> float:
        return left + (ts - start) / span_t * plot_w

    def y_of(v: float) -> float:
        return top_pad + plot_h - (max(lo, min(hi, v)) - lo) / ((hi - lo) or 1) * plot_h

    grid = []
    for fraction in (0, 0.5, 1):
        value = lo + (hi - lo) * fraction
        if hi - lo >= 10:
            value = float(round(value))
        y = y_of(value)
        grid.append(f'<path class="gl" d="M{left} {_fmt(y)}H{left + plot_w}"/><text class="ax" x="{left - 6}" y="{_fmt(y + 3.5)}" text-anchor="end">{_fmt(value)}</text>')
    ticks = []
    tick_count = 6
    for index in range(tick_count + 1):
        ts = start + span_t * index / tick_count
        fmt = "%H:%M" if span_t <= 2 * 86400 else "%a %d"
        anchor = "start" if index == 0 else "end" if index == tick_count else "middle"
        ticks.append(f'<text class="ax" x="{_fmt(x_of(ts))}" y="{height - 5}" text-anchor="{anchor}">{e(clock_time(ts, fmt))}</text>')
    segments: list[list[tuple[float, float]]] = [[]]
    gap = (series.get("bucket") or 300) * 2.5
    last_t = None
    for ts, v in zip(times, values):
        if v is None:
            continue
        if last_t is not None and ts - last_t > gap and segments[-1]:
            segments.append([])
        segments[-1].append((x_of(ts), y_of(v)))
        last_t = ts
    segments = [s for s in segments if s]
    line = " ".join("M" + " L".join(f"{_fmt(x)} {_fmt(y)}" for x, y in seg) for seg in segments)
    base_y = top_pad + plot_h
    area = " ".join(
        f"M{_fmt(seg[0][0])} {_fmt(base_y)} L" + " L".join(f"{_fmt(x)} {_fmt(y)}" for x, y in seg) + f" L{_fmt(seg[-1][0])} {_fmt(base_y)}Z"
        for seg in segments
    )
    limits = []
    label_ys: list[float] = []
    for level, limit in (("crit", critical), ("warn", warning)):
        if limit is not None and lo <= limit <= hi:
            y = y_of(limit)
            label_y = y + 3.5
            for taken in label_ys:
                if abs(label_y - taken) < 12.5:
                    label_y = taken + 12.5
            label_ys.append(label_y)
            limits.append(
                f'<path class="lim {level}" d="M{left} {_fmt(y)}H{left + plot_w}"/>'
                f'<text class="lim-t {level}" x="{left + plot_w + 6}" y="{_fmt(label_y)}">{_fmt(limit)}{e(unit)}</text>'
            )
    last_x, last_y = segments[-1][-1]
    last_value = [v for v in values if v is not None][-1]
    tone = tone_for(last_value, warning, critical)
    projection = ""
    if forecast and forecast.get("threshold") is not None and float(forecast.get("slope_per_day") or 0) > 0:
        slope = float(forecast["slope_per_day"])
        current = float(forecast.get("current") or last_value)
        threshold = float(forecast["threshold"])
        px_per_day = plot_w / (span_t / 86400)
        offset = min(right - 10, (threshold - current) / slope * px_per_day)
        reach = current + slope * offset / px_per_day
        projection = (
            f'<path class="proj" d="M{_fmt(last_x)} {_fmt(y_of(current))} L{_fmt(last_x + offset)} {_fmt(y_of(reach))}"/>'
            f'<circle class="proj-dot" cx="{_fmt(last_x + offset)}" cy="{_fmt(y_of(reach))}" r="2.6"/>'
        )
    points = [[round(t), v] for t, v in zip(times, values) if v is not None]
    head_value = f"{last_value:.0f}{unit}" if unit == "%" else f"{last_value:.1f}{unit}"
    note = ""
    if forecast:
        note = f'<span class="fc t-warn">{icon("trend")}{e(forecast_text(forecast, unit))}</span>'
    return (
        f'<div class="chart" data-chart data-unit="{e(unit)}" data-start="{start:.0f}" data-end="{end:.0f}" '
        f'data-left="{left}" data-width="{plot_w}" data-w="{width}" data-points="{e(json.dumps(points))}">'
        f'<div class="chart-h"><b>{e(label)}</b><span class="cv t-{tone}">{e(head_value)}</span>{note}</div>'
        f'<svg viewBox="0 0 {width} {height}" class="chart-svg t-{tone}" preserveAspectRatio="none">{"".join(grid)}{"".join(limits)}'
        f'<path class="area" d="{area}"/><path class="line" d="{line}"/>{projection}'
        f'<circle class="last" cx="{_fmt(last_x)}" cy="{_fmt(last_y)}" r="3.2"/>{"".join(ticks)}'
        f'<path class="xh" d="M0 {top_pad}V{top_pad + plot_h}"/></svg><div class="chart-tip"></div></div>'
    )


def forecast_text(forecast: dict[str, Any], unit: str) -> str:
    eta = format_duration(float(forecast.get("eta_seconds") or 0), coarse=True)
    return f"{float(forecast['threshold']):g}{unit} in ~{eta}"


def fleet_chart(buckets: Sequence[dict[str, int]], start: float, bucket: float, width: int = 560, height: int = 120) -> str:
    total = max((sum(b.values()) for b in buckets), default=0) or 1
    count = len(buckets) or 1
    step = (width - 30) / count
    order = (("ok", "ok"), ("unknown", "unk"), ("warning", "warn"), ("critical", "crit"))
    rects = []
    for index, data in enumerate(buckets):
        y = height - 18.0
        x = 30 + index * step
        label = clock_time(start + index * bucket, "%H:%M")
        parts = ", ".join(f"{data.get(k, 0)} {k}" for k, _ in order if data.get(k))
        for key, tone in order:
            value = data.get(key, 0)
            if not value:
                continue
            h = value / total * (height - 26)
            y -= h
            rects.append(f'<rect class="f-{tone}" x="{_fmt(x + 0.5)}" y="{_fmt(y)}" width="{_fmt(max(1.0, step - 1.5))}" height="{_fmt(h)}" rx="1"><title>{e(label)} · {e(parts)}</title></rect>')
    axis = []
    for index in range(0, count + 1, max(1, count // 4)):
        x = 30 + index * step
        anchor = "start" if index == 0 else "end" if index >= count else "middle"
        axis.append(f'<text class="ax" x="{_fmt(x)}" y="{height - 4}" text-anchor="{anchor}">{e(clock_time(start + index * bucket, "%H:%M"))}</text>')
    labels = (
        f'<text class="ax" x="24" y="{height - 18}" text-anchor="end">0</text>'
        f'<text class="ax" x="24" y="{_fmt(height - 18 - (height - 26) + 4)}" text-anchor="end">{total}</text>'
    )
    return f'<svg class="fleet" viewBox="0 0 {width} {height}" preserveAspectRatio="none">{labels}{"".join(rects)}{"".join(axis)}</svg>'


def calendar_heatmap(counts: dict[str, int], end: float, weeks: int = 26) -> str:
    """GitHub-style grid of changes per day; ``counts`` maps YYYY-MM-DD to a number."""
    last = time.localtime(end)
    end_day = time.mktime((last.tm_year, last.tm_mon, last.tm_mday, 12, 0, 0, 0, 0, -1))
    start_day = end_day - (weeks * 7 - 1) * 86400
    while time.localtime(start_day).tm_wday != 0:
        start_day -= 86400
    peak = max(counts.values(), default=0) or 1
    cells, months = [], []
    day, column, last_month = start_day, 0, None
    while day <= end_day + 1:
        local = time.localtime(day)
        row = local.tm_wday
        key = time.strftime("%Y-%m-%d", local)
        value = counts.get(key, 0)
        level = 0 if not value else min(4, 1 + int(value / peak * 3.999))
        cells.append(
            f'<rect class="c{level}" x="{30 + column * 15}" y="{16 + row * 15}" width="12" height="12" rx="2.5">'
            f'<title>{time.strftime("%a %b %d", local)}: {value} change{"s" if value != 1 else ""}</title></rect>'
        )
        if local.tm_mon != last_month and row == 0:
            months.append(f'<text class="ax" x="{30 + column * 15}" y="10">{time.strftime("%b", local)}</text>')
            last_month = local.tm_mon
        if row == 6:
            column += 1
        day += 86400
    days = "".join(f'<text class="ax" x="22" y="{26 + i * 15}" text-anchor="end">{d}</text>' for i, d in ((0, "Mon"), (2, "Wed"), (4, "Fri")))
    width = 30 + (column + 1) * 15
    return f'<svg class="heat" viewBox="0 0 {width} {16 + 7 * 15}">{"".join(months)}{days}{"".join(cells)}</svg>'


def risk_meter(score: int | None, risk: str | None) -> str:
    score = max(0, min(100, int(score or 0)))
    return f'<div class="meter risk-{e(risk or "none")}"><span style="width:{max(3, score)}%"></span></div>'


# --------------------------------------------------------------------------- equipment faceplate


def _port_number(name: str, ports: int) -> int | None:
    numbers = [int(n) for n in re.findall(r"\d+", name or "")]
    candidates = [n for n in numbers if 1 <= n <= ports]
    return max(candidates) if candidates else None


def faceplate(kind: str, name: str, model: str, health: dict[str, Any], status: str) -> str:
    """A 1U front panel: port LEDs lit for links seen by LLDP, status LEDs from the last health check."""
    layout = {"switch": (48, 4), "router": (8, 4), "firewall": (12, 4), "wireless": (4, 2), "host": (4, 2)}.get(kind, (24, 4))
    copper, sfp = layout
    total = copper + sfp
    lit: dict[int, str] = {}
    for neighbor in health.get("neighbors") or []:
        number = _port_number(neighbor.get("port", ""), total)
        if number:
            lit[number] = f'{neighbor.get("port")} → {neighbor.get("remote")} {neighbor.get("remote_port") or ""}'.strip()
    width = 1000
    ports_svg = []
    rows = 2 if copper > 12 else 1
    per_row = math.ceil(copper / rows)
    port_w, gap = (14, 4) if copper > 12 else (22, 7)
    x0 = 300
    for index in range(copper):
        number = index + 1
        row, col = (index % rows, index // rows) if rows == 2 else (0, index)
        x = x0 + col * (port_w + gap) + (col // 6) * 8
        y = 22 + row * 25 if rows == 2 else 30
        state = "on" if number in lit else ""
        title = e(lit.get(number, f"port {number}"))
        ports_svg.append(f'<g class="port {state}"><rect x="{x}" y="{y}" width="{port_w}" height="{18}" rx="2"/><rect class="led" x="{x + 2}" y="{y + 2}" width="4" height="3" rx=".6"/><title>{title}</title></g>')
    sfp_x = x0 + per_row * (port_w + gap) + (per_row // 6) * 8 + 26
    for index in range(sfp):
        number = copper + index + 1
        col, row = index // 2, index % 2
        x = sfp_x + col * 34
        y = 22 + row * 25
        state = "on" if number in lit else ""
        title = e(lit.get(number, f"uplink {number}"))
        ports_svg.append(f'<g class="port sfp {state}"><rect x="{x}" y="{y}" width="28" height="18" rx="2"/><rect class="led" x="{x + 3}" y="{y + 2}" width="5" height="3" rx=".6"/><title>{title}</title></g>')
    fans = health.get("fans") or {}
    psus = health.get("psus") or {}
    leds = [("SYS", TONE.get(status, "unk"))]
    if fans:
        leds.append(("FAN", "ok" if all(fans.values()) else "warn"))
    temps = [t.get("status") for t in (health.get("temperatures") or {}).values()]
    if temps:
        leds.append(("TMP", "crit" if "critical" in temps else "warn" if "warning" in temps else "ok"))
    for index, (_, ok) in enumerate(sorted(psus.items())[:2]):
        leds.append((f"PS{index + 1}", "ok" if ok else "crit"))
    led_svg = []
    for index, (text, tone) in enumerate(leds):
        x = 150 + index * 26
        led_svg.append(f'<g class="sled t-{tone}"><circle cx="{x}" cy="32" r="4.2"/><text x="{x}" y="52" text-anchor="middle">{text}</text></g>')
    end_x = max(sfp_x + math.ceil(sfp / 2) * 34 + 30, 860)
    return (
        f'<svg class="faceplate" viewBox="0 0 {width} 78" preserveAspectRatio="xMidYMid meet">'
        f'<rect class="chassis" x="6" y="4" width="{width - 12}" height="70" rx="7"/>'
        f'<rect class="ear" x="6" y="4" width="22" height="70" rx="5"/><rect class="ear" x="{width - 28}" y="4" width="22" height="70" rx="5"/>'
        f'<circle class="screw" cx="17" cy="18" r="3"/><circle class="screw" cx="17" cy="60" r="3"/>'
        f'<circle class="screw" cx="{width - 17}" cy="18" r="3"/><circle class="screw" cx="{width - 17}" cy="60" r="3"/>'
        f'<text class="fp-name" x="44" y="30">{e(name)}</text><text class="fp-model" x="44" y="48">{e(model[:22])}</text>'
        f'{"".join(led_svg)}{"".join(ports_svg)}'
        f'<path class="vent" d="M{end_x} 22h{width - 60 - end_x}M{end_x} 31h{width - 60 - end_x}M{end_x} 40h{width - 60 - end_x}M{end_x} 49h{width - 60 - end_x}M{end_x} 58h{width - 60 - end_x}"/>'
        "</svg>"
    )


# --------------------------------------------------------------------------- configuration text


_HIGHLIGHT = re.compile(
    r'(?P<str>"(?:[^"\\]|\\.)*")'
    r"|(?P<sec><(?:removed|encrypted|secret:[0-9a-f]{6,64}|private key removed)>)"
    r"|(?P<ip>(?<![\w.:])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\w.])|(?<![\w:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}(?:/\d{1,3})?(?![\w:]))"
    r"|(?P<num>(?<![\w.\-/])\d+(?![\w.\-/]))"
)
_NEGATIONS = ("no", "unset", "delete", "remove", "disable", "shutdown")


def highlight(line: str, header: bool = False) -> str:
    stripped = line.lstrip()
    indent = line[: len(line) - len(stripped)]
    if not stripped:
        return ""
    if stripped.startswith(("!", "#", ";", "/*", ":")) and not stripped.startswith(("#config", ":/")):
        return f'{e(indent)}<span class="cm">{e(stripped)}</span>'
    out, last = [], 0
    for match in _HIGHLIGHT.finditer(stripped):
        out.append(e(stripped[last: match.start()]))
        kind = match.lastgroup or ""
        cls = {"str": "s", "sec": "x", "ip": "ip", "num": "n"}[kind]
        out.append(f'<span class="{cls}">{e(match.group(0))}</span>')
        last = match.end()
    out.append(e(stripped[last:]))
    body = "".join(out)
    first = re.match(r"^([A-Za-z/][\w/-]*)", stripped)
    if first and "<span" not in body[: len(first.group(1)) + 6]:
        word = first.group(1)
        cls = "neg" if word.lower() in _NEGATIONS else "hd" if header else "kw"
        body = f'<span class="{cls}">{e(word)}</span>' + body[len(e(word)):]
    return e(indent) + body


def render_config(text: str, platform: str | None = None, highlight_line: int | None = None) -> str:
    parsed: Parsed = parse(text, platform=platform)
    blocks = parsed.blocks()
    rows = []
    for index, line in enumerate(parsed.lines):
        number = index + 1
        attrs = f' data-n="{number}"'
        cls = "cl"
        if index in blocks:
            cls += " hd"
            attrs += f' data-end="{blocks[index] + 1}"'
        if highlight_line == number:
            cls += " hit"
        depth = parsed.depth(index)
        if depth > 0:
            attrs += f' data-d="{depth}"'
        rows.append(f'<div class="{cls}"{attrs}><span class="ln">{number}</span><code>{highlight(line, index in blocks) or " "}</code></div>')
    return f'<div class="code" data-syntax="{e(parsed.syntax)}">{"".join(rows)}</div>'


def _intraline(old: str, new: str) -> tuple[str, str]:
    matcher = difflib.SequenceMatcher(None, old, new, autojunk=False)
    if matcher.ratio() < 0.35:
        return e(old), e(new)
    a, b = [], []
    for tag_name, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag_name == "equal":
            a.append(e(old[i1:i2]))
            b.append(e(new[j1:j2]))
        else:
            if i2 > i1:
                a.append(f"<mark>{e(old[i1:i2])}</mark>")
            if j2 > j1:
                b.append(f"<mark>{e(new[j1:j2])}</mark>")
    return "".join(a), "".join(b)


def _parse_diff(diff: str) -> list[dict[str, Any]]:
    """Unified diff -> rows: {kind: hunk|ctx|add|del|file, old, new, text}."""
    rows: list[dict[str, Any]] = []
    old_no = new_no = 0
    for line in diff.splitlines():
        if line.startswith(("+++ ", "--- ")):
            if line.startswith("+++ "):
                rows.append({"kind": "file", "text": line[4:].replace("b/", "", 1)})
            continue
        if line.startswith("@@"):
            match = re.match(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@(.*)", line)
            if match:
                old_no, new_no = int(match.group(1)), int(match.group(2))
                rows.append({"kind": "hunk", "text": line, "context": match.group(3).strip()})
            continue
        if line.startswith("+"):
            rows.append({"kind": "add", "new": new_no, "text": line[1:]})
            new_no += 1
        elif line.startswith("-"):
            rows.append({"kind": "del", "old": old_no, "text": line[1:]})
            old_no += 1
        elif line.startswith("\\"):
            continue
        else:
            rows.append({"kind": "ctx", "old": old_no, "new": new_no, "text": line[1:] if line.startswith(" ") else line})
            old_no += 1
            new_no += 1
    return rows


def _pairs(rows: list[dict[str, Any]]) -> None:
    """Mark runs of deleted+added lines with intraline highlights."""
    index = 0
    while index < len(rows):
        if rows[index]["kind"] != "del":
            index += 1
            continue
        dels = []
        while index < len(rows) and rows[index]["kind"] == "del":
            dels.append(rows[index])
            index += 1
        adds = []
        while index < len(rows) and rows[index]["kind"] == "add":
            adds.append(rows[index])
            index += 1
        for old, new in zip(dels, adds):
            old["html"], new["html"] = _intraline(old["text"], new["text"])
            old["pair"] = new
            new["pair"] = old


def render_diff(diff: str, layout: str = "unified", show_files: bool = True) -> str:
    rows = _parse_diff(diff)
    if not rows:
        return '<div class="diff-empty">No differences between these versions.</div>'
    _pairs(rows)
    out = []
    if layout == "split":
        index = 0
        while index < len(rows):
            row = rows[index]
            kind = row["kind"]
            if kind == "file":
                if show_files:
                    out.append(f'<div class="sl file"><code>{icon("file")}{e(row["text"])}</code></div>')
                index += 1
            elif kind == "hunk":
                out.append(f'<div class="sl hunk"><code>{e(row["text"])}</code></div>')
                index += 1
            elif kind == "ctx":
                text = highlight(row["text"]) or " "
                out.append(f'<div class="sl"><span class="ln">{row["old"]}</span><code>{text}</code><span class="ln">{row["new"]}</span><code>{text}</code></div>')
                index += 1
            else:
                dels, adds = [], []
                while index < len(rows) and rows[index]["kind"] == "del":
                    dels.append(rows[index])
                    index += 1
                while index < len(rows) and rows[index]["kind"] == "add":
                    adds.append(rows[index])
                    index += 1
                for position in range(max(len(dels), len(adds))):
                    left = dels[position] if position < len(dels) else None
                    right = adds[position] if position < len(adds) else None
                    lhtml = (left.get("html") or e(left["text"])) if left else ""
                    rhtml = (right.get("html") or e(right["text"])) if right else ""
                    out.append(
                        f'<div class="sl"><span class="ln">{left["old"] if left else ""}</span><code class="{"del" if left else "blank"}">{lhtml or " "}</code>'
                        f'<span class="ln">{right["new"] if right else ""}</span><code class="{"add" if right else "blank"}">{rhtml or " "}</code></div>'
                    )
        return f'<div class="diff split">{"".join(out)}</div>'
    for row in rows:
        kind = row["kind"]
        if kind == "file":
            if show_files:
                out.append(f'<div class="dl file"><code>{icon("file")}{e(row["text"])}</code></div>')
        elif kind == "hunk":
            context = f' <i>{e(row["context"])}</i>' if row.get("context") else ""
            out.append(f'<div class="dl hunk"><span class="ln"></span><span class="ln"></span><code>{e(row["text"].split(" @@")[0])} @@{context}</code></div>')
        elif kind == "ctx":
            out.append(f'<div class="dl"><span class="ln">{row["old"]}</span><span class="ln">{row["new"]}</span><code>{highlight(row["text"]) or " "}</code></div>')
        elif kind == "add":
            out.append(f'<div class="dl add"><span class="ln"></span><span class="ln">{row["new"]}</span><code>{row.get("html") or e(row["text"]) or " "}</code></div>')
        else:
            out.append(f'<div class="dl del"><span class="ln">{row["old"]}</span><span class="ln"></span><code>{row.get("html") or e(row["text"]) or " "}</code></div>')
    return f'<div class="diff unified">{"".join(out)}</div>'


def intel_card(analysis: dict[str, Any] | None, unplanned: bool | None = None, who: str | None = None, when: float | None = None, now: float | None = None) -> str:
    """Change intelligence summary for one change."""
    if not analysis:
        return ""
    if analysis.get("initial"):
        return f'<div class="intel"><div class="intel-h">{icon("sparkle")}<b>Initial backup</b><span class="muted">{e(analysis.get("added", 0))} lines recorded</span></div></div>'
    risk = analysis.get("risk") or "low"
    cats = "".join(f'<span class="chip c-{e(c["risk"])}">{e(c["label"])}<b>{c["count"]}</b></span>' for c in analysis.get("categories") or [])
    items = []
    for item in (analysis.get("items") or [])[:8]:
        action = {"added": "+", "removed": "−", "modified": "~"}.get(item.get("action"), "~")
        items.append(
            f'<li class="r-{e(item.get("risk"))}"><span class="act a-{e(item.get("action"))}">{action}</span>'
            f'<span class="it">{e(item.get("text"))}</span><span class="cat">{e(item.get("category_label"))}</span></li>'
        )
    flags = ""
    if unplanned:
        flags += f'<span class="flag t-warn">{icon("window")}Outside change window</span>'
    elif unplanned is False:
        flags += f'<span class="flag t-ok">{icon("window")}Inside change window</span>'
    meta = []
    if who:
        meta.append(f'{avatar(who)}<span>{e(who)}</span>')
    if when:
        meta.append(ago(when, now))
    return (
        f'<div class="intel"><div class="intel-h">{icon("sparkle")}<b>Change intelligence</b>{risk_pill(risk)}'
        f'<span class="score" title="Risk score">{e(analysis.get("score", 0))}<small>/100</small></span>{flags}'
        f'<span class="intel-meta">{"".join(meta)}</span></div>'
        f'{risk_meter(analysis.get("score"), risk)}<div class="chips">{cats}</div><ul class="items">{"".join(items)}</ul></div>'
    )


def max_risk(risks: Iterable[str | None]) -> str | None:
    present = [r for r in risks if r]
    return max(present, key=lambda r: RISK_ORDER.get(r, 0)) if present else None
