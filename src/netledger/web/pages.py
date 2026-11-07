"""Server-rendered pages. Live regions are marked ``data-live="<key>"`` and swapped in place by app.js."""

from __future__ import annotations

import time
from collections import Counter
from typing import Any, Optional
from urllib.parse import quote

from netledger.intel import CATEGORIES, RISK_ORDER
from netledger.search import KINDS, ROLES
from netledger.topology import device_kind
from netledger.utils import format_duration, parse_iso
from netledger.web.shell import page
from netledger.web.ui import (
    CHECK_NAMES,
    KIND_ICON,
    STATUS_LABEL,
    TONE,
    ago,
    avatar,
    bars,
    calendar_heatmap,
    clock_time,
    data_json,
    dot,
    e,
    faceplate,
    fleet_chart,
    forecast_text,
    gauge,
    icon,
    intel_card,
    max_risk,
    pill,
    render_diff,
    risk_pill,
    segbar,
    sparkline,
    status_strip,
    tag,
    tone_for,
    trend_chart,
)

DAY = 86400.0
CHECK_ICONS = {"reachability": "plug", "cpu": "cpu", "memory": "memory", "temperature": "thermo", "fans": "fan", "power": "power", "environment": "pulse"}
METRIC_INFO = {"memory": ("Memory", "%", "memory"), "temperature": ("Temperature", "°C", "thermo")}


def q(value: str) -> str:
    return quote(value, safe="")


def device_href(name: str) -> str:
    return f"/devices/{q(name)}"


# --------------------------------------------------------------------------- rows


def build_rows(snapshot: dict[str, Any], inventory: list[dict[str, Any]], changes: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    devices = snapshot.get("devices") or {}
    known = {d["name"]: d for d in inventory}
    names = [d["name"] for d in inventory] + sorted(n for n in devices if n not in known)
    latest: dict[str, dict[str, Any]] = {}
    for change in changes if changes is not None else reversed(snapshot.get("changes") or []):
        latest.setdefault(change.get("device"), change)
    rows = []
    for name in names:
        data = devices.get(name) or {}
        info = {**(data.get("info") or {}), **known.get(name, {})}
        rows.append({
            "name": name,
            "info": info,
            "facts": data.get("facts") or {},
            "backup": data.get("backup") or {},
            "health": data.get("health") or {},
            "compliance": data.get("compliance") or {},
            "in_inventory": name in known,
            "last_change": latest.get(name),
        })
    rows.sort(key=lambda r: ((r["info"].get("site") or "~").lower(), r["name"].lower()))
    return rows


def overall(row: dict[str, Any]) -> str:
    health = row["health"].get("status")
    backup = row["backup"].get("status")
    if health == "critical" or backup == "failed":
        return "critical"
    if health == "warning":
        return "warning"
    if health == "ok" or backup == "ok":
        return "ok"
    return "unknown"


def failing_rules(row: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    return [(k, v) for k, v in sorted((row["compliance"].get("rules") or {}).items()) if not v.get("passed")]


def attention(rows: list[dict[str, Any]], now: float) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for row in rows:
        name, health, backup = row["name"], row["health"], row["backup"]
        since = health.get("status_since")
        if health.get("status") == "critical":
            problems = [c for c in health.get("checks") or [] if c.get("status") == "critical"]
            if not health.get("reachable", True):
                items.append({"sev": "crit", "icon": "plug", "device": name, "title": "Unreachable", "detail": (problems[0]["message"] if problems else "no answer"), "since": since})
            for check in problems if health.get("reachable", True) else []:
                items.append({"sev": "crit", "icon": CHECK_ICONS.get(check.get("name"), "alert"), "device": name, "title": f"{CHECK_NAMES.get(check.get('name'), check.get('name'))} critical", "detail": check.get("message"), "since": since})
        for check in health.get("checks") or []:
            if check.get("status") == "warning":
                items.append({"sev": "warn", "icon": CHECK_ICONS.get(check.get("name"), "alert"), "device": name, "title": f"{CHECK_NAMES.get(check.get('name'), check.get('name'))} warning", "detail": check.get("message"), "since": since})
        if backup.get("status") == "failed":
            items.append({"sev": "crit", "icon": "database", "device": name, "title": "Backup failing", "detail": f"{backup.get('consecutive_failures') or 1} in a row · last good {format_duration(now - backup['last_success'], coarse=True) + ' ago' if backup.get('last_success') else 'never'}", "since": backup.get("last_attempt")})
        if backup.get("unsaved_changes"):
            items.append({"sev": "warn", "icon": "file", "device": name, "title": "Unsaved configuration", "detail": "running ≠ startup · a reload would lose changes", "since": backup.get("last_change")})
        for rule, result in failing_rules(row):
            items.append({"sev": "crit" if result.get("severity") == "critical" else "warn", "icon": "shield", "device": name, "title": f"Compliance · {rule}", "detail": result.get("description") or "rule failed", "since": None})
        for metric, fc in (health.get("forecast") or {}).items():
            label, unit, glyph = METRIC_INFO.get(metric, (metric.title(), "", "trend"))
            days = float(fc.get("eta_seconds") or 0) / DAY
            items.append({"sev": "warn" if days <= 7 else "info", "icon": "trend", "device": name, "title": f"{label} trending up", "detail": f"reaches {forecast_text(fc, unit)} (+{fc.get('slope_per_day', 0):.1f}{unit}/day)", "since": None})
        change = row.get("last_change") or {}
        if change.get("unplanned") and (change.get("ts") or 0) > now - DAY:
            first = (change.get("highlights") or ["configuration changed"])[0]
            who = f" · by {change['changed_by']}" if change.get("changed_by") else ""
            items.append({"sev": "warn", "icon": "window", "device": name, "title": "Unplanned change", "detail": f"{first}{who}", "since": change.get("ts")})
    order = {"crit": 0, "warn": 1, "info": 2}
    items.sort(key=lambda i: (order[i["sev"]], -(i["since"] or 0), i["device"]))
    return items


def _site_rows(rows: list[dict[str, Any]]) -> list[tuple[str, str, int]]:
    sites: dict[str, list[str]] = {}
    for row in rows:
        sites.setdefault(row["info"].get("site") or "", []).append(overall(row))
    worst = {"critical": 3, "warning": 2, "unknown": 1, "ok": 0}
    return [(site, max(statuses, key=lambda s: worst.get(s, 0)), len(statuses)) for site, statuses in sorted(sites.items(), key=lambda s: (s[0] == "", s[0]))]


def nav_counts(rows: list[dict[str, Any]], changes: list[dict[str, Any]], now: float) -> dict[str, Any]:
    items = attention(rows, now)
    recent = [c for c in changes if (c.get("ts") or 0) > now - DAY]
    return {
        "overview": len({i["device"] for i in items if i["sev"] in ("crit", "warn")}) or None,
        "overview_tone": "crit" if any(i["sev"] == "crit" for i in items) else "warn",
        "changes": len(recent) or None,
        "changes_tone": "warn" if any(c.get("unplanned") for c in recent) else "",
    }


def common(view: dict[str, Any], rows: list[dict[str, Any]], changes: list[dict[str, Any]]) -> None:
    now = view.get("now") or time.time()
    view.setdefault("nav", nav_counts(rows, changes, now))
    view.setdefault("sites", _site_rows(rows))


# --------------------------------------------------------------------------- shared fragments


def change_entry(change: dict[str, Any], now: float, links: Any = None, expanded: bool = False, compact: bool = False) -> str:
    device = change.get("device") or ""
    risk = change.get("risk")
    highlights = change.get("highlights") or []
    reasons = [str(r) for r in change.get("reasons") or []]
    summary = highlights[0] if highlights else f"+{change.get('added', 0)}/-{change.get('removed', 0)} lines"
    more = len(highlights) - 1
    sha = change.get("commit") or ""
    commit_url = links.commit(sha) if links and sha else None
    sha_html = ""
    if sha:
        sha_html = f'<a class="sha" href="{e(commit_url)}">{e(sha[:7])}</a>' if commit_url else f'<span class="sha">{e(sha[:7])}</span>'
    flags = ""
    if change.get("unplanned"):
        flags += f'<span class="flag t-warn" title="No approved change window covers this change">{icon("window")}unplanned</span>'
    cats = "".join(f'<span class="chip">{e(label)}</span>' for label in (change.get("category_labels") or [])[:3])
    who = change.get("changed_by")
    who_html = f'{avatar(who)}<span class="who">{e(who)}</span>' if who else ""
    tm = f'{device_href(device)}?to={e(sha)}#timemachine' if sha else f"{device_href(device)}#timemachine"
    details = ""
    if not compact:
        rest = "".join(f"<li>{e(h)}</li>" for h in highlights[1:6])
        diff = change.get("diff")
        why = "".join(f"<li>{e(r)}</li>" for r in reasons)
        body = (
            (f'<div class="why-block"><span>Why</span><ul>{why}</ul></div>' if why else "")
            + (f'<ul class="hl">{rest}</ul>' if rest else "")
            + (render_diff(diff, show_files=False) if diff else "")
        )
        details = f'<div class="entry-more">{body}<a class="more" href="{tm}">Open in time machine {icon("chev")}</a></div>' if body else ""
    search = " ".join(str(v) for v in (device, change.get("site"), who, change.get("platform_name"), " ".join(highlights), " ".join(reasons))).lower()
    open_attr = " open" if expanded else ""
    stats = f'<span class="add">+{e(change.get("added", 0))}</span><span class="del">−{e(change.get("removed", 0))}</span>'
    why_html = f'<span class="why" title="{e(chr(10).join(reasons))}">{e(reasons[0])}</span>' if reasons else ""
    inner = (
        f'<span class="node r-{e(risk or "none")}"></span>'
        f'<div class="entry-main"><div class="entry-top"><a class="dev" href="{device_href(device)}">{e(device)}</a>{risk_pill(risk)}{why_html}{flags}'
        f'<span class="entry-when">{ago(change.get("ts"), now)}</span></div>'
        f'<div class="entry-sum">{e(summary)}{f" <span class=more-n>+{more} more</span>" if more > 0 else ""}</div>'
        f'<div class="entry-meta">{who_html}<span class="stats">{stats}</span>{cats}{sha_html}</div></div>'
    )
    attrs = (
        f' data-risk="{e(risk or "none")}" data-cats="{e(" ".join(change.get("categories") or []))}" '
        f'data-unplanned="{1 if change.get("unplanned") else 0}" data-search="{e(search)}"'
    )
    if compact or not details:
        return f'<li class="entry"{attrs}><a class="entry-link" href="{tm}" aria-label="Open change"></a>{inner}</li>'
    return f'<li class="entry"{attrs}><details{open_attr}><summary>{inner}</summary>{details}</details></li>'


def topology_panel(view: dict[str, Any], mini: bool) -> str:
    topo = view.get("topology") or {"nodes": [], "links": [], "sites": []}
    devices = sum(1 for n in topo["nodes"] if not n.get("external"))
    sub = f"{devices} devices · {len(topo['links'])} links discovered via LLDP" if topo.get("lldp") else f"{devices} devices · waiting for LLDP neighbors"
    tools = (
        '<div class="seg" data-topo-mode><button class="on" data-m="health">Health</button><button data-m="changes">Changes 24h</button>'
        '<button data-m="vendor">Vendor</button></div>'
    )
    extra = f'<a class="more" href="/topology">Full map {icon("chev")}</a>' if mini else '<button class="btn sm" data-topo-fit>Fit</button><button class="btn sm" data-topo-reset>Reset layout</button>'
    legend = (
        '<div class="topo-legend"><span><i class="lg t-ok"></i>healthy</span><span><i class="lg t-warn"></i>warning</span>'
        '<span><i class="lg t-crit"></i>critical</span><span><i class="lg t-unk"></i>discovered</span>'
        '<span><i class="lg ring"></i>changed in 24h</span></div>'
    )
    return (
        f'<section class="panel topo-panel{" mini" if mini else ""}" data-live="map">'
        f'<header class="ph"><h2>{icon("map")}Network map</h2><span class="sub">{e(sub)}</span><div class="ph-tools">{tools}{extra}</div></header>'
        f'<div class="topo" data-topology data-now="{view.get("now", 0):.0f}"><script type="application/json" data-topo-json>{data_json(topo)}</script>'
        f'<noscript><div class="empty">The map needs JavaScript.</div></noscript>{legend}<div class="topo-tip" hidden></div></div></section>'
    )


def _kpi(label: str, glyph: str, value: str, sub: str, viz: str = "", tone: str = "", href: str = "") -> str:
    tag_name = "a" if href else "div"
    href_attr = f' href="{e(href)}"' if href else ""
    return (
        f'<{tag_name} class="kpi{(" t-" + tone) if tone else ""}"{href_attr}><div class="kpi-top"><span>{e(label)}</span>{icon(glyph)}</div>'
        f'<div class="kpi-value">{value}</div><div class="kpi-sub">{sub}</div><div class="kpi-viz">{viz}</div></{tag_name}>'
    )


# --------------------------------------------------------------------------- overview


def render_dashboard(view: dict[str, Any], nonce: str = "") -> str:
    rows: list[dict[str, Any]] = view["rows"]
    changes: list[dict[str, Any]] = view.get("changes") or []
    now = view.get("now") or time.time()
    common(view, rows, changes)
    site_filter = view.get("site_filter")
    visible = [r for r in rows if not site_filter or (r["info"].get("site") or "") == site_filter]
    thresholds = view.get("thresholds") or {}
    cpu_t, mem_t, tmp_t = thresholds.get("cpu", {}), thresholds.get("memory", {}), thresholds.get("temperature", {})

    total = len(visible)
    statuses = Counter(overall(r) for r in visible)
    sites = {r["info"].get("site") for r in visible if r["info"].get("site")}
    platforms = {r["info"].get("platform") for r in visible}
    backed = sum(1 for r in visible if r["backup"].get("status") == "ok")
    failed = sum(1 for r in visible if r["backup"].get("status") == "failed")
    pending = total - backed - failed
    names = {r["name"] for r in visible}
    recent = [c for c in changes if (c.get("ts") or 0) > now - DAY and c.get("device") in names]
    high = sum(1 for c in recent if c.get("risk") == "high")
    unplanned = sum(1 for c in recent if c.get("unplanned"))
    per_day = [0] * 14
    day_risk: list[list[str]] = [[] for _ in range(14)]
    for change in changes:
        age = int((now - (change.get("ts") or 0)) // DAY)
        if 0 <= age < 14 and change.get("device") in names:
            per_day[13 - age] += 1
            day_risk[13 - age].append(change.get("risk") or "low")
    day_tones = [{"high": "crit", "medium": "warn", "low": "acc"}.get(max_risk(r) or "", "none") for r in day_risk]
    rules = [(r["name"], k, v) for r in visible for k, v in ((r["compliance"].get("rules") or {}).items())]
    passing = sum(1 for _, _, v in rules if v.get("passed"))
    forecasts = [(r, m, f) for r in visible for m, f in ((r["health"].get("forecast") or {}).items())]
    forecasts.sort(key=lambda item: float(item[2].get("eta_seconds") or 0))
    fleet = view.get("fleet") or []
    health_pct = [round(b.get("ok", 0) / max(1, sum(b.values())) * 100, 1) if sum(b.values()) else None for b in fleet]
    backup_run = (view.get("runs") or {}).get("backup") or {}

    kpis = [
        _kpi("Devices", "layers", str(total), f"{len(sites)} sites · {len(platforms)} platforms",
             segbar([("ok", statuses.get("ok", 0)), ("warn", statuses.get("warning", 0)), ("crit", statuses.get("critical", 0)), ("unk", statuses.get("unknown", 0))], "device status")),
        _kpi("Config backups", "database", f"{backed}<small>/{total}</small>", (f'<span class="t-crit">{failed} failing</span> · ' if failed else "") + f"last run {ago(backup_run.get('finished'), now)}",
             segbar([("ok", backed), ("crit", failed), ("unk", pending)]), "crit" if failed else "ok"),
        _kpi("Changes · 24h", "commit", str(len(recent)), f'{high} high risk · <span class="{"t-warn" if unplanned else ""}">{unplanned} unplanned</span>',
             bars(per_day, day_tones), "warn" if unplanned else "", "/changes"),
        _kpi("Fleet health", "pulse", f'{statuses.get("ok", 0)}<small> healthy</small>',
             f'<span class="t-warn">{statuses.get("warning", 0)} warning</span> · <span class="t-crit">{statuses.get("critical", 0)} critical</span>',
             sparkline(health_pct, "ok", 140, 26), "crit" if statuses.get("critical") else "warn" if statuses.get("warning") else "ok"),
        _kpi("Compliance", "shield", f"{(passing / len(rules) * 100) if rules else 100:.0f}<small>%</small>", f"{len(rules) - passing} failing of {len(rules)} checks",
             segbar([("ok", passing), ("crit", len(rules) - passing)]), "warn" if len(rules) - passing else "ok"),
        _kpi("Forecasts", "trend", str(len(forecasts)),
             (f'{e(forecasts[0][0]["name"])} · {e(METRIC_INFO.get(forecasts[0][1], (forecasts[0][1],))[0].lower())} in ~{e(format_duration(float(forecasts[0][2]["eta_seconds"]), coarse=True))}' if forecasts else "no exhaustion predicted"),
             "", "warn" if forecasts else "ok"),
    ]

    items = attention(visible, now)
    att_html = "".join(
        f'<li class="att s-{i["sev"]}"><span class="att-ic">{icon(i["icon"])}</span><div class="att-body">'
        f'<div><a class="dev" href="{device_href(i["device"])}">{e(i["device"])}</a><b>{e(i["title"])}</b></div><small>{e(i["detail"])}</small></div>'
        f'<span class="att-when">{ago(i["since"], now, "")}</span></li>'
        for i in items[:9]
    ) or f'<li class="att-empty">{icon("check")}<b>All clear.</b><span>Every device is healthy, backed up and compliant.</span></li>'
    attention_panel = (
        f'<section class="panel att-panel" data-live="attention"><header class="ph"><h2>{icon("alert")}Needs attention</h2>'
        f'<span class="count {"t-crit" if any(i["sev"] == "crit" for i in items) else "t-warn" if items else "t-ok"}">{len(items)}</span></header>'
        f'<ul class="att-list">{att_html}</ul>' + (f'<div class="att-more">+{len(items) - 9} more</div>' if len(items) > 9 else "") + "</section>"
    )

    ledger = "".join(change_entry(c, now, view.get("links"), compact=True) for c in [c for c in changes if c.get("device") in names][:7])
    ledger_panel = (
        f'<section class="panel ledger-panel" data-live="ledger"><header class="ph"><h2>{icon("commit")}Change ledger</h2>'
        f'<span class="sub">every change, explained</span><div class="ph-tools"><a class="more" href="/changes">All changes {icon("chev")}</a></div></header>'
        f'<ol class="ledger">{ledger or "<li class=empty>No configuration changes recorded yet.</li>"}</ol></section>'
    )

    fc_html = []
    sparks_mem = (view.get("sparks") or {}).get("memory") or {}
    for row, metric, fc in forecasts[:4]:
        label, unit, glyph = METRIC_INFO.get(metric, (metric.title(), "", "trend"))
        days = float(fc.get("eta_seconds") or 0) / DAY
        fc_html.append(
            f'<li class="fc-item"><span class="fc-ic t-{"warn" if days <= 7 else "low"}">{icon(glyph)}</span><div><a class="dev" href="{device_href(row["name"])}#trends">{e(row["name"])}</a>'
            f'<small>{e(label)} {fc.get("current", 0):.0f}{e(unit)} → {float(fc["threshold"]):g}{e(unit)} · +{fc.get("slope_per_day", 0):.1f}{e(unit)}/day</small></div>'
            f'{sparkline(sparks_mem.get(row["name"]) if metric == "memory" else None, "warn", 70, 20) if metric == "memory" else ""}'
            f'<span class="eta t-{"warn" if days <= 7 else "low"}">~{e(format_duration(float(fc["eta_seconds"]), coarse=True))}</span></li>'
        )
    pulse_panel = (
        f'<section class="panel pulse-panel" data-live="pulse"><header class="ph"><h2>{icon("pulse")}Fleet health · 24h</h2>'
        f'<span class="sub">devices per status, every 30 minutes</span></header>'
        f'<div class="pb">{fleet_chart(fleet, view.get("fleet_start") or now - DAY, view.get("fleet_bucket") or 1800) if fleet else "<div class=empty>Health history appears after the first checks.</div>"}</div>'
        f'<div class="ph sub-h"><h3>{icon("trend")}Capacity forecasts</h3><span class="sub">linear trend of the last 7 days</span></div>'
        f'<ul class="fc-list">{"".join(fc_html) or "<li class=empty>Nothing is trending toward a threshold.</li>"}</ul></section>'
    )

    table = devices_table(visible, view, cpu_t, mem_t, tmp_t)
    site_note = f'<div class="filter-note">Showing site <b>{e(site_filter)}</b> · <a href="/">show all</a></div>' if site_filter else ""
    content = (
        f'{site_note}<section class="kpis" data-live="kpis">{"".join(kpis)}</section>'
        f'<div class="row r-map">{topology_panel(view, mini=True)}{attention_panel}</div>'
        f'<div class="row r-split">{ledger_panel}{pulse_panel}</div>{table}'
    )
    return page(view, "Overview", "Overview", content, crumbs=e(view.get("repo_label") or ""))


def devices_table(rows: list[dict[str, Any]], view: dict[str, Any], cpu_t: dict[str, Any], mem_t: dict[str, Any], tmp_t: dict[str, Any]) -> str:
    now = view.get("now") or time.time()
    strips = view.get("strips") or {}
    sparks = view.get("sparks") or {}
    strip_start = view.get("strip_start") or now - DAY
    body = []
    for row in rows:
        info, facts, backup, health = row["info"], row["facts"], row["backup"], row["health"]
        status = overall(row)
        kind = device_kind(info)
        model = facts.get("model") or ""
        tags = ""
        if backup.get("unsaved_changes"):
            tags += tag("unsaved", "warn", "Running configuration differs from startup")
        failing = failing_rules(row)
        if failing:
            tags += tag(f"{len(failing)} compliance", "crit" if any(v.get("severity") == "critical" for _, v in failing) else "info", ", ".join(k for k, _ in failing))
        if backup.get("status") == "failed":
            backup_cell = pill("failed", "Failing", backup.get("error")) + f'<small>{e(backup.get("consecutive_failures") or 1)}× · last good {ago(backup.get("last_success"), now)}</small>'
        elif backup.get("status") == "ok":
            backup_cell = pill("ok", "Backed up") + f"<small>{ago(backup.get('last_success'), now)}{tags}</small>"
        else:
            backup_cell = pill("pending") + "<small>waiting for first run</small>"
        change = row.get("last_change")
        if change:
            who = change.get("changed_by")
            change_cell = (
                f'<span class="chg"><i class="rdot r-{e(change.get("risk") or "none")}"></i>{ago(change.get("ts"), now)}</span>'
                f'<small title="{e("; ".join(change.get("highlights") or []))}">{e((change.get("highlights") or [""])[0][:42])}{e(" · " + who if who else "")}</small>'
            )
        elif backup.get("first_backup"):
            change_cell = f'<span class="muted">no changes</span><small>since {ago(backup.get("first_backup"), now)}</small>'
        else:
            change_cell = '<span class="muted">–</span>'
        hstatus = health.get("status")
        problems = [c.get("message") for c in health.get("checks") or [] if c.get("status") in ("warning", "critical", "unknown")]
        uptime = health.get("uptime")
        detail = problems[0] if problems else (f"up {format_duration(uptime, coarse=True)}" if uptime else "")
        health_cell = (pill(hstatus) if hstatus else '<span class="muted">–</span>') + (f'<small title="{e(detail)}">{e(detail)}</small>' if detail else "")
        cpu, mem = health.get("cpu"), health.get("memory_pct")
        temps = [t.get("value") for t in (health.get("temperatures") or {}).values() if t.get("value") is not None]
        temp = max(temps) if temps else None
        cpu_tone, mem_tone, tmp_tone = tone_for(cpu, cpu_t.get("warning"), cpu_t.get("critical")), tone_for(mem, mem_t.get("warning"), mem_t.get("critical")), tone_for(temp, tmp_t.get("warning"), tmp_t.get("critical"))
        cpu_cell = f'<div class="metric">{sparkline((sparks.get("cpu") or {}).get(row["name"]), cpu_tone)}<b class="t-{cpu_tone}">{cpu:.0f}%</b></div>' if cpu is not None else '<span class="muted">–</span>'
        mem_cell = f'<div class="metric">{sparkline((sparks.get("memory") or {}).get(row["name"]), mem_tone)}<b class="t-{mem_tone}">{mem:.0f}%</b></div>' if mem is not None else '<span class="muted">–</span>'
        temp_cell = f'<b class="num t-{tmp_tone if tmp_tone != "ok" else "plain"}">{temp:.0f}°C</b>' if temp is not None else '<span class="muted">–</span>'
        search = " ".join(str(v) for v in (row["name"], info.get("host"), info.get("site"), info.get("role"), info.get("platform"), info.get("platform_name"), info.get("vendor"), model, *(info.get("tags") or []))).lower()
        needs = "1" if status in ("warning", "critical") or backup.get("unsaved_changes") or failing or health.get("forecast") else "0"
        changed = "1" if change and (change.get("ts") or 0) > now - DAY else "0"
        sort_status = {"critical": 0, "warning": 1, "unknown": 2, "ok": 3}.get(status, 2)
        body.append(
            f'<tr data-search="{e(search)}" data-attn="{needs}" data-changed="{changed}" data-unsaved="{1 if backup.get("unsaved_changes") else 0}"'
            f' data-s-name="{e(row["name"].lower())}" data-s-status="{sort_status}" data-s-cpu="{cpu if cpu is not None else -1}" data-s-mem="{mem if mem is not None else -1}"'
            f' data-s-temp="{temp if temp is not None else -1}" data-s-change="{(change or {}).get("ts") or 0}">'
            f'<td><a class="devcell" href="{device_href(row["name"])}"><span class="kind k-{kind} t-{TONE.get(status, "unk")}">{icon(KIND_ICON.get(kind, "switch"))}</span>'
            f'<span><b>{e(row["name"])}</b><small><span class="mono">{e(info.get("host"))}</span>{e(" · " + info["site"] if info.get("site") else "")}</small></span></a></td>'
            f'<td><span class="plat">{e(info.get("platform_name") or info.get("platform") or "–")}</span><small>{e(model or "–")}</small></td>'
            f"<td>{backup_cell}</td><td>{change_cell}</td><td>{health_cell}</td>"
            f'<td class="strip-cell">{status_strip(strips.get(row["name"]), strip_start, view.get("strip_bucket") or 1800)}</td>'
            f"<td>{cpu_cell}</td><td>{mem_cell}</td><td>{temp_cell}</td></tr>"
        )
    head = (
        '<tr><th data-sort="name">Device</th><th>Platform</th><th>Backup</th><th data-sort="change">Last change</th>'
        '<th data-sort="status">Health</th><th>Last 24 hours</th><th data-sort="cpu">CPU</th><th data-sort="mem">Memory</th>'
        '<th data-sort="temp">Temp</th></tr>'
    )
    empty = '<tr><td colspan="9" class="empty">No devices yet - add some to your inventory.</td></tr>'
    return (
        f'<section class="panel devices" data-live="devices"><header class="ph"><h2>{icon("layers")}Devices</h2>'
        f'<span class="sub" data-count>{len(rows)} devices</span><div class="ph-tools">'
        f'<label class="find">{icon("search")}<input id="q" type="search" placeholder="Filter by name, site, platform, model, tag…" autocomplete="off" data-filter></label>'
        '<div class="seg" data-chips><button class="on" data-f="all">All</button><button data-f="attn">Needs attention</button>'
        '<button data-f="changed">Changed 24h</button><button data-f="unsaved">Unsaved</button></div></div></header>'
        f'<div class="scroll"><table id="devices" class="tbl"><thead>{head}</thead><tbody>{"".join(body) or empty}</tbody></table></div></section>'
    )


# --------------------------------------------------------------------------- device


def _version_label(version: dict[str, Any]) -> str:
    return clock_time(version.get("ts"), "%b %d %H:%M")


def time_machine(view: dict[str, Any], row: dict[str, Any]) -> str:
    name = row["name"]
    versions: list[dict[str, Any]] = view.get("versions") or []
    now = view.get("now") or time.time()
    if view.get("tm_error"):
        body = f'<div class="empty">{icon("history")}<b>Time machine unavailable</b><span>{e(view["tm_error"])}</span></div>'
        return f'<section class="panel tm" id="timemachine"><header class="ph"><h2>{icon("history")}Configuration time machine</h2></header>{body}</section>'
    if not versions:
        return (
            f'<section class="panel tm" id="timemachine"><header class="ph"><h2>{icon("history")}Configuration time machine</h2></header>'
            f'<div class="empty">{icon("history")}<b>No versions yet</b><span>Every backup that changes the configuration becomes a version here.</span></div></section>'
        )
    to_sha, from_sha = view.get("to_sha"), view.get("from_sha")
    first, last = versions[-1].get("ts") or now, now
    span = max(DAY, last - first)
    dots = []
    for version in reversed(versions):
        ts = version.get("ts") or now
        x = 16 + (ts - first) / span * 968
        size = 4 + min(6.0, (abs(version.get("added") or 0) + abs(version.get("removed") or 0)) ** 0.5)
        state = " to" if version["sha"] == to_sha else " from" if version["sha"] == from_sha else ""
        label = e(f'{_version_label(version)} · {version.get("summary") or version.get("subject") or ""}')
        dots.append(
            f'<g class="vd r-{e(version.get("risk") or "none")}{state}" data-sha="{e(version["sha"])}" transform="translate({x:.1f} 30)">'
            f'<circle class="halo" r="{size + 5:.1f}"/><circle r="{size:.1f}"/><title>{label}</title></g>'
        )
    ticks = []
    for index in range(5):
        ts = first + span * index / 4
        ticks.append(f'<text class="ax" x="{16 + 968 * index / 4:.1f}" y="62" text-anchor="{"start" if index == 0 else "end" if index == 4 else "middle"}">{e(clock_time(ts, "%b %d"))}</text>')
    rail = (
        f'<svg class="tm-rail" viewBox="0 0 1000 68" preserveAspectRatio="none"><path class="axis" d="M16 30H984"/>'
        f'{"".join(ticks)}{"".join(dots)}</svg>'
    )
    items = []
    for index, version in enumerate(versions):
        state = "to" if version["sha"] == to_sha else "from" if version["sha"] == from_sha else ""
        who = version.get("changed_by") or version.get("author")
        stat = ""
        if version.get("added") is not None:
            stat = f'<span class="v-stat"><span class="add">+{version.get("added", 0)}</span><span class="del">−{version.get("removed", 0)}</span></span>'
        why = version.get("reasons") or []
        title = f' title="{e(chr(10).join(why))}"' if why else ""
        items.append(
            f'<li class="v {state}" data-sha="{e(version["sha"])}" data-prev="{e(versions[index + 1]["sha"]) if index + 1 < len(versions) else ""}" tabindex="0"{title}>'
            f'<span class="v-dot r-{e(version.get("risk") or "none")}"></span><span class="v-main"><b>{e(_version_label(version))}</b>'
            f'<span class="muted">{e(who or "")}</span>'
            f'<small>{e(version.get("summary") or version.get("subject") or "")}</small></span>{stat}</li>'
        )
    to_version = next((v for v in versions if v["sha"] == to_sha), versions[0])
    from_version = next((v for v in versions if v["sha"] == from_sha), None)
    head = tm_head(from_version, to_version)
    analysis = view.get("analysis")
    intel = intel_card(analysis, view.get("tm_unplanned"), view.get("tm_who"), view.get("tm_when"), now) if analysis else ""
    diff_html = render_diff(view.get("diff") or "", show_files=False) if from_version else '<div class="diff-empty">This is the first version: switch to <b>Full config</b> to read it.</div>'
    count = len(versions)
    return (
        f'<section class="panel tm" id="timemachine" data-tm data-device="{e(name)}" data-from="{e(from_sha or "")}" data-to="{e(to_sha or "")}">'
        f'<header class="ph"><h2>{icon("history")}Configuration time machine</h2><span class="sub">{count} version{"s" if count != 1 else ""} · secrets masked</span>'
        f'<div class="ph-tools"><div class="seg" data-tm-view><button class="on" data-v="diff">{icon("split")}Changes</button><button data-v="config">{icon("code")}Full config</button></div>'
        f'<div class="seg" data-tm-layout><button class="on" data-l="unified">Unified</button><button data-l="split">Side by side</button></div>'
        f'<a class="btn sm" data-tm-download href="/api/devices/{q(name)}/config?rev={e(to_version["sha"])}&amp;download=1">{icon("download")}Download</a></div></header>'
        f'<div class="tm-rail-wrap">{rail}<div class="tm-hint">{icon("keyboard")}click a version to view it · shift-click to choose what to compare against</div></div>'
        f'<div class="tm-body"><ol class="tm-list">{"".join(items)}</ol><div class="tm-main">'
        f'<div class="tm-head" data-tm-head>{head}</div><div data-tm-intel>{intel}</div>'
        f'<div class="tm-diff" data-tm-diff>{diff_html}</div>'
        f'<div class="tm-config" data-tm-config hidden><div class="code-tools"><label class="find">{icon("search")}<input data-code-find placeholder="Find in this configuration…" autocomplete="off"></label>'
        f'<span class="muted" data-code-count></span><button class="btn sm" data-fold-all>Collapse sections</button></div><div data-code-body><div class="empty">Loading…</div></div></div>'
        "</div></div></section>"
    )


def tm_head(from_version: dict[str, Any] | None, to_version: dict[str, Any]) -> str:
    to_html = f'<span class="sha">{e(to_version["sha"][:7])}</span> {e(_version_label(to_version))}'
    if not from_version:
        return f'{icon("file")}Version {to_html}'
    return f'{icon("split")}Comparing <span class="sha from">{e(from_version["sha"][:7])}</span> {e(_version_label(from_version))} <span class="arrow">→</span> {to_html}'


def trends_panel(view: dict[str, Any], row: dict[str, Any]) -> str:
    series = view.get("series") or {}
    thresholds = view.get("thresholds") or {}
    forecasts = row["health"].get("forecast") or {}
    selected = view.get("range") or "24h"
    tabs = "".join(
        f'<a class="{"on" if selected == key else ""}" href="?range={key}#trends" data-r="{key}">{label}</a>'
        for key, label in (("24h", "24 hours"), ("7d", "7 days"), ("30d", "30 days"))
    )
    return (
        f'<section class="panel trends" id="trends" data-trends data-device="{e(row["name"])}"><header class="ph"><h2>{icon("trend")}Trends</h2>'
        f'<span class="sub">from {e(series.get("samples", 0))} health check{"" if series.get("samples") == 1 else "s"}</span><div class="ph-tools"><div class="seg" data-range>{tabs}</div></div></header>'
        f'<div class="charts" data-trends-body>{trend_charts(series, thresholds, forecasts)}</div></section>'
    )


def trend_charts(series: dict[str, Any], thresholds: dict[str, Any], forecasts: dict[str, Any]) -> str:
    cpu_t, mem_t, tmp_t = thresholds.get("cpu", {}), thresholds.get("memory", {}), thresholds.get("temperature", {})
    return (
        trend_chart(series, "cpu", "CPU · busiest core", "%", cpu_t.get("warning"), cpu_t.get("critical"))
        + trend_chart(series, "memory", "Memory", "%", mem_t.get("warning"), mem_t.get("critical"), forecasts.get("memory"))
        + trend_chart(series, "temperature", "Hottest sensor", "°C", tmp_t.get("warning"), tmp_t.get("critical"), forecasts.get("temperature"), maximum=None)
    )


def vitals_panel(view: dict[str, Any], row: dict[str, Any]) -> str:
    now = view.get("now") or time.time()
    health = row["health"]
    thresholds = view.get("thresholds") or {}
    cpu_t, mem_t, tmp_t = thresholds.get("cpu", {}), thresholds.get("memory", {}), thresholds.get("temperature", {})
    forecasts = health.get("forecast") or {}
    temps = health.get("temperatures") or {}
    hottest = max((t.get("value") for t in temps.values() if t.get("value") is not None), default=None)
    cores = len(health.get("cpus") or {})
    used, total = health.get("memory_used"), health.get("memory_total")
    mem_sub = f"{used / 1024 ** 3:.1f} of {total / 1024 ** 3:.0f} GB" if used and total else "of installed memory"
    gauges = (
        gauge(health.get("cpu"), "CPU", "%", cpu_t.get("warning"), cpu_t.get("critical"), sub=f"busiest of {cores} cores" if cores else "")
        + gauge(health.get("memory_pct"), "Memory", "%", mem_t.get("warning"), mem_t.get("critical"), sub=mem_sub,
                note=forecast_text(forecasts["memory"], "%") if forecasts.get("memory") else "")
        + gauge(hottest, "Temp", "°C", tmp_t.get("warning"), tmp_t.get("critical"), maximum=max(100.0, (tmp_t.get("critical") or 0) + 15),
                sub=f"hottest of {len(temps)} sensors" if temps else "", note=forecast_text(forecasts["temperature"], "°C") if forecasts.get("temperature") else "")
    )
    checks = "".join(
        f'<li><span class="ck-ic t-{TONE.get(c.get("status"), "unk")}">{icon(CHECK_ICONS.get(c.get("name"), "pulse"))}</span>'
        f'<span class="ck-name">{e(CHECK_NAMES.get(c.get("name"), c.get("name")))}</span><span class="ck-msg">{e(c.get("message"))}</span>{pill(c.get("status"), STATUS_LABEL.get(c.get("status") or "", "").replace("Healthy", "OK"))}</li>'
        for c in health.get("checks") or []
    ) or '<li class="empty">No health data yet.</li>'
    sensors = "".join(
        f'<span class="sensor t-{TONE.get(t.get("status"), "unk")}" title="{e(n)}"><b>{t.get("value", 0):.1f}°</b>{e(n)}</span>'
        for n, t in sorted(temps.items())
    )
    hw = "".join(f'<span class="hwled {"ok" if ok else "bad"}">{icon("fan")}{e(n)}</span>' for n, ok in sorted((health.get("fans") or {}).items()))
    hw += "".join(f'<span class="hwled {"ok" if ok else "bad"}">{icon("power")}{e(n)}</span>' for n, ok in sorted((health.get("psus") or {}).items()))
    reboot = ""
    if health.get("last_reboot") and now - health["last_reboot"] < 7 * DAY:
        reboot = tag(f"rebooted {format_duration(now - health['last_reboot'], coarse=True)} ago", "warn")
    return (
        f'<section class="panel vitals" data-live="vitals"><header class="ph"><h2>{icon("pulse")}Vitals</h2>'
        f'<span class="sub">checked {ago(health.get("checked_at"), now)}{" · up " + e(format_duration(health.get("uptime"), coarse=True)) if health.get("uptime") else ""}</span>{reboot}</header>'
        f'<div class="gauges">{gauges}</div><ul class="checks">{checks}</ul>'
        + (f'<div class="sensors">{sensors}</div>' if sensors else "")
        + (f'<div class="hw">{hw}</div>' if hw else "")
        + "</section>"
    )


def render_device(view: dict[str, Any], row: dict[str, Any], nonce: str = "") -> str:
    now = view.get("now") or time.time()
    rows = view.get("rows") or [row]
    changes = view.get("changes") or []
    common(view, rows, changes)
    info, facts, backup, health = row["info"], row["facts"], row["backup"], row["health"]
    status = overall(row)
    kind = device_kind(info)
    links = info.get("links") or {}
    chips = [
        f'<span class="mono">{e(info.get("host"))}</span>',
        e(info.get("platform_name") or info.get("platform")),
        e(facts.get("model")) if facts.get("model") else "",
        e(facts.get("os_version")) if facts.get("os_version") else "",
        f'S/N <span class="mono">{e(facts.get("serial_number"))}</span>' if facts.get("serial_number") else "",
        f'{icon("site")}{e(info.get("site"))}' if info.get("site") else "",
        e(info.get("role")) if info.get("role") else "",
    ]
    tags = "".join(tag(t, "info") for t in info.get("tags") or [])
    actions = []
    if links.get("history"):
        actions.append(f'<a class="btn" href="{e(links["history"])}">{icon("external")}History in Git</a>')
    actions.append(f'<a class="btn" href="/search?q={q(info.get("host") or row["name"])}">{icon("target")}Where is {e(info.get("host"))}?</a>')
    actions.append(f'<a class="btn" href="/api/devices/{q(row["name"])}">{icon("code")}JSON</a>')
    hero = (
        f'<section class="dhero t-{TONE.get(status, "unk")}" data-live="hero"><div class="dhero-id"><span class="kind big k-{kind} t-{TONE.get(status, "unk")}">{icon(KIND_ICON.get(kind, "switch"))}</span>'
        f'<div><h2>{e(row["name"])}{pill(status if status != "unknown" else "pending", STATUS_LABEL.get(status) if status != "unknown" else "Not checked yet")}</h2>'
        f'<div class="chips-line">{"<i>·</i>".join(c for c in chips if c)}</div><div class="tags">{tags}</div></div></div>'
        f'<div class="dhero-actions">{"".join(actions)}</div>'
        f'<div class="dhero-plate">{faceplate(kind, row["name"], facts.get("model") or info.get("platform_name") or "", health, status)}</div></section>'
    )
    alerts = []
    if backup.get("status") == "failed":
        alerts.append(f'<div class="alert t-crit">{icon("database")}<div><b>Backup failing</b> · {e(backup.get("consecutive_failures"))} in a row<small>{e(backup.get("error"))}</small></div></div>')
    if backup.get("unsaved_changes"):
        alerts.append(f'<div class="alert t-warn">{icon("file")}<div><b>Unsaved configuration</b><small>The running configuration differs from the startup configuration; a reload would lose these changes.</small></div></div>')
    last = row.get("last_change") or {}
    if last.get("unplanned"):
        alerts.append(f'<div class="alert t-warn">{icon("window")}<div><b>Unplanned change {ago(last.get("ts"), now)}</b><small>No approved change window covers it ({e(", ".join(view.get("windows") or []))}).</small></div></div>')

    compliance = row["compliance"].get("rules") or {}
    comp_items = "".join(
        f'<li><span class="ck-ic t-{"ok" if r.get("passed") else "crit" if r.get("severity") == "critical" else "warn"}">{icon("check" if r.get("passed") else "xcircle")}</span>'
        f'<span class="ck-name"><code>{e(name)}</code></span><span class="ck-msg">{e(r.get("description") or "")}'
        + (f'<small>{e("; ".join(r.get("findings") or []))}</small>' if not r.get("passed") and r.get("findings") else "")
        + f'</span>{pill("passed" if r.get("passed") else ("critical" if r.get("severity") == "critical" else "warning"), "Pass" if r.get("passed") else "Fail")}</li>'
        for name, r in sorted(compliance.items())
    )
    compliance_panel = (
        f'<section class="panel"><header class="ph"><h2>{icon("shield")}Compliance</h2><span class="sub">{sum(1 for r in compliance.values() if r.get("passed"))}/{len(compliance)} passing</span></header>'
        f'<ul class="checks">{comp_items or "<li class=empty>No compliance rules apply to this device.</li>"}</ul></section>'
    )
    neighbors = health.get("neighbors") or []
    known = {r["name"] for r in rows}
    nb_items = "".join(
        f'<li><span class="mono port">{e(n.get("port"))}</span><span class="arrow">↔</span>'
        + (f'<a class="dev" href="{device_href(n["remote"].split(".")[0])}">{e(n["remote"].split(".")[0])}</a>' if n.get("remote", "").split(".")[0] in known else f'<span>{e(n.get("remote"))}</span>')
        + f'<span class="mono port muted">{e(n.get("remote_port"))}</span></li>'
        for n in neighbors
    )
    neighbors_panel = (
        f'<section class="panel"><header class="ph"><h2>{icon("link")}Neighbors</h2><span class="sub">LLDP · {ago(health.get("neighbors_at"), now, "not collected")}</span></header>'
        f'<ul class="nb">{nb_items or "<li class=empty>No LLDP neighbors reported.</li>"}</ul></section>'
    )
    commit = backup.get("last_commit")
    commit_url = view["links"].commit(commit) if commit and view.get("links") else None
    details = [
        ("Status", pill("ok", "Backed up") if backup.get("status") == "ok" else pill("failed", "Failing") if backup.get("status") == "failed" else pill("pending")),
        ("Last success", ago(backup.get("last_success"), now)),
        ("Changes recorded", e(backup.get("changes_total") or 0)),
        ("Last commit", f'<a class="sha" href="{e(commit_url)}">{e(commit[:10])}</a>' if commit_url else f'<span class="sha">{e((commit or "–")[:10])}</span>'),
        ("Repository folder", f'<span class="mono">{e(info.get("dir") or "–")}</span>'),
        ("Backup took", e(f'{backup.get("duration", 0):.1f}s') if backup.get("duration") is not None else "–"),
    ]
    details_panel = (
        f'<section class="panel"><header class="ph"><h2>{icon("database")}Backup</h2><span class="sub">{e(view.get("repo_label") or "")}</span></header>'
        f'<dl class="kv">{"".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in details)}</dl></section>'
    )
    content = (
        f"{hero}{''.join(alerts)}<div class='row r-dev'>{vitals_panel(view, row)}{trends_panel(view, row)}</div>"
        f"{time_machine(view, row)}<div class='row r-3'>{compliance_panel}{neighbors_panel}{details_panel}</div>"
    )
    crumbs = f'<a href="/">Overview</a>{icon("chev")}' + (f'<a href="/?site={q(info.get("site"))}">{e(info.get("site"))}</a>{icon("chev")}' if info.get("site") else "") + e(row["name"])
    return page(view, row["name"], e(row["name"]), content, crumbs=crumbs)


# --------------------------------------------------------------------------- changes


def render_changes(view: dict[str, Any]) -> str:
    rows = view.get("rows") or []
    changes: list[dict[str, Any]] = view.get("changes") or []
    now = view.get("now") or time.time()
    common(view, rows, changes)
    month = [c for c in changes if (c.get("ts") or 0) > now - 30 * DAY]
    high = sum(1 for c in month if c.get("risk") == "high")
    unplanned = sum(1 for c in month if c.get("unplanned"))
    engineers = Counter(c.get("changed_by") for c in month if c.get("changed_by"))
    devices = Counter(c.get("device") for c in month)
    kpis = (
        _kpi("Changes · 30 days", "commit", str(len(month)), f"on {len(devices)} devices", bars(_per_day(changes, now, 30)))
        + _kpi("High risk", "alert", str(high), "routing, firewall, access, VPN, NAT", "", "crit" if high else "")
        + _kpi("Unplanned", "window", str(unplanned), e(", ".join(view.get("windows") or []) or "no change windows configured"), "", "warn" if unplanned else "")
        + _kpi("Engineers", "user", str(len(engineers)), " ".join(avatar(n) for n, _ in engineers.most_common(6)) or "unknown", "")
    )
    counts: Counter[str] = Counter(time.strftime("%Y-%m-%d", time.localtime(c["ts"])) for c in changes if c.get("ts"))
    categories: Counter[str] = Counter()
    for change in month:
        for key in change.get("categories") or []:
            categories[key] += 1
    peak = max(categories.values(), default=1)
    cat_rows = "".join(
        f'<li data-cat="{e(key)}"><span>{e(CATEGORIES.get(key, (key,))[0])}</span><span class="bar r-{e(CATEGORIES.get(key, ("", "low"))[1])}"><i style="width:{count / peak * 100:.0f}%"></i></span><b>{count}</b></li>'
        for key, count in sorted(categories.items(), key=lambda kv: (-kv[1], kv[0]))
    )
    top = "".join(f'<li><a class="dev" href="{device_href(n)}">{e(n)}</a><b>{c}</b></li>' for n, c in devices.most_common(5))
    filters = (
        '<div class="seg" data-risk-filter><button class="on" data-r="all">All</button><button data-r="high">High</button>'
        '<button data-r="medium">Medium</button><button data-r="low">Low</button></div>'
        '<label class="toggle"><input type="checkbox" data-unplanned-filter><span>Unplanned only</span></label>'
        f'<label class="find">{icon("search")}<input type="search" data-ledger-filter placeholder="Device, engineer, VLAN, ACL…" autocomplete="off"></label>'
    )
    groups: list[str] = []
    current_day = None
    entries: list[str] = []
    for index, change in enumerate(changes[:400]):
        day = time.strftime("%Y-%m-%d", time.localtime(change.get("ts") or 0))
        if day != current_day:
            if entries:
                groups.append(f'<li class="day"><h4>{e(_day_label(current_day, now))}</h4><ol class="ledger">{"".join(entries)}</ol></li>')
            current_day, entries = day, []
        entries.append(change_entry(change, now, view.get("links"), expanded=index == 0))
    if entries:
        groups.append(f'<li class="day"><h4>{e(_day_label(current_day, now))}</h4><ol class="ledger">{"".join(entries)}</ol></li>')
    content = (
        f'<section class="kpis k4">{kpis}</section>'
        f'<div class="row r-cal"><section class="panel"><header class="ph"><h2>{icon("calendar")}Change cadence</h2><span class="sub">changes per day</span></header>'
        f'<div class="pb heat-wrap">{calendar_heatmap(counts, now)}</div></section>'
        f'<section class="panel"><header class="ph"><h2>{icon("layers")}What changed · 30 days</h2></header><ul class="catbars">{cat_rows or "<li class=empty>No changes in the last 30 days.</li>"}</ul></section>'
        f'<section class="panel"><header class="ph"><h2>{icon("bolt")}Most changed</h2></header><ul class="toplist">{top or "<li class=empty>–</li>"}</ul></section></div>'
        f'<section class="panel ledger-full" data-live="ledger"><header class="ph"><h2>{icon("commit")}Change ledger</h2><span class="sub">{len(changes)} changes · newest first</span>'
        f'<div class="ph-tools">{filters}</div></header><ol class="days">{"".join(groups) or "<li class=empty>No configuration changes recorded yet.</li>"}</ol></section>'
    )
    return page(view, "Change ledger", "Change ledger", content, crumbs="Every configuration change, explained and scored")


def _per_day(changes: list[dict[str, Any]], now: float, days: int) -> list[float]:
    counts = [0.0] * days
    for change in changes:
        age = int((now - (change.get("ts") or 0)) // DAY)
        if 0 <= age < days:
            counts[days - 1 - age] += 1
    return counts


def _day_label(day: str | None, now: float) -> str:
    if not day:
        return ""
    today = time.strftime("%Y-%m-%d", time.localtime(now))
    yesterday = time.strftime("%Y-%m-%d", time.localtime(now - DAY))
    if day == today:
        return "Today"
    if day == yesterday:
        return "Yesterday"
    stamp = time.mktime(time.strptime(day, "%Y-%m-%d"))
    return time.strftime("%A, %B %d", time.localtime(stamp))


# --------------------------------------------------------------------------- where is (search)


EXAMPLES = ("10.10.40.57", "10.20.0.0/16", "192.0.2.10", "snmp-server community", "/ntp server 10\\.\\d+/", "GUEST")


def render_search(view: dict[str, Any]) -> str:
    rows = view.get("rows") or []
    changes = view.get("changes") or []
    common(view, rows, changes)
    query = view.get("query") or ""
    result = view.get("result")
    error = view.get("error")
    statuses = {r["name"]: overall(r) for r in rows}
    examples = "".join(f'<a class="chip" href="/search?q={q(x)}">{e(x)}</a>' for x in EXAMPLES)
    box = (
        f'<section class="where"><form class="where-box" method="get" action="/search">{icon("target")}'
        f'<input name="q" value="{e(query)}" placeholder="An IP address, a subnet, any text, or /a regex/" autocomplete="off" autofocus data-where>'
        f'<button class="btn primary">Search {len(rows)} devices</button></form>'
        f'<div class="where-hints"><span class="muted">Try</span>{examples}</div>'
        '<p class="where-help">IP searches understand every vendor\'s notation (<code>10.1.1.1 255.255.255.0</code>, ACL wildcards, '
        '<code>/24</code>, <code>host 10.1.1.1</code>, <code>address=10.1.1.1/24</code>) and rank the interface subnet an address lives in first '
        '- longest prefix wins, just like routing.</p></section>'
    )
    if error:
        body = f'<div class="alert t-warn">{icon("alert")}<div><b>{e(error)}</b></div></div>'
    elif result is None:
        body = ""
    else:
        summary = (
            f'<div class="where-sum"><b>{result.total} match{"es" if result.total != 1 else ""}</b> on <b>{len(result.hits)}</b> of {result.devices} devices'
            f' · {e(result.query.describe())} · {result.lines:,} lines in {result.elapsed * 1000:.0f} ms'
            + (' · <span class="t-warn">results truncated</span>' if result.truncated else "") + "</div>"
        )
        best = result.best()
        best_html = ""
        if best:
            exact = best[0][1].kind == "exact"
            items = "".join(
                f'<li>{dot(statuses.get(h.device))}<a class="dev" href="{device_href(h.device)}?view=config&amp;line={m.line_no}#timemachine">{e(h.device)}</a>'
                f'<span class="muted">{e(" › ".join(m.section) or "global")}</span><code>{e(m.line.strip())}</code></li>'
                for h, m in best
            )
            network = best[0][1].network or ""
            title = f"{e(result.query.raw)} is configured on" if exact else f"{e(result.query.raw)} lives in <span class=mono>{e(network)}</span>"
            best_html = f'<section class="best">{icon("target")}<div><h3>{title}</h3><ul>{items}</ul></div></section>'
        groups = []
        for hits in result.hits:
            lines = []
            for m in hits.matches:
                text = m.line
                parts, last = [], 0
                for start, end in sorted(m.spans):
                    if start < last:
                        continue
                    parts.append(e(text[last:start]))
                    parts.append(f"<mark>{e(text[start:end])}</mark>")
                    last = end
                parts.append(e(text[last:]))
                kind = f'<span class="k k-{e(m.kind)}">{e(KINDS.get(m.kind, m.kind))}{(" " + e(m.network)) if m.network and m.kind != "exact" else ""}</span>' if m.kind != "text" else ""
                lines.append(
                    f'<li><a class="ln" href="{device_href(hits.device)}?view=config&amp;line={m.line_no}#timemachine">{m.line_no}</a>'
                    f'<span class="ctx">{e(" › ".join(m.section))}</span><code>{"".join(parts)}</code>'
                    f'<span class="role">{e(ROLES.get(m.role, m.role))}</span>{kind}</li>'
                )
            info = hits.info
            groups.append(
                f'<section class="hit"><header>{dot(statuses.get(hits.device))}<a class="dev" href="{device_href(hits.device)}">{e(hits.device)}</a>'
                f'<span class="muted">{e(info.get("platform_name") or info.get("platform") or "")} · {e(info.get("site") or "")}</span>'
                f'<span class="mono muted">{e(hits.path)}</span><b>{len(hits.matches)}</b></header><ol>{"".join(lines)}</ol></section>'
            )
        body = summary + best_html + ("".join(groups) or f'<div class="empty">{icon("search")}<b>Nothing found</b><span>No configuration mentions {e(query)}.</span></div>')
    return page(view, "Where is", "Where is…", box + f'<div class="where-results">{body}</div>', crumbs="Fleet-wide, IP-aware configuration search")


# --------------------------------------------------------------------------- topology


def render_topology(view: dict[str, Any]) -> str:
    rows = view.get("rows") or []
    common(view, rows, view.get("changes") or [])
    return page(view, "Network map", "Network map", topology_panel(view, mini=False), crumbs="Discovered from LLDP · drag nodes, scroll to zoom")


# --------------------------------------------------------------------------- wallboard


def render_wall(view: dict[str, Any]) -> str:
    rows = view.get("rows") or []
    changes = view.get("changes") or []
    now = view.get("now") or time.time()
    common(view, rows, changes)
    statuses = Counter(overall(r) for r in rows)
    bad = statuses.get("critical", 0) + statuses.get("warning", 0)
    headline = "All systems nominal" if not bad else f"{bad} device{'s' if bad != 1 else ''} need{'s' if bad == 1 else ''} attention"
    tone = "crit" if statuses.get("critical") else "warn" if bad else "ok"
    tiles = []
    for row in sorted(rows, key=lambda r: ({"critical": 0, "warning": 1, "unknown": 2, "ok": 3}.get(overall(r), 2), r["name"])):
        status = overall(row)
        health = row["health"]
        problems = [c.get("message") for c in health.get("checks") or [] if c.get("status") in ("warning", "critical")]
        if row["backup"].get("status") == "failed" and not problems:
            problems = ["backup failing"]
        kind = device_kind(row["info"])
        metric = f'{health.get("cpu", 0):.0f}% cpu · {health.get("memory_pct", 0):.0f}% mem' if health.get("cpu") is not None else ""
        tiles.append(
            f'<div class="wt t-{TONE.get(status, "unk")}">{icon(KIND_ICON.get(kind, "switch"))}<b>{e(row["name"])}</b>'
            f'<span>{e(problems[0] if problems else metric or STATUS_LABEL.get(status, ""))}</span><small>{e(row["info"].get("site") or "")}</small></div>'
        )
    recent = changes[:8]
    ticker = "".join(
        f'<span class="tk">{risk_pill(c.get("risk"), short=True)}<b>{e(c.get("device"))}</b>{e((c.get("highlights") or [""])[0])}<i>{ago(c.get("ts"), now)}</i></span>'
        for c in recent
    )
    content = (
        f'<div class="wall-top"><div class="wall-brand">{icon("pulse")}<b>{e(view.get("title") or "NetLedger")}</b><span>NOC wallboard</span></div>'
        f'<div class="wall-head t-{tone}" data-live="wall-head"><i class="beacon"></i>{e(headline)}</div><div class="wall-clock" data-clock></div></div>'
        f'<div class="wall-kpis" data-live="wall-kpis"><div><b class="t-ok">{statuses.get("ok", 0)}</b>healthy</div><div><b class="t-warn">{statuses.get("warning", 0)}</b>warning</div>'
        f'<div><b class="t-crit">{statuses.get("critical", 0)}</b>critical</div><div><b>{sum(1 for c in changes if (c.get("ts") or 0) > now - DAY)}</b>changes · 24h</div>'
        f'<div><b>{sum(1 for r in rows if r["backup"].get("status") == "ok")}/{len(rows)}</b>backed up</div></div>'
        f'<div class="wall-grid" data-live="wall-grid">{"".join(tiles)}</div>'
        f'<div class="wall-ticker" data-live="wall-ticker"><div class="tk-label">{icon("commit")}Latest changes</div><div class="tk-track"><div class="tk-inner">{ticker}{ticker}</div></div></div>'
        '<a class="wall-exit" href="/">Exit wallboard</a>'
    )
    return page(view, "Wallboard", "Wallboard", content, body_class="wall")


def render_not_found(view: dict[str, Any], what: str) -> str:
    content = f'<div class="empty big">{icon("search")}<b>{e(what)} not found</b><span><a href="/">Back to the overview</a></span></div>'
    return page(view, "Not found", "Not found", content)


def version_rows(versions: list[dict[str, Any]], changes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge Git history with the change ledger (risk, summary, engineer) by commit id."""
    by_commit = {c.get("commit"): c for c in changes if c.get("commit")}
    out = []
    for index, version in enumerate(versions):
        record = by_commit.get(version.get("sha")) or {}
        ts = parse_iso(version.get("date")) if version.get("date") else None
        initial = index == len(versions) - 1
        summary = (record.get("highlights") or [None])[0]
        if not summary:
            subject = version.get("subject") or ""
            summary = "initial backup" if initial or subject.endswith("initial backup") else subject.split(": ", 1)[-1]
        out.append({
            **version,
            "ts": ts,
            "risk": record.get("risk") if record else (None if initial else None),
            "summary": summary,
            "changed_by": record.get("changed_by"),
            "unplanned": record.get("unplanned"),
            "highlights": record.get("highlights") or [],
            "reasons": record.get("reasons") or [],
        })
    return out


def risk_rank(risk: Optional[str]) -> int:
    return RISK_ORDER.get(risk or "", -1)
