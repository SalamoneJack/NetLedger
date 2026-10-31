"""Page frame: sidebar, top bar, command palette and live-update hooks."""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import quote

from netledger import __version__
from netledger.utils import format_duration
from netledger.web.assets import asset_url
from netledger.web.ui import LOGO, ago, dot, e, icon, sprite

NAV = (
    ("overview", "/", "grid", "Overview"),
    ("topology", "/topology", "map", "Network map"),
    ("changes", "/changes", "commit", "Change ledger"),
    ("search", "/search", "target", "Where is…"),
    ("wall", "/wall", "tv", "NOC wallboard"),
)


def _job(view: dict[str, Any], job: str, label: str, glyph: str) -> str:
    now_ts = view.get("now") or time.time()
    run = (view.get("runs") or {}).get(job) or {}
    info = (view.get("jobs") or {}).get(job) or {}
    progress = (view.get("progress") or {}).get(job)
    if progress:
        done, total = progress.get("done", 0), progress.get("total", 0) or 1
        state = f'<span class="job-run">running · {done}/{total}</span>'
        bar = f'<div class="job-bar"><span style="width:{done / total * 100:.0f}%"></span></div>'
    else:
        nxt = info.get("next_run")
        state = f'<span class="muted">next in {e(format_duration(max(0, nxt - now_ts), coarse=True))}</span>' if nxt else ""
        bar = ""
    button = ""
    if view.get("can_trigger"):
        button = f'<button class="job-btn" data-run="{job}" title="Run {label.lower()} now">{icon("play")}</button>'
    return (
        f'<div class="job" data-job="{job}">{icon(glyph, "job-ic")}<div class="job-body"><b>{e(label)}</b>'
        f'<span>{ago(run.get("finished"), now_ts, "not run yet")} {state}</span>{bar}</div>{button}</div>'
    )


def sidebar(view: dict[str, Any]) -> str:
    page = view.get("page")
    nav = view.get("nav") or {}
    links = []
    for key, href, glyph, label in NAV:
        count = nav.get(key)
        badge = f'<em class="{e(nav.get(key + "_tone", ""))}">{count}</em>' if count else ""
        links.append(f'<a href="{href}" class="{"on" if page == key else ""}" data-key="{key}">{icon(glyph)}<span>{e(label)}</span>{badge}</a>')
    sites = []
    for site, status, count in view.get("sites") or []:
        name = site or "(no site)"
        sites.append(f'<a href="/?site={quote(site)}" class="site">{dot(status)}<span>{e(name)}</span><em>{count}</em></a>')
    repo = view.get("repo_url")
    repo_label = e(view.get("repo_label") or "")
    repo_html = f'<a href="{e(repo)}" class="repo" title="{repo_label}">{icon("database")}<span>{repo_label}</span></a>' if repo else f'<div class="repo" title="{repo_label}">{icon("database")}<span>{repo_label}</span></div>'
    return (
        f'<aside class="side"><a class="brand" href="/">{LOGO}<span><b>{e(view.get("title") or "NetLedger")}</b>'
        f'<small>config ledger · health</small></span></a>'
        f'<nav class="nav">{"".join(links)}</nav>'
        + (f'<div class="side-group"><h6>Sites</h6>{"".join(sites)}</div>' if sites else "")
        + f'<div class="side-foot">{_job(view, "backup", "Backup", "database")}{_job(view, "health", "Health check", "pulse")}{repo_html}</div></aside>'
    )


def topbar(view: dict[str, Any], heading: str, crumbs: str = "") -> str:
    theme = view.get("theme") or "light"
    return (
        f'<header class="top"><div class="top-l">{f"<div class=crumbs>{crumbs}</div>" if crumbs else ""}<h1>{heading}</h1></div>'
        f'<div class="top-r"><button class="cmdk" data-palette>{icon("search")}<span>Search devices, IPs, configs…</span><kbd>Ctrl K</kbd></button>'
        f'<span class="live" data-live-indicator title="Live updates">{icon("pulse")}<span>Live</span></span>'
        f'<button class="icon-btn" data-theme-toggle title="Toggle light / dark ({e(theme)})">{icon("sun", "i-sun")}{icon("moon", "i-moon")}</button></div></header>'
        '<div class="topprog" data-topprog hidden><span></span></div>'
    )


def page(view: dict[str, Any], title: str, heading: str, content: str, crumbs: str = "", body_class: str = "") -> str:
    theme = view.get("theme") or "light"
    site_title = view.get("title") or "NetLedger"
    footer = (
        f'<footer>NetLedger {e(__version__)} · <a href="/metrics">Prometheus metrics</a> · <a href="/api/status">JSON API</a>'
        f' · secrets are masked everywhere in this interface · rendered {e(time.strftime("%H:%M:%S", time.localtime(view.get("now") or time.time())))}</footer>'
    )
    shell = (
        f'<div class="app">{sidebar(view)}<div class="main">{topbar(view, heading, crumbs)}'
        f'<main id="content" data-live-root>{content}</main>{footer}</div></div>'
    ) if body_class != "wall" else f'<main id="content" data-live-root>{content}</main>'
    return (
        f'<!doctype html><html lang="en" data-theme="{e(theme)}"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark light">'
        f'<title>{e(title)} · {e(site_title)}</title>'
        f'<link rel="icon" href="data:image/svg+xml,{quote(LOGO)}"><link rel="stylesheet" href="{asset_url("app.css")}"></head>'
        f'<body class="{e(body_class)}" data-page="{e(view.get("page") or "")}" data-rev="{e(view.get("rev", 0))}" data-cursor="{e(view.get("cursor", 0))}"'
        f' data-trigger="{1 if view.get("can_trigger") else 0}">{sprite()}{shell}'
        '<div class="toasts" data-toasts></div>'
        f'<script src="{asset_url("app.js")}" defer></script></body></html>'
    )
