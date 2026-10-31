"""Built-in HTTP server: web console, JSON API, Prometheus metrics and Kubernetes probes."""

from __future__ import annotations

import base64
import hmac
import json
import logging
import re
import threading
import time
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import parse_qs, quote, unquote, urlparse

from netledger import __version__
from netledger.config import Settings
from netledger.history import MetricsHistory
from netledger.intel import analyze
from netledger.metrics import render_metrics
from netledger.normalize import Normalizer
from netledger.platforms import get_platform
from netledger.search import DocumentCache, QueryError, SearchResult, config_root, parse_query, search
from netledger.state import StateStore
from netledger.storage import Store, StoreError, derive_web_url, links_for
from netledger.topology import build_topology
from netledger.utils import unified_diff
from netledger.web import (
    build_rows,
    intel_card,
    overall,
    render_changes,
    render_config,
    render_dashboard,
    render_device,
    render_diff,
    render_not_found,
    render_search,
    render_topology,
    render_wall,
    tm_head,
    trend_charts,
    version_rows,
)
from netledger.web.assets import lookup as asset_lookup
from netledger.windows import ChangeCalendar

log = logging.getLogger(__name__)

DAY = 86400.0
RANGES = {"24h": DAY, "7d": 7 * DAY, "30d": 30 * DAY}
_SHA = re.compile(r"^[0-9a-fA-F]{7,40}$")


class JobTracker:
    """Progress of running jobs, for the live dashboard."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._jobs: dict[str, dict[str, Any]] = {}

    def start(self, job: str, total: int = 0) -> None:
        with self._lock:
            self._jobs[job] = {"total": total, "done": 0, "current": None, "started": time.time(), "failed": 0}

    def advance(self, job: str, name: str | None = None, status: str | None = None) -> None:
        with self._lock:
            entry = self._jobs.get(job)
            if entry is not None:
                entry["done"] += 1
                entry["current"] = name
                if status in ("failed", "critical"):
                    entry["failed"] += 1
                entry["total"] = max(entry["total"], entry["done"])

    def finish(self, job: str) -> None:
        with self._lock:
            self._jobs.pop(job, None)

    def status(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return {job: dict(entry) for job, entry in self._jobs.items()}

    def wrap(self, job: str, func: Callable[[Callable[[Any], None]], Any], total: Callable[[], int] | None = None) -> Callable[[], Any]:
        """Scheduler job that reports per-device progress of ``func(progress)``."""

        def run() -> Any:
            try:
                count = total() if total else 0
            except Exception:  # noqa: BLE001
                count = 0
            self.start(job, count)

            def progress(result: Any) -> None:
                device = getattr(result, "device", None)
                self.advance(job, getattr(device, "name", None), getattr(result, "status", None))

            try:
                return func(progress)
            finally:
                self.finish(job)

        return run


class App:
    """Shared state for request handlers: builds the views, reads history, searches configurations."""

    def __init__(
        self,
        settings: Settings,
        state: StateStore,
        scheduler: Any | None = None,
        inventory_loader: Callable[[], list[dict[str, Any]]] | None = None,
        history: MetricsHistory | None = None,
        tracker: JobTracker | None = None,
    ):
        self.settings = settings
        self.state = state
        self.scheduler = scheduler
        self.inventory_loader = inventory_loader
        self.links = links_for(settings)
        self.ready = False
        self.tracker = tracker or JobTracker()
        self._own_history = history is None
        self.history = history if history is not None else MetricsHistory.for_settings(settings)
        self.normalizer = Normalizer(settings.normalize)
        self.documents = DocumentCache()
        self._inventory: list[dict[str, Any]] = []
        self._inventory_at = 0.0
        self._lock = threading.Lock()
        self._store: Store | None = None
        self._versions: dict[str, tuple[float, list[dict[str, Any]]]] = {}
        self._blobs: OrderedDict[tuple[str, str], str | None] = OrderedDict()
        try:
            from netledger.scheduler import load_timezone

            tz = load_timezone(settings.changes.timezone or settings.schedule.timezone)
        except ValueError:
            tz = None
        self.calendar = ChangeCalendar(settings.changes.windows, tz)

    def close(self) -> None:
        if self._own_history and self.history is not None:
            self.history.close()

    # ------------------------------------------------------------------ data

    def inventory(self) -> list[dict[str, Any]]:
        if self.inventory_loader is None:
            return []
        with self._lock:
            if time.time() - self._inventory_at > 30:
                try:
                    self._inventory = self.inventory_loader()
                except Exception as exc:  # noqa: BLE001
                    log.warning("dashboard could not load inventory: %s", exc)
                self._inventory_at = time.time()
            return list(self._inventory)

    def rows(self) -> list[dict[str, Any]]:
        snapshot = self.state.snapshot()
        return build_rows(snapshot, self.inventory(), list(reversed(snapshot.get("changes") or [])))

    @property
    def can_trigger(self) -> bool:
        server = self.settings.server
        return self.scheduler is not None and bool(server.api_token or server.username or server.allow_anonymous_triggers)

    def _repo_label(self) -> tuple[str | None, str]:
        git = self.settings.git
        repo_url = self.links.base
        if repo_url:
            return repo_url, repo_url.replace("https://", "") + f" · {git.branch}"
        if git.backend == "local":
            path = self.settings.resolve_path(git.workdir) if git.workdir else self.settings.data_path / "repo"
            try:
                shown = path.relative_to(self.settings.base_dir).as_posix()
            except ValueError:
                shown = path.name
            return None, f"local repository · {shown}"
        return None, derive_web_url(git.url) or git.url or ""

    def base_view(self, page: str, theme: str | None = None) -> dict[str, Any]:
        snapshot = self.state.snapshot()
        changes = list(reversed(snapshot.get("changes") or []))
        thresholds = self.settings.health.thresholds
        repo_url, repo_label = self._repo_label()
        now = time.time()
        return {
            "page": page,
            "title": self.settings.server.title,
            "rows": build_rows(snapshot, self.inventory(), changes),
            "changes": changes,
            "runs": snapshot.get("runs") or {},
            "jobs": self.scheduler.status() if self.scheduler else {},
            "progress": self.tracker.status(),
            "repo_url": repo_url,
            "repo_label": repo_label,
            "links": self.links,
            "can_trigger": self.can_trigger,
            "theme": theme if theme in ("auto", "light", "dark") else self.settings.server.theme,
            "now": now,
            "rev": self.state.revision,
            "cursor": self.state.activity_cursor,
            "windows": self.calendar.texts,
            "next_window": self.calendar.next_open(now),
            "thresholds": {
                "cpu": thresholds.cpu.model_dump(),
                "memory": thresholds.memory.model_dump(),
                "temperature": thresholds.temperature.model_dump(),
            },
        }

    def _history_views(self, view: dict[str, Any]) -> None:
        if self.history is None:
            return
        now = view["now"]
        since = now - DAY
        view.update({
            "strips": self.history.strips(since, 48, now),
            "strip_start": since,
            "strip_bucket": DAY / 48,
            "sparks": {"cpu": self.history.sparks("cpu", since, 24, now), "memory": self.history.sparks("memory", since, 24, now)},
            "fleet": self.history.fleet(since, 48, now),
            "fleet_start": since,
            "fleet_bucket": DAY / 48,
        })

    def topology(self, rows: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        return build_topology(rows if rows is not None else self.rows(), overall)

    def overview_view(self, theme: str | None = None, site: str | None = None) -> dict[str, Any]:
        view = self.base_view("overview", theme)
        view["site_filter"] = site
        self._history_views(view)
        view["topology"] = self.topology(view["rows"])
        return view

    # kept for backwards compatibility with embedders of 1.0
    def view(self, theme: str | None = None) -> dict[str, Any]:
        return self.overview_view(theme)

    # ------------------------------------------------------------------ repository history

    def _reader(self) -> Store | None:
        if self._store is not None:
            return self._store
        git = self.settings.git
        if git.backend == "github":
            from netledger.storage.github import GitHubStore

            self._store = GitHubStore(git)
        else:
            from netledger.storage.gitcli import GitCLIStore

            workdir = self.settings.resolve_path(git.workdir) if git.workdir else self.settings.data_path / "repo"
            if not (workdir / ".git").is_dir():
                return None
            self._store = GitCLIStore(git, workdir)
        return self._store

    def config_path(self, row: dict[str, Any]) -> str | None:
        folder = row["info"].get("dir")
        if not folder:
            return None
        try:
            extension = get_platform(row["info"].get("platform") or "").extension
        except KeyError:
            extension = "cfg"
        return f"{folder}/running-config.{extension}"

    def versions(self, row: dict[str, Any], limit: int = 60) -> list[dict[str, Any]]:
        path = self.config_path(row)
        reader = self._reader()
        if not path or reader is None:
            return []
        cached = self._versions.get(path)
        revision = self.state.revision
        if cached and cached[0] == revision:
            entries = cached[1]
        else:
            entries = reader.versions(path, limit)
            self._versions[path] = (revision, entries)
        changes = self.state.changes(device=row["name"])
        return version_rows(entries, changes)

    def show(self, row: dict[str, Any], rev: str) -> str | None:
        path = self.config_path(row)
        reader = self._reader()
        if not path or reader is None or not _SHA.match(rev or ""):
            return None
        key = (path, rev)
        if key not in self._blobs:
            text = reader.show(rev, path)
            self._blobs[key] = self.normalizer.mask(text, self._platform(row)) if text is not None else None
            while len(self._blobs) > 64:
                self._blobs.popitem(last=False)
        return self._blobs[key]

    def _platform(self, row: dict[str, Any]) -> Any:
        try:
            return get_platform(row["info"].get("platform") or "")
        except KeyError:
            return get_platform("generic")

    def compare(self, row: dict[str, Any], frm: str | None, to: str) -> dict[str, Any]:
        new = self.show(row, to)
        if new is None:
            raise KeyError(to)
        old = self.show(row, frm) if frm else None
        path = self.config_path(row) or "running-config"
        platform = self._platform(row)
        if old is None:
            return {"from": None, "to": to, "diff": "", "analysis": {"initial": True, "added": len(new.splitlines())}}
        return {
            "from": frm,
            "to": to,
            "diff": unified_diff(old, new, path),
            "analysis": analyze(old, new, platform.key).to_dict(max_items=12),
        }

    def time_machine(self, row: dict[str, Any], to: str | None = None, frm: str | None = None) -> dict[str, Any]:
        try:
            versions = self.versions(row)
        except (StoreError, NotImplementedError) as exc:
            return {"versions": [], "tm_error": str(exc)}
        except Exception as exc:  # noqa: BLE001
            log.debug("time machine for %s unavailable: %s", row["name"], exc)
            return {"versions": [], "tm_error": f"repository history is not available: {exc}"}
        if not versions:
            return {"versions": []}
        shas = [v["sha"] for v in versions]
        to_sha = next((s for s in shas if to and s.startswith(to)), shas[0])
        index = shas.index(to_sha)
        from_sha = next((s for s in shas if frm and s.startswith(frm)), shas[index + 1] if index + 1 < len(shas) else None)
        result: dict[str, Any] = {"versions": versions, "to_sha": to_sha, "from_sha": from_sha}
        try:
            result.update(self.compare(row, from_sha, to_sha))
        except (KeyError, StoreError) as exc:
            result["tm_error"] = f"could not read version {exc}"
        record = versions[index]
        result.update({"tm_unplanned": record.get("unplanned"), "tm_who": record.get("changed_by") or record.get("author"), "tm_when": record.get("ts")})
        return result

    def trends(self, name: str, window: str = "24h") -> dict[str, Any]:
        span = RANGES.get(window, DAY)
        now = time.time()
        if self.history is None:
            return {"t": [], "start": now - span, "end": now}
        series = self.history.series(name, now - span, now, points=144 if span <= DAY else 168)
        series["samples"] = sum(1 for s in series["status"] if s is not None)
        return series

    def device_view(self, name: str, theme: str | None = None, query: dict[str, str] | None = None) -> tuple[dict[str, Any], dict[str, Any] | None]:
        query = query or {}
        view = self.base_view("device", theme)
        row = next((r for r in view["rows"] if r["name"] == name), None)
        if row is None:
            return view, None
        window = query.get("range") if query.get("range") in RANGES else "24h"
        view["range"] = window
        view["series"] = self.trends(name, window)
        view.update(self.time_machine(row, query.get("to"), query.get("from")))
        return view, row

    # ------------------------------------------------------------------ search

    def search(self, query: Any, rows: list[dict[str, Any]] | None = None) -> SearchResult:
        rows = rows if rows is not None else self.rows()
        entries = []
        for row in rows:
            path = self.config_path(row)
            if path:
                entries.append((row["name"], path, row["info"].get("platform"), row["info"]))
        documents = self.documents.load(config_root(self.settings), entries, lambda raw, platform: self.normalizer.mask(raw, self._platform_for(platform)) or "")
        return search(documents, query)

    def _platform_for(self, key: str | None) -> Any:
        try:
            return get_platform(key or "")
        except KeyError:
            return get_platform("generic")

    def search_view(self, theme: str, text: str) -> dict[str, Any]:
        view = self.base_view("search", theme)
        view["query"] = text
        if text.strip():
            try:
                view["result"] = self.search(parse_query(text), view["rows"])
            except QueryError as exc:
                view["error"] = str(exc)
        return view

    # ------------------------------------------------------------------ live updates

    def live(self, cursor: int = 0) -> dict[str, Any]:
        return {
            "rev": self.state.revision,
            "now": time.time(),
            "jobs": self.scheduler.status() if self.scheduler else {},
            "progress": self.tracker.status(),
            "cursor": self.state.activity_cursor,
            "activity": list(reversed(self.state.activity(after=cursor, limit=10))),
        }


def _handler_for(app: App) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = f"NetLedger/{__version__}"
        sys_version = ""

        def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
            log.debug("%s %s", self.address_string(), fmt % args)

        # ---------------------------------------------------------- helpers

        def _send(self, status: int, body: bytes, content_type: str, extra: dict[str, str] | None = None, cache: str = "no-store") -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", cache)
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, status: int, payload: Any) -> None:
            self._send(status, json.dumps(payload, indent=2, default=str).encode(), "application/json")

        def _html(self, page: str, status: int = 200) -> None:
            csp = (
                "default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'self'; "
                "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
            )
            self._send(status, page.encode(), "text/html; charset=utf-8", {"Content-Security-Policy": csp, "X-Frame-Options": "DENY"})

        def _auth_method(self) -> str | None:
            """'token', 'basic', 'open' or None (rejected)."""
            server = app.settings.server
            if not (server.username or server.api_token):
                return "open"
            header = self.headers.get("Authorization", "")
            if server.api_token and header.startswith("Bearer ") and hmac.compare_digest(header[7:].strip(), server.api_token):
                return "token"
            if server.username and header.startswith("Basic "):
                try:
                    user, _, password = base64.b64decode(header[6:]).decode().partition(":")
                except (ValueError, UnicodeDecodeError):
                    return None
                if hmac.compare_digest(user, server.username) and hmac.compare_digest(password, server.password or ""):
                    return "basic"
            return None

        def _require_auth(self) -> str | None:
            method = self._auth_method()
            if method is None:
                extra = {"WWW-Authenticate": 'Basic realm="NetLedger", charset="UTF-8"'} if app.settings.server.username else {}
                self._send(401, b"authentication required\n", "text/plain", extra)
            return method

        def _theme(self, query: dict[str, list[str]]) -> str:
            if query.get("theme"):
                return query["theme"][0]
            match = re.search(r"(?:^|;\s*)nl_theme=(auto|light|dark)\b", self.headers.get("Cookie", ""))
            return match.group(1) if match else app.settings.server.theme

        # ---------------------------------------------------------- routes

        def do_HEAD(self) -> None:  # noqa: N802
            self.do_GET()

        def do_GET(self) -> None:  # noqa: N802
            url = urlparse(self.path)
            raw_path = url.path.rstrip("/") or "/"
            query = parse_qs(url.query)
            arg = {k: v[0] for k, v in query.items() if v}
            if raw_path == "/healthz":
                self._send(200, b"ok\n", "text/plain")
                return
            if raw_path == "/readyz":
                self._send(200 if app.ready else 503, b"ready\n" if app.ready else b"starting\n", "text/plain")
                return
            if raw_path.startswith("/static/"):
                found = asset_lookup(raw_path[len("/static/"):])
                if found is None:
                    self._send(404, b"not found\n", "text/plain")
                else:
                    body, content_type, immutable = found
                    self._send(200, body, content_type, cache="public, max-age=31536000, immutable" if immutable else "no-cache")
                return
            if raw_path == "/metrics":
                if app.settings.server.metrics_auth and self._require_auth() is None:
                    return
                self._send(200, render_metrics(app.state.snapshot()).encode(), "text/plain; version=0.0.4; charset=utf-8")
                return
            if self._require_auth() is None:
                return
            theme = self._theme(query)
            try:
                self._route(raw_path, arg, theme)
            except BrokenPipeError:
                pass

        def _route(self, path: str, arg: dict[str, str], theme: str) -> None:
            if path == "/":
                self._html(render_dashboard(app.overview_view(theme, arg.get("site"))))
            elif path == "/topology":
                view = app.base_view("topology", theme)
                view["topology"] = app.topology(view["rows"])
                self._html(render_topology(view))
            elif path == "/changes":
                self._html(render_changes(app.base_view("changes", theme)))
            elif path == "/search":
                self._html(render_search(app.search_view(theme, arg.get("q", ""))))
            elif path == "/wall":
                self._html(render_wall(app.base_view("wall", theme)))
            elif path.startswith("/devices/"):
                name = unquote(path[len("/devices/"):])
                view, row = app.device_view(name, theme, arg)
                if row is None:
                    self._html(render_not_found(view, f"Device {name}"), 404)
                else:
                    self._html(render_device(view, row))
            elif path.startswith("/api/"):
                self._api(path[len("/api/"):], arg)
            else:
                self._send(404, b"not found\n", "text/plain")

        def _api(self, path: str, arg: dict[str, str]) -> None:
            if path == "status":
                snapshot = app.state.snapshot()
                self._json(200, {
                    "version": __version__,
                    "runs": snapshot.get("runs"),
                    "jobs": app.scheduler.status() if app.scheduler else {},
                    "devices": len(snapshot.get("devices") or {}),
                    "rev": app.state.revision,
                })
            elif path == "live":
                try:
                    cursor = int(arg.get("cursor", "0"))
                except ValueError:
                    cursor = 0
                self._json(200, app.live(cursor))
            elif path == "devices":
                self._json(200, app.rows())
            elif path == "palette":
                self._json(200, [
                    {"name": r["name"], "host": r["info"].get("host"), "site": r["info"].get("site"), "platform": r["info"].get("platform_name"),
                     "model": r["facts"].get("model"), "status": overall(r)}
                    for r in app.rows()
                ])
            elif path == "topology":
                self._json(200, app.topology())
            elif path == "changes":
                try:
                    limit = max(1, min(1000, int(arg.get("limit", "100"))))
                except ValueError:
                    limit = 100
                self._json(200, app.state.changes(limit=limit, device=arg.get("device")))
            elif path == "search":
                try:
                    query = parse_query(arg.get("q", ""), regex=arg.get("regex") == "1")
                except QueryError as exc:
                    self._json(400, {"error": str(exc)})
                    return
                self._json(200, app.search(query).to_dict())
            elif path.startswith("devices/"):
                self._device_api(path[len("devices/"):], arg)
            else:
                self._json(404, {"error": "not found"})

        def _device_api(self, rest: str, arg: dict[str, str]) -> None:
            name_part, _, action = rest.partition("/")
            name = unquote(name_part)
            row = next((r for r in app.rows() if r["name"] == name), None)
            if row is None:
                self._json(404, {"error": "device not found"})
                return
            if not action:
                self._json(200, row)
            elif action == "versions":
                try:
                    self._json(200, app.versions(row))
                except (StoreError, NotImplementedError) as exc:
                    self._json(503, {"error": str(exc)})
            elif action == "config":
                versions = app.versions(row)
                rev = arg.get("rev") or (versions[0]["sha"] if versions else "")
                text = app.show(row, rev) if rev else None
                if text is None:
                    self._json(404, {"error": "version not found"})
                    return
                if arg.get("download"):
                    extension = (app.config_path(row) or "x.cfg").rsplit(".", 1)[-1]
                    filename = re.sub(r"[^\w.-]+", "_", f"{name}-{rev[:7]}.{extension}")
                    self._send(200, text.encode(), "text/plain; charset=utf-8", {"Content-Disposition": f'attachment; filename="{filename}"'})
                    return
                line = int(arg["line"]) if arg.get("line", "").isdigit() else None
                self._json(200, {"rev": rev, "lines": len(text.splitlines()), "text": text, "html": render_config(text, row["info"].get("platform"), line)})
            elif action == "diff":
                to, frm = arg.get("to", ""), arg.get("from") or None
                if not _SHA.match(to) or (frm and not _SHA.match(frm)):
                    self._json(400, {"error": "from/to must be commit ids"})
                    return
                versions = app.versions(row)
                by_sha = {v["sha"]: v for v in versions}
                try:
                    data = app.compare(row, frm, to)
                except KeyError:
                    self._json(404, {"error": "version not found"})
                    return
                record = by_sha.get(to) or {}
                from_record = by_sha.get(frm) if frm else None
                data["html"] = {
                    "head": tm_head(from_record, record) if record else "",
                    "intel": intel_card(data["analysis"], record.get("unplanned"), record.get("changed_by") or record.get("author"), record.get("ts")),
                    "unified": render_diff(data["diff"], "unified", show_files=False) if frm else "",
                    "split": render_diff(data["diff"], "split", show_files=False) if frm else "",
                }
                data["download"] = f"/api/devices/{quote(name, safe='')}/config?rev={to}&download=1"
                self._json(200, data)
            elif action == "trends":
                window = arg.get("range") if arg.get("range") in RANGES else "24h"
                series = app.trends(name, window)
                thresholds = app.base_view("device")["thresholds"]
                self._json(200, {"range": window, "series": series, "html": trend_charts(series, thresholds, row["health"].get("forecast") or {})})
            else:
                self._json(404, {"error": f"unknown device resource {action!r}"})

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path.rstrip("/")
            if not path.startswith("/api/run/"):
                self._send(404, b"not found\n", "text/plain")
                return
            if not app.can_trigger:
                self._json(403, {"error": "remote triggering is disabled; set server.api_token or server.username/password"})
                return
            method = self._require_auth()
            if method is None:
                return
            if method in ("basic", "open") and self.headers.get("X-NetLedger-Request") != "1":
                self._json(403, {"error": "missing X-NetLedger-Request header"})
                return
            job = path.rsplit("/", 1)[-1]
            if job not in ("backup", "health"):
                self._json(404, {"error": f"unknown job {job!r}"})
                return
            try:
                started = app.scheduler.trigger(job)
            except KeyError:
                self._json(404, {"error": f"job {job!r} is not scheduled"})
                return
            self._json(202 if started else 409, {"job": job, "started": started})

    return Handler


class DashboardServer:
    def __init__(self, app: App, host: str, port: int):
        self.app = app
        self.httpd = ThreadingHTTPServer((host, port), _handler_for(app))
        self.httpd.daemon_threads = True
        self.thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        return int(self.httpd.server_address[1])

    def start(self) -> None:
        self.thread = threading.Thread(target=self.httpd.serve_forever, name="netledger-http", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.app.close()
