from __future__ import annotations

import base64
import json
import re
import urllib.error
import urllib.request
from typing import Any

import pytest

from netledger.backup import BackupRunner
from netledger.drivers.simulated import SimulatedDriver
from netledger.health import HealthRunner
from netledger.inventory import load_inventory
from netledger.metrics import render_metrics
from netledger.scheduler import IntervalSchedule, Scheduler
from netledger.server import App, DashboardServer, JobTracker
from netledger.state import StateStore

from .conftest import needs_git, simulated


def fetch(url: str, method: str = "GET", headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], str]:
    request = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=20) as resp:
            return resp.status, dict(resp.headers), resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read().decode()


@pytest.fixture
def running(make_env):  # noqa: ANN001, ANN201
    def start(changes: bool = False, **server: Any) -> tuple[str, App, list[str]]:
        devices = [
            simulated("core<script>1", "ios"),
            simulated("fw1", "fortios", cpu=93),
            simulated("down1", "eos", unreachable=True),
            simulated("sw9", "ios", change=True, changed_by="jsmith", neighbors={"Twe1/0/1": ["fw1", "port2"]}),
        ]
        settings = make_env(devices, server=server, health={"unreachable_after": 1})
        state = StateStore(settings.data_path / "state.json")
        inventory = load_inventory(settings)
        BackupRunner(settings, state).run(inventory, inventory=inventory)
        if changes:
            SimulatedDriver.revision = 2
            BackupRunner(settings, state).run(inventory, inventory=inventory)
        HealthRunner(settings, state).run(inventory)
        triggered: list[str] = []
        scheduler = Scheduler()
        scheduler.add("backup", IntervalSchedule(3600), lambda: triggered.append("backup"))
        scheduler.add("health", IntervalSchedule(3600), lambda: triggered.append("health"))
        app = App(settings, state, scheduler, inventory_loader=lambda: [d.summary() for d in load_inventory(settings)])
        app.ready = True
        server_obj = DashboardServer(app, "127.0.0.1", 0)
        server_obj.start()
        servers.append(server_obj)
        return f"http://127.0.0.1:{server_obj.port}", app, triggered

    servers: list[DashboardServer] = []
    yield start
    for server_obj in servers:
        server_obj.stop()


@needs_git
def test_pages_assets_probes_and_metrics(running) -> None:  # noqa: ANN001
    base, _, _ = running()
    assert fetch(base + "/healthz")[0] == 200 and fetch(base + "/readyz")[0] == 200
    status, headers, page = fetch(base + "/")
    csp = headers["Content-Security-Policy"]
    assert status == 200 and "script-src 'self'" in csp and "unsafe-inline" not in csp.split("script-src")[1].split(";")[0]
    assert "core&lt;script&gt;1" in page and "<script>1" not in page  # device names are escaped
    assert re.search(r"<script(?![^>]*(?:src=|application/json))", page) is None  # no inline scripts
    assert "Network map" in page and "Change ledger" in page and "Needs attention" in page
    assert 'data-theme="light"' in page  # day mode is the default

    css = re.search(r'href="(/static/app\.[0-9a-f]+\.css)"', page).group(1)
    js = re.search(r'src="(/static/app\.[0-9a-f]+\.js)"', page).group(1)
    status, headers, body = fetch(base + css)
    assert status == 200 and headers["Content-Type"].startswith("text/css") and "immutable" in headers["Cache-Control"] and ":root" in body
    status, headers, body = fetch(base + js)
    assert status == 200 and headers["Content-Type"].startswith("text/javascript") and "use strict" in body
    assert fetch(base + "/static/app.0000000000.js")[0] == 404
    assert fetch(base + "/static/../server.py")[0] == 404

    for path in ("/topology", "/changes", "/wall", "/search", "/search?q=10.10.99.0/24", "/devices/fw1", "/?site=nowhere"):
        assert fetch(base + path)[0] == 200, path
    status, _, detail = fetch(base + "/devices/fw1")
    assert "CPU 9" in detail and "Configuration time machine" in detail and "faceplate" in detail
    assert fetch(base + "/devices/nope")[0] == 404
    status, headers, metrics = fetch(base + "/metrics")
    assert status == 200 and headers["Content-Type"].startswith("text/plain; version=0.0.4")
    assert 'netledger_backup_success{device="fw1",site="",platform="fortios"} 1' in metrics
    assert 'netledger_device_up{device="down1",site="",platform="eos"} 0' in metrics
    devices = json.loads(fetch(base + "/api/devices")[2])
    assert {d["name"] for d in devices} == {"core<script>1", "fw1", "down1", "sw9"}
    palette = json.loads(fetch(base + "/api/palette")[2])
    assert {d["name"]: d["status"] for d in palette}["down1"] == "critical"


@needs_git
def test_theme_default_cookie_and_setting(running) -> None:  # noqa: ANN001
    base, app, _ = running()
    assert 'data-theme="light"' in fetch(base + "/")[2]
    assert 'data-theme="dark"' in fetch(base + "/", headers={"Cookie": "a=b; nl_theme=dark"})[2]
    assert 'data-theme="auto"' in fetch(base + "/?theme=auto")[2]
    app.settings.server.theme = "dark"
    assert 'data-theme="dark"' in fetch(base + "/changes")[2]


@needs_git
def test_time_machine_change_ledger_and_topology(running) -> None:  # noqa: ANN001
    base, app, _ = running(changes=True)
    versions = json.loads(fetch(base + "/api/devices/sw9/versions")[2])
    assert len(versions) == 2 and versions[0]["risk"] == "high" and versions[0]["changed_by"] == "jsmith"
    assert versions[1]["summary"] == "initial backup"
    newest, oldest = versions[0]["sha"], versions[1]["sha"]

    status, _, body = fetch(base + f"/api/devices/sw9/diff?from={oldest}&to={newest}")
    diff = json.loads(body)
    assert status == 200 and diff["analysis"]["risk"] == "high"
    assert "Added ACL GUEST-ISOLATION" in diff["analysis"]["highlights"]
    assert "+vlan 40" in diff["diff"] and "GUEST-WIFI" in diff["html"]["unified"] and 'class="diff split"' in diff["html"]["split"]
    assert "Change intelligence" in diff["html"]["intel"]
    assert fetch(base + "/api/devices/sw9/diff?to=nothex")[0] == 400
    assert fetch(base + "/api/devices/sw9/diff?to=" + "0" * 40)[0] == 404

    status, _, body = fetch(base + f"/api/devices/sw9/config?rev={newest}&line=3")
    config = json.loads(body)
    assert status == 200 and "hostname sw9" in config["text"] and 'class="cl hit"' in config["html"]
    assert "$9$" not in config["text"] and "<removed>" in config["text"]  # secrets are always masked
    status, headers, text = fetch(base + f"/api/devices/sw9/config?rev={newest}&download=1")
    assert status == 200 and "attachment" in headers["Content-Disposition"] and "hostname sw9" in text

    status, _, page = fetch(base + f"/devices/sw9?to={newest[:8]}")
    assert status == 200 and "Change intelligence" in page and "Added VLAN 40 (GUEST-WIFI)" in page
    ledger = json.loads(fetch(base + "/api/changes?device=sw9")[2])
    assert len(ledger) == 1 and ledger[0]["risk"] == "high" and ledger[0]["commit"] == newest
    assert "Added interface Vlan40" in fetch(base + "/changes")[2]

    trends = json.loads(fetch(base + "/api/devices/fw1/trends?range=7d")[2])
    assert trends["range"] == "7d" and "data-chart" in trends["html"]
    topology = json.loads(fetch(base + "/api/topology")[2])
    assert {(link["source"], link["target"]) for link in topology["links"]} == {("sw9", "fw1")}
    assert topology["lldp"] is True


@needs_git
def test_where_is_search(running) -> None:  # noqa: ANN001
    base, _, _ = running(changes=True)
    result = json.loads(fetch(base + "/api/search?q=10.10.40.57")[2])
    assert result["mode"] == "ip" and result["best"][0]["device"] == "sw9" and result["best"][0]["network"] == "10.10.40.0/24"
    assert fetch(base + "/api/search?q=" + "%2F(a%2B)%2B%2F")[0] == 400  # nested quantifiers are refused
    status, _, page = fetch(base + "/search?q=10.10.40.57")
    assert status == 200 and "lives in" in page and "10.10.40.0/24" in page
    text = json.loads(fetch(base + "/api/search?q=snmp-server%20community")[2])
    assert text["mode"] == "text" and text["total"] >= 1


@needs_git
def test_live_updates(running) -> None:  # noqa: ANN001
    base, app, _ = running()
    first = json.loads(fetch(base + "/api/live?cursor=0")[2])
    assert first["rev"] == app.state.revision and isinstance(first["activity"], list)
    app.state.update("fw1", "health", {"status": "critical"})
    app.tracker.start("backup", 4)
    app.tracker.advance("backup", "fw1")
    later = json.loads(fetch(base + f"/api/live?cursor={first['cursor']}")[2])
    assert later["rev"] > first["rev"] and later["progress"]["backup"]["done"] == 1


def test_job_tracker_wrap() -> None:
    tracker = JobTracker()
    seen: list[dict[str, Any]] = []

    class Result:
        def __init__(self, name: str) -> None:
            self.device = type("D", (), {"name": name})()
            self.status = "ok"

    def job(progress):  # noqa: ANN001, ANN202
        progress(Result("a"))
        seen.append(tracker.status()["backup"])
        return "done"

    assert tracker.wrap("backup", job, total=lambda: 3)() == "done"
    assert seen[0]["done"] == 1 and seen[0]["total"] == 3 and seen[0]["current"] == "a"
    assert tracker.status() == {}


@needs_git
def test_auth_and_triggers(running) -> None:  # noqa: ANN001
    base, _, triggered = running(username="admin", password="pw", api_token="tok")
    assert fetch(base + "/")[0] == 401
    assert fetch(base + "/api/live")[0] == 401
    assert fetch(base + "/healthz")[0] == 200 and fetch(base + "/metrics")[0] == 200
    assert fetch(base + "/static/app.css")[0] == 200  # assets carry no data
    basic = {"Authorization": "Basic " + base64.b64encode(b"admin:pw").decode()}
    assert fetch(base + "/", headers=basic)[0] == 200
    assert fetch(base + "/", headers={"Authorization": "Basic " + base64.b64encode(b"admin:no").decode()})[0] == 401
    assert fetch(base + "/api/run/backup", "POST", basic)[0] == 403  # browser session without CSRF header
    assert fetch(base + "/api/run/backup", "POST", {**basic, "X-NetLedger-Request": "1"})[0] == 202
    assert fetch(base + "/api/run/health", "POST", {"Authorization": "Bearer tok"})[0] == 202
    assert fetch(base + "/api/run/health", "POST", {"Authorization": "Bearer wrong"})[0] == 401
    assert fetch(base + "/api/run/reboot", "POST", {"Authorization": "Bearer tok"})[0] == 404


@needs_git
def test_triggers_disabled_without_auth(running) -> None:  # noqa: ANN001
    base, _, _ = running()
    assert fetch(base + "/api/run/backup", "POST", {"X-NetLedger-Request": "1"})[0] == 403


def test_metrics_label_escaping() -> None:
    snapshot = {"devices": {'we"ird\\name': {"info": {"site": "a\nb", "platform": "ios"}, "backup": {"status": "ok", "changes_total": 2}}}, "runs": {}}
    text = render_metrics(snapshot)
    assert 'netledger_backup_success{device="we\\"ird\\\\name",site="a\\nb",platform="ios"} 1' in text
    assert "# TYPE netledger_config_changes_total counter" in text
