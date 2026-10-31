"""``netledger demo``: a self-contained tour using simulated devices and a local Git repository.

The tour generates six weeks of believable history in a few seconds - earlier edits by several
engineers, overnight changes inside the maintenance window, a week of health samples with a memory
leak and a switch that keeps running hotter - then makes a live, unplanned change.
"""

from __future__ import annotations

import os
import time
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Iterator

import yaml
from rich import box
from rich.console import Console
from rich.table import Table

from netledger import backup as backup_module
from netledger.backup import BackupReport, BackupRunner
from netledger.config import Settings, load_settings
from netledger.drivers.simulated import _STARTED, SENSORS, SimulatedDriver, simulated_reading
from netledger.health import HealthReport, HealthRunner, worst
from netledger.history import MetricsHistory, Sample
from netledger.inventory import Device, load_inventory
from netledger.state import StateStore
from netledger.storage.gitcli import remove_tree

MARKER = "# NetLedger demo environment"

DEMO_CONFIG: dict[str, Any] = {
    "data_dir": "data",
    "inventory": ["inventory.yaml"],
    "credentials": {"default": {"username": "netledger", "password": "demo"}},
    "git": {
        "backend": "local",
        "author_name": "NetLedger",
        "author_email": "netledger@example.net",
        "path": "{site}/{name}",
    },
    "backup": {"workers": 8, "retrieve": ["running", "startup"], "commands": {"ios": ["show inventory"]}},
    "health": {"unreachable_after": 1, "thresholds": {"temperature": {"warning": 70, "critical": 85}}},
    "changes": {"windows": ["daily 01:00-04:00"]},
    "compliance": [
        {
            "name": "ssh-only-vty",
            "description": "VTY lines must only accept SSH",
            "platforms": ["ios"],
            "must_not_match": r"^\s*transport input .*telnet",
        },
        {
            "name": "ntp-configured",
            "description": "An NTP server must be configured",
            "platforms": ["ios", "eos"],
            "must_match": r"^ntp server ",
        },
        {
            "name": "no-default-snmp",
            "description": "SNMP must not use the public/private communities",
            "must_not_match": r"^snmp-server community (?:public|private)\b",
            "severity": "critical",
        },
    ],
    "schedule": {"backup": "every 10m", "health": "every 1m", "run_on_start": False},
    "server": {"port": 8080, "allow_anonymous_triggers": True, "title": "NetLedger"},
}


def _links(*pairs: tuple[str, str, str]) -> dict[str, list[str]]:
    return {local: [remote, remote_port] for local, remote, remote_port in pairs}


DEMO_INVENTORY: dict[str, Any] = {
    "defaults": {"driver": "simulated", "credentials": "default"},
    "groups": {
        "core": {"role": "core", "tags": ["critical"]},
        "firewalls": {"role": "firewall", "tags": ["security"]},
        "datacenter": {"site": "dc1"},
        "branches": {"tags": ["branch"]},
    },
    "devices": [
        {"name": "hq-core-sw01", "host": "10.10.99.11", "platform": "ios", "site": "hq", "groups": ["core"],
         "optional_args": {"change": True, "unsaved": True, "changed_by": "jsmith", "neighbors": _links(
             ("Twe1/0/1", "hq-core-sw02", "Twe1/0/1"), ("Twe1/0/2", "hq-core-sw02", "Twe1/0/2"),
             ("Twe1/0/3", "hq-fw01", "port2"), ("Twe1/0/4", "esx-hq-01.corp.example.net", "vmnic0"),
             ("Twe1/0/5", "hq-wlc01", "Te0/0/0"))}},
        {"name": "hq-core-sw02", "host": "10.10.99.12", "platform": "ios", "site": "hq", "groups": ["core"],
         "optional_args": {"legacy_vty": True, "neighbors": _links(
             ("Twe1/0/1", "hq-core-sw01", "Twe1/0/1"), ("Twe1/0/2", "hq-core-sw01", "Twe1/0/2"),
             ("Twe1/0/3", "hq-fw02", "port2"), ("Twe1/0/4", "esx-hq-02.corp.example.net", "vmnic0"))}},
        {"name": "hq-fw01", "host": "10.10.99.1", "platform": "fortios", "site": "hq", "groups": ["firewalls"],
         "optional_args": {"change": True, "neighbors": _links(("port2", "hq-core-sw01", "Twe1/0/3"), ("ha", "hq-fw02", "ha"))}},
        {"name": "hq-fw02", "host": "10.10.99.2", "platform": "fortios", "site": "hq", "groups": ["firewalls"],
         "optional_args": {"cpu": 84, "neighbors": _links(("port2", "hq-core-sw02", "Twe1/0/3"), ("ha", "hq-fw01", "ha"))}},
        {"name": "dc1-spine01", "host": "10.20.99.21", "platform": "junos", "groups": ["datacenter", "core"],
         "optional_args": {"change": True, "changed_by": "mlopez", "neighbors": _links(
             ("et-0/0/48", "dc1-leaf01", "Ethernet49/1"), ("et-0/0/49", "dc1-leaf02", "Ethernet49/1"),
             ("xe-0/0/1", "dc1-edge-fw01", "ethernet1/2"))}},
        {"name": "dc1-leaf01", "host": "10.20.99.31", "platform": "eos", "role": "leaf", "groups": ["datacenter"],
         "optional_args": {"change": True, "neighbors": _links(
             ("Ethernet49/1", "dc1-spine01", "et-0/0/48"), ("Ethernet1", "esxi-dc1-01", "vmnic0"), ("Ethernet3", "esxi-dc1-03", "vmnic0"))}},
        {"name": "dc1-leaf02", "host": "10.20.99.32", "platform": "eos", "role": "leaf", "groups": ["datacenter"],
         "optional_args": {"temperature": 63, "temperature_drift": 1.1, "neighbors": _links(
             ("Ethernet49/1", "dc1-spine01", "et-0/0/49"), ("Ethernet5", "esxi-dc1-05", "vmnic1"))}},
        {"name": "dc1-edge-fw01", "host": "10.20.99.5", "platform": "panos", "groups": ["datacenter", "firewalls"],
         "optional_args": {"change": True, "neighbors": _links(
             ("ethernet1/2", "dc1-spine01", "xe-0/0/1"), ("ethernet1/3", "dc1-ext-asa01", "GigabitEthernet1/2"))}},
        {"name": "dc1-ext-asa01", "host": "10.20.99.6", "platform": "asa", "groups": ["datacenter", "firewalls"],
         "optional_args": {"memory": 89, "memory_leak": 2.0, "neighbors": _links(("GigabitEthernet1/2", "dc1-edge-fw01", "ethernet1/3"))}},
        {"name": "nyc-rtr01", "host": "10.30.99.1", "platform": "routeros", "site": "nyc", "role": "router",
         "groups": ["branches"], "optional_args": {"change": True, "neighbors": _links(("sfp-sfpplus2", "nyc-sw01", "1/1/49"))}},
        {"name": "nyc-sw01", "host": "10.30.99.10", "platform": "aoscx", "site": "nyc", "role": "access",
         "groups": ["branches"], "optional_args": {"fan_failed": True, "neighbors": _links(
             ("1/1/49", "nyc-rtr01", "sfp-sfpplus2"), ("1/1/1", "nyc-ap01", "eth0"))}},
        {"name": "lon-sw01", "host": "10.40.99.10", "platform": "procurve", "site": "lon", "role": "access",
         "groups": ["branches"], "optional_args": {"neighbors": _links(("25", "lon-fw01", "internal1"), ("3", "lon-ap01", "eth0"))}},
        {"name": "lon-fw01", "host": "10.40.99.1", "platform": "fortios", "site": "lon", "groups": ["branches", "firewalls"],
         "optional_args": {"outage_minutes": 200, "model": "FortiGate-60F", "neighbors": _links(("internal1", "lon-sw01", "25"))}},
    ],
}

# Earlier edits per template (see drivers/simulated.py) and when the fleet backups found them.
EDITS = {"ios": 4, "fortios": 3, "junos": 3, "eos": 2, "panos": 2, "routeros": 2}
EPOCH_DAYS = (41, 34, 26, 17, 9)
# Changes made overnight, inside the "daily 01:00-04:00" change window: (device, nights ago, hh, mm)
OVERNIGHT = (("dc1-leaf01", 3, 3, 5), ("nyc-rtr01", 1, 1, 40), ("dc1-edge-fw01", 0, 2, 20))
FAN_FAILED_HOURS = 5


@contextmanager
def simulated_time(ts: float) -> Iterator[None]:
    """Pretend it is ``ts``: run timestamps, commit dates and the simulated devices' clock (which keeps ticking)."""
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts))
    saved_env = {key: os.environ.get(key) for key in ("GIT_AUTHOR_DATE", "GIT_COMMITTER_DATE")}
    saved_now, saved_clock = backup_module.now, SimulatedDriver.clock
    started = time.time()
    os.environ["GIT_AUTHOR_DATE"] = os.environ["GIT_COMMITTER_DATE"] = stamp
    backup_module.now = lambda: ts + (time.time() - started)  # type: ignore[assignment]
    SimulatedDriver.clock = staticmethod(lambda: ts + (time.time() - started))  # type: ignore[assignment]
    try:
        yield
    finally:
        backup_module.now = saved_now  # type: ignore[assignment]
        SimulatedDriver.clock = saved_clock  # type: ignore[assignment]
        for key, value in saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def prepare(directory: Path, port: int | None = None) -> Settings:
    """Create (or reset) a demo environment in ``directory`` and load its settings."""
    directory = directory.resolve()
    config_path = directory / "netledger.yaml"
    if directory.exists() and any(directory.iterdir()):
        if not (config_path.exists() and config_path.read_text(encoding="utf-8").startswith(MARKER)):
            raise SystemExit(f"{directory} is not empty and is not a NetLedger demo directory; choose another --dir")
        remove_tree(directory / "data")
    directory.mkdir(parents=True, exist_ok=True)
    config = dict(DEMO_CONFIG)
    if port:
        config["server"] = {**config["server"], "port": port}
    header = f"{MARKER} - simulated devices, local Git repository. Safe to delete.\n"
    config_path.write_text(header + yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    (directory / "inventory.yaml").write_text(
        f"{MARKER}\n" + yaml.safe_dump(DEMO_INVENTORY, sort_keys=False, width=120), encoding="utf-8"
    )
    return load_settings(config_path)


def backup(settings: Settings, state: StateStore, revision: int, names: list[str] | None = None) -> BackupReport:
    SimulatedDriver.revision = revision
    inventory = load_inventory(settings)
    devices = [d for d in inventory if names is None or d.name in names]
    return BackupRunner(settings, state).run(devices, inventory=inventory)


def health(settings: Settings, state: StateStore, history: MetricsHistory | None = None) -> HealthReport:
    return HealthRunner(settings, state, history=history).run(load_inventory(settings))


def _overnight(now: float, nights: int, hour: int, minute: int) -> float:
    moment = datetime.fromtimestamp(now).replace(hour=hour, minute=minute, second=0, microsecond=0) - timedelta(days=nights)
    while moment.timestamp() > now - 3600 - nights * 86400:
        moment -= timedelta(days=1)
    return moment.timestamp()


def build_history(settings: Settings, state: StateStore, end: float | None = None, report: Callable[[str], None] | None = None) -> None:
    """Six weeks of backdated backups (earlier edits, overnight changes) ending with a quiet backup at ``end``."""
    end = end or time.time()
    say = report or (lambda _text: None)
    devices = load_inventory(settings)
    changing = [d for d in devices if d.optional_args.get("change")]
    scale, revision = SimulatedDriver.latency_scale, SimulatedDriver.revision
    SimulatedDriver.latency_scale = 0
    try:
        with simulated_time(end - EPOCH_DAYS[0] * 86400 + 3600 * 3):
            SimulatedDriver.epoch = 0
            backup(settings, state, revision=1)
        say(f"{len(devices)} devices backed up for the first time, {EPOCH_DAYS[0]} days ago")
        edits = 0
        for epoch in range(1, len(EPOCH_DAYS)):
            SimulatedDriver.epoch = epoch
            for index, device in enumerate(changing):
                if EDITS.get(device.platform, 0) >= epoch:
                    jitter = ((index * 7 + epoch * 5) % 19) * 3600 + index * 611
                    with simulated_time(end - EPOCH_DAYS[epoch] * 86400 + jitter):
                        backup(settings, state, revision=1, names=[device.name])
                    edits += 1
        SimulatedDriver.epoch = 99
        say(f"{edits} earlier changes by five engineers over the following weeks")
        for name, nights, hour, minute in OVERNIGHT:
            moment = _overnight(end, nights, hour, minute)
            with simulated_time(moment - 15 * 60):
                backup(settings, state, revision=1, names=[name])
            SimulatedDriver.revisions[name] = 2
            with simulated_time(moment):
                backup(settings, state, revision=1, names=[name])
        say(f"{len(OVERNIGHT)} changes made overnight, inside the 01:00-04:00 change window")
        with simulated_time(end):
            backup(settings, state, revision=1)
    finally:
        SimulatedDriver.latency_scale, SimulatedDriver.revision = scale, revision


def _sample_status(device: Device, reading: dict[str, float], ts: float, settings: Settings) -> str:
    args = device.optional_args
    outage = args.get("outage_minutes")
    if args.get("unreachable") or (outage is not None and ts >= _STARTED - float(outage) * 60):
        return "critical"
    limits = settings.health.thresholds
    sensors = SENSORS.get(device.platform, SENSORS["ios"])["temp"]
    hottest = reading["temperature"] + 4.5 * (len(sensors) - 1)

    def grade(value: float, warning: float | None, critical: float | None) -> str:
        if critical is not None and value >= critical:
            return "critical"
        return "warning" if warning is not None and value >= warning else "ok"

    statuses = [
        grade(reading["cpu"], limits.cpu.warning, limits.cpu.critical),
        grade(reading["memory"], limits.memory.warning, limits.memory.critical),
        grade(hottest, limits.temperature.warning, limits.temperature.critical),
    ]
    if args.get("fan_failed") and ts >= _STARTED - FAN_FAILED_HOURS * 3600:
        statuses.append("warning")
    return worst(*statuses)


def backfill_health(settings: Settings, history: MetricsHistory, days: int = 7, step: int = 900) -> dict[str, float]:
    """A week of health samples computed from the simulation (the live checks continue from here).

    Returns when each device's current status began, for :func:`settle_health`.
    """
    devices = load_inventory(settings)
    until = time.time() - 60
    samples: list[Sample] = []
    since: dict[str, float] = {}
    for device in devices:
        last_status = None
        for ts in range(int(until - days * 86400), int(until), step):
            reading = simulated_reading(device.name, device.optional_args, ts)
            status = _sample_status(device, reading, ts, settings)
            down = status == "critical" and (device.optional_args.get("outage_minutes") is not None)
            sensors = SENSORS.get(device.platform, SENSORS["ios"])["temp"]
            samples.append(Sample(
                device.name, ts, status,
                None if down else reading["cpu"], None if down else reading["memory"],
                None if down else round(reading["temperature"] + 4.5 * (len(sensors) - 1), 1),
                None if down else round(0.3 + (hash(device.name) % 90) / 100, 3),
            ))
            if status != last_status:
                since[device.name] = ts
                last_status = status
    history.record(samples)
    return since


def settle_health(state: StateStore, since: dict[str, float]) -> None:
    """After the first live check: statuses began when the history says they did, not just now."""
    now = time.time()
    for name, ts in since.items():
        current = state.section(name, "health")
        if current:
            values: dict[str, Any] = {"status_since": ts}
            if current.get("status") == "critical" and not current.get("reachable"):
                values["consecutive_failures"] = max(int(current.get("consecutive_failures") or 0), int((now - ts) / 300))
            state.update(name, "health", values)
    state.save()


def git_log_table(settings: Settings, limit: int = 12) -> Table:
    from netledger.storage.gitcli import GitCLIStore

    store = GitCLIStore(settings.git, settings.data_path / "repo")
    table = Table(box=box.SIMPLE_HEAVY, header_style="bold", pad_edge=False)
    table.add_column("Commit", style="yellow")
    table.add_column("Author")
    table.add_column("Message")
    for entry in store.log(limit=limit):
        table.add_row(entry["sha"][:8], entry["author"], entry["subject"])
    return table


def run(directory: Path, console: Console, port: int | None = None, serve: bool = True, host: str = "127.0.0.1") -> int:
    from netledger import console as out

    settings = prepare(directory, port)
    state = StateStore(settings.data_path / "state.json")
    history = MetricsHistory.for_settings(settings)
    thresholds = settings.health.thresholds
    cpu = (thresholds.cpu.warning, thresholds.cpu.critical)
    memory = (thresholds.memory.warning, thresholds.memory.critical)

    console.rule("[bold]1. Six weeks of history for a simulated 13-device network")
    build_history(settings, state, end=time.time() - 12 * 60, report=lambda text: console.print(f"  [green]✔[/] {text}"))
    console.print()
    console.rule("[bold]2. An engineer makes changes outside the change window... backup")
    out.print_backup_report(console, backup(settings, state, revision=2), show_diff=False)
    console.print()
    console.rule("[bold]3. Health check (plus a week of history: trends, forecasts)")
    since = backfill_health(settings, history) if history is not None else {}
    report = health(settings, state, history)
    settle_health(state, since)
    out.print_health_report(console, report, cpu, memory)
    console.print()
    console.rule("[bold]4. Git history")
    console.print(git_log_table(settings))
    console.print(f"Repository: [bold]{settings.data_path / 'repo'}[/]  (try: git -C \"{settings.data_path / 'repo'}\" log -p)")
    if not serve:
        if history is not None:
            history.close()
        return 0

    from netledger.scheduler import Scheduler, parse_schedule
    from netledger.server import App, DashboardServer, JobTracker

    tracker = JobTracker()
    scheduler = Scheduler()
    scheduler.add("backup", parse_schedule("every 10m"), tracker.wrap("backup", lambda progress: BackupRunner(settings, state).run(
        load_inventory(settings), inventory=load_inventory(settings), progress=progress)))
    scheduler.add("health", parse_schedule("every 1m"), tracker.wrap("health", lambda progress: HealthRunner(settings, state, history=history).run(
        load_inventory(settings), progress=progress)))
    app = App(settings, state, scheduler, inventory_loader=lambda: [d.summary() for d in load_inventory(settings)], history=history, tracker=tracker)
    server = DashboardServer(app, host, settings.server.port)
    server.start()
    app.ready = True
    console.print()
    shown = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    console.print(f"[bold green]Dashboard:[/] http://{shown}:{server.port}/   (Ctrl+C to stop)")
    try:
        scheduler.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        scheduler.stop()
        server.stop()
        if history is not None:
            history.close()
    return 0
