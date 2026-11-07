"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import logging
import re
import shutil
import signal
import sys
import time
from importlib import resources
from pathlib import Path
from typing import Any, Callable

from rich import box
from rich.table import Table

from netledger import __version__
from netledger.config import ConfigError, Settings, load_settings
from netledger.console import inventory_table, make_console, print_backup_report, print_health_report
from netledger.inventory import Device, DeviceFilter, load_inventory, validate_inventory
from netledger.logs import setup_logging
from netledger.platforms import all_platforms

console = make_console()
err = make_console(stderr=True)
log = logging.getLogger("netledger")


# --------------------------------------------------------------------------- helpers


def _settings(args: argparse.Namespace) -> Settings:
    settings = load_settings(args.config)
    setup_logging(
        args.log_level or settings.logging.level,
        args.log_format or settings.logging.format,
        args.log_file or settings.logging.file,
    )
    return settings


def _devices(args: argparse.Namespace, settings: Settings) -> tuple[list[Device], list[Device]]:
    inventory = load_inventory(settings)
    selected = DeviceFilter(
        names=args.device, sites=args.site, groups=args.group, tags=args.tag, platforms=args.platform
    ).apply(inventory)
    return inventory, selected


def _thresholds(settings: Settings) -> tuple[tuple[Any, Any], tuple[Any, Any]]:
    t = settings.health.thresholds
    return (t.cpu.warning, t.cpu.critical), (t.memory.warning, t.memory.critical)


def _state(settings: Settings):  # noqa: ANN202
    from netledger.state import StateStore

    return StateStore(settings.data_path / "state.json")


def _progress(total: int, label: str) -> tuple[Any, Callable[[Any], None]]:
    """Rich progress bar when interactive, otherwise a no-op."""
    if not console.is_terminal or total == 0:
        return None, lambda _result: None
    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
    )

    progress = Progress(SpinnerColumn(), TextColumn(label), BarColumn(), MofNCompleteColumn(), TimeElapsedColumn(), console=console, transient=True)
    task = progress.add_task(label, total=total)
    return progress, lambda _result: progress.advance(task)


# --------------------------------------------------------------------------- commands


def cmd_init(args: argparse.Namespace) -> int:
    target = Path(args.directory).resolve()
    target.mkdir(parents=True, exist_ok=True)
    templates = resources.files("netledger") / "templates"
    for out_name, template in (("netledger.yaml", "netledger.yaml"), ("inventory.yaml", "inventory.yaml"), ("netledger.env", "netledger.env")):
        destination = target / out_name
        if destination.exists() and not args.force:
            console.print(f"  [yellow]skip[/]   {destination} (already exists)")
            continue
        destination.write_text((templates / template).read_text(encoding="utf-8"), encoding="utf-8")
        console.print(f"  [green]create[/] {destination}")
    console.print(
        "\nNext steps:\n"
        "  1. Put credentials and your Git token in [bold]netledger.env[/] (never commit it)\n"
        "  2. Point [bold]git.url[/] in netledger.yaml at your backup repository\n"
        "  3. List your devices in [bold]inventory.yaml[/]\n"
        "  4. [bold]netledger validate[/] → [bold]netledger test -d <device>[/] → [bold]netledger backup[/]\n"
    )
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    from netledger.scheduler import ScheduleError, load_timezone, parse_schedule
    from netledger.storage import create_store

    settings = _settings(args)
    devices = load_inventory(settings)
    problems = validate_inventory(devices, settings)
    try:
        tz = load_timezone(settings.schedule.timezone)
        for job in ("backup", "health"):
            expression = getattr(settings.schedule, job)
            if expression:
                parse_schedule(expression, tz)
    except ScheduleError as exc:
        problems.append(f"schedule: {exc}")
    if settings.git.backend in ("git", "local") and shutil.which("git") is None:
        problems.append("the 'git' executable was not found (install Git, or use git.backend: github)")

    table = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
    table.add_column(style="bold")
    table.add_column()
    platforms = sorted({d.platform for d in devices})
    table.add_row("Configuration", str(settings.config_path))
    table.add_row("Data directory", str(settings.data_path))
    table.add_row("Inventory", f"{len(devices)} devices · {len({d.site for d in devices if d.site})} sites · platforms: {', '.join(platforms) or '-'}")
    table.add_row("Repository", f"{create_store(settings).describe()} ({settings.git.backend}, {settings.git.commit_mode} commits)")
    table.add_row("Secrets in configs", settings.normalize.secrets)
    table.add_row("Schedules", f"backup '{settings.schedule.backup}' · health '{settings.schedule.health}'")
    table.add_row("Notifications", ", ".join(n.label for n in settings.notifications) or "none")
    table.add_row("Compliance rules", str(len(settings.compliance)))
    console.print(table)
    if problems:
        for problem in problems:
            console.print(f"[red]✖[/] {problem}")
        return 2
    console.print("[bold green]✔ Configuration is valid[/]")
    return 0


def cmd_inventory(args: argparse.Namespace) -> int:
    settings = _settings(args)
    _, devices = _devices(args, settings)
    if args.format == "json":
        print(json.dumps([d.summary() for d in devices], indent=2))
    elif args.format == "yaml":
        import yaml

        print(yaml.safe_dump([d.summary() for d in devices], sort_keys=False), end="")
    else:
        console.print(inventory_table(devices))
        console.print(f"{len(devices)} device(s)")
    return 0


def cmd_platforms(args: argparse.Namespace) -> int:
    table = Table(box=box.SIMPLE_HEAVY, header_style="bold", pad_edge=False)
    for column in ("Platform", "Name", "Driver", "Health data", "Aliases"):
        table.add_column(column, style="bold" if column == "Platform" else "")
    for platform in all_platforms():
        driver = platform.driver.replace("netledger.drivers.", "built-in ").split(":")[0] if platform.builtin else platform.driver
        health = {"full": "[green]cpu · memory · temp · fans · psu[/]", "partial": "[yellow]partial[/]", "none": "[grey62]reachability only[/]"}.get(platform.health, platform.health)
        table.add_row(platform.key, platform.name, driver, health, ", ".join(platform.aliases[:4]))
    console.print(table)
    console.print("Any other NAPALM driver works too: set [bold]driver: <napalm-driver>[/] on the device.")
    return 0


def cmd_test(args: argparse.Namespace) -> int:
    from netledger.connection import device_session
    from netledger.health import HealthCollected, evaluate
    from netledger.utils import format_duration

    settings = _settings(args)
    _, devices = _devices(args, settings)
    if not devices:
        err.print("[red]No devices matched.[/] Use -d NAME (globs allowed).")
        return 2
    failures = 0
    for device in devices:
        started = time.monotonic()
        try:
            with console.status(f"Connecting to {device.name} ({device.host})..."), device_session(device, settings, retries=0) as driver:
                facts = driver.get_facts()
                config = driver.get_config(retrieve="running")["running"] if args.show_config else None
                env = None
                if args.health:
                    try:
                        env = driver.get_environment()
                    except NotImplementedError:
                        env = None
        except Exception as exc:  # noqa: BLE001
            failures += 1
            console.print(f"[bold red]✖ {device.name}[/] ({device.host}): {exc}")
            continue
        elapsed = time.monotonic() - started
        console.print(f"[bold green]✔ {device.name}[/] connected via {device.driver_spec} in {format_duration(elapsed)}")
        table = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
        table.add_column(style="bold")
        table.add_column()
        for key in ("hostname", "vendor", "model", "os_version", "serial_number"):
            table.add_row(key.replace("_", " "), str(facts.get(key) or "-"))
        uptime = facts.get("uptime")
        table.add_row("uptime", format_duration(uptime) if isinstance(uptime, (int, float)) and uptime >= 0 else "-")
        console.print(table)
        if config is not None:
            lines = config.splitlines()
            console.print(f"[bold]Running configuration:[/] {len(lines)} lines")
            for line in lines[: args.lines]:
                console.print("  " + line, markup=False, highlight=False)
        if env is not None:
            health = evaluate(device, HealthCollected(reachable=True, facts=facts, env=env, duration=elapsed), settings)
            for check in health.checks:
                console.print(f"  {check.name:<12} [{'green' if check.status == 'ok' else 'yellow' if check.status == 'warning' else 'red'}]{check.status}[/]  {check.message}")
    return 1 if failures else 0


def cmd_backup(args: argparse.Namespace) -> int:
    from netledger.backup import BackupRunner
    from netledger.notify import Dispatcher

    settings = _settings(args)
    inventory, devices = _devices(args, settings)
    if args.workers:
        settings.backup.workers = args.workers
    if not devices:
        err.print("[yellow]No devices matched the filters.[/]")
        return 2
    runner = BackupRunner(settings, _state(settings), None if args.no_notify or args.dry_run else Dispatcher(settings))
    progress, advance = _progress(len(devices), "Backing up")
    if progress:
        with progress:
            report = runner.run(devices, inventory=inventory, dry_run=args.dry_run, push=not args.no_push, progress=advance)
    else:
        report = runner.run(devices, inventory=inventory, dry_run=args.dry_run, push=not args.no_push)
    if args.json:
        print(json.dumps(_backup_json(report), indent=2, default=str))
    else:
        print_backup_report(console, report, show_diff=args.dry_run or args.diff)
    if report.error:
        return 2
    return 1 if report.failed else 0


def _backup_json(report: Any) -> dict[str, Any]:
    return {
        "started": report.started,
        "finished": report.finished,
        "store": report.store,
        "commits": report.commits,
        "pushed": report.pushed,
        "error": report.error,
        "devices": [
            {
                "name": r.device.name,
                "status": r.status,
                "error": r.error,
                "duration": round(r.duration, 2),
                "commit": r.commit,
                "changed": r.config_changed,
                "initial": r.initial,
                "unsaved_changes": r.unsaved,
                "warnings": r.warnings,
                "files": [{"path": c.path, "action": c.action, "added": c.added, "removed": c.removed} for c in r.changes],
                "compliance": [c.to_dict() for c in r.compliance],
            }
            for r in report.results
        ],
    }


def cmd_health(args: argparse.Namespace) -> int:
    from netledger.health import HealthRunner
    from netledger.notify import Dispatcher

    try:
        settings = _settings(args)
        _, devices = _devices(args, settings)
    except ConfigError as exc:
        err.print(f"[red]Configuration error:[/] {exc}")
        return 3
    if not devices:
        err.print("[yellow]No devices matched the filters.[/]")
        return 3
    runner = HealthRunner(settings, _state(settings), None if args.no_notify else Dispatcher(settings))
    progress, advance = _progress(len(devices), "Checking health")
    if progress:
        with progress:
            report = runner.run(devices, progress=advance, notify=not args.no_notify)
    else:
        report = runner.run(devices, notify=not args.no_notify)
    if args.json:
        payload = [
            {
                "name": r.device.name,
                "status": r.status,
                "reachable": r.reachable,
                "error": r.error,
                "cpu": r.cpu,
                "memory_percent": r.memory_pct,
                "temperatures": r.temperatures,
                "fans": r.fans,
                "power_supplies": r.psus,
                "uptime": r.uptime,
                "checks": [c.to_dict() for c in r.checks],
            }
            for r in report.results
        ]
        print(json.dumps({"status": report.status, "devices": payload}, indent=2))
    else:
        print_health_report(console, report, *_thresholds(settings))
    return report.exit_code


def cmd_run(args: argparse.Namespace) -> int:
    backup_code = cmd_backup(args)
    if backup_code == 2:
        return backup_code
    health_code = cmd_health(args)
    return max(backup_code, 1 if health_code in (1, 2) else 0)


def cmd_serve(args: argparse.Namespace) -> int:
    from netledger.backup import BackupRunner
    from netledger.health import HealthRunner
    from netledger.history import MetricsHistory
    from netledger.notify import Dispatcher
    from netledger.scheduler import Scheduler, load_timezone, parse_schedule
    from netledger.server import App, DashboardServer, JobTracker

    settings = _settings(args)
    state = _state(settings)
    dispatcher = Dispatcher(settings)
    tz = load_timezone(settings.schedule.timezone)
    scheduler = Scheduler()
    history = MetricsHistory.for_settings(settings)
    tracker = JobTracker()

    def backup_job(progress: Callable[[Any], None]) -> None:
        devices = load_inventory(settings)
        report = BackupRunner(settings, state, dispatcher).run(devices, inventory=devices, progress=progress)
        log.info(
            "backup run finished: %d ok, %d failed, %d changed, %d commit(s)%s",
            len(report.ok), len(report.failed), len([r for r in report.results if r.config_changed]), report.commits,
            f"; repository error: {report.error}" if report.error else f"; {report.publish_message}",
        )

    def health_job(progress: Callable[[Any], None]) -> None:
        report = HealthRunner(settings, state, dispatcher, history=history).run(load_inventory(settings), progress=progress)
        log.info("health run finished: %d ok, %d warning, %d critical, %d unknown",
                 report.count("ok"), report.count("warning"), report.count("critical"), report.count("unknown"))

    def count(kind: str) -> Callable[[], int]:
        return lambda: sum(1 for d in load_inventory(settings) if getattr(d, kind))

    if settings.backup.enabled and settings.schedule.backup:
        scheduler.add("backup", parse_schedule(settings.schedule.backup, tz), tracker.wrap("backup", backup_job, count("backup")),
                      run_now=settings.schedule.run_on_start)
    if settings.health.enabled and settings.schedule.health:
        scheduler.add("health", parse_schedule(settings.schedule.health, tz), tracker.wrap("health", health_job, count("health")),
                      run_now=settings.schedule.run_on_start)

    server = None
    app = App(settings, state, scheduler, inventory_loader=lambda: [d.summary() for d in load_inventory(settings)],
              history=history, tracker=tracker)
    if settings.server.enabled:
        host, port = args.host or settings.server.host, args.port or settings.server.port
        server = DashboardServer(app, host, port)
        server.start()
        log.info("dashboard and metrics on http://%s:%d/", host if host not in ("0.0.0.0", "::") else "localhost", server.port)
    app.ready = True

    def stop(*_args: Any) -> None:
        log.info("shutting down")
        scheduler.stop()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, stop)
        except (ValueError, OSError):
            pass
    log.info("NetLedger %s started: backup '%s', health '%s'", __version__, settings.schedule.backup, settings.schedule.health)
    try:
        scheduler.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        scheduler.stop()
        if server:
            server.stop()
        if history is not None:
            history.close()
    return 0


def cmd_notify_test(args: argparse.Namespace) -> int:
    from netledger.notify import Dispatcher

    settings = _settings(args)
    if not settings.notifications:
        console.print("No notifications configured.")
        return 2
    results = Dispatcher(settings).test()
    for name, outcome in results.items():
        console.print(f"{'[green]✔' if outcome == 'ok' else '[red]✖'}[/] {name}: {outcome}")
    return 0 if all(v == "ok" for v in results.values()) else 1


def cmd_search(args: argparse.Namespace) -> int:
    from netledger.search import Document, QueryError, as_network, parse_query, search

    settings = _settings(args)
    if settings.git.backend == "github":
        err.print("[red]search needs a local clone (git or local backend).[/]")
        return 2
    repo = settings.resolve_path(settings.git.workdir) if settings.git.workdir else settings.data_path / "repo"
    root = repo / settings.git.base_dir
    if not root.is_dir():
        err.print(f"[yellow]Nothing backed up yet in {root}.[/] Run 'netledger backup' first.")
        return 2
    ip_mode = args.ip or (not args.regex and as_network(args.pattern) is not None)
    if ip_mode:
        try:
            query = parse_query(args.pattern)
        except QueryError as exc:
            err.print(f"[red]{exc}[/]")
            return 2
        if query.mode != "ip":
            err.print(f"[red]{args.pattern!r} is not an IP address or network.[/]")
            return 2
        documents = []
        for path in sorted(root.rglob("running-config.*")):
            device = path.parent.name
            documents.append(Document(device, path.relative_to(repo).as_posix(), path.read_text(encoding="utf-8", errors="replace")))
        result = search(documents, query)
        for hits in result.hits:
            if args.files:
                console.print(hits.device)
                continue
            console.print(f"[bold]{hits.device}[/]  [grey62]{hits.path}[/]")
            for match in hits.matches:
                where = " › ".join(match.section)
                context = f"[grey62]{where} ›[/] " if where else ""
                console.print(
                    f"  [cyan]{match.line_no:>5}[/]  {context}{match.line.strip()}  [grey62]({match.kind} {match.network or ''}, {match.role})[/]",
                    highlight=False,
                )
        best = result.best()
        if best:
            hits, match = best[0]
            console.print(f"[green]→ {args.pattern} lives in {match.network} on {', '.join(sorted({h.device for h, _ in best}))}[/]")
        console.print(f"[grey62]{result.total} match(es) on {len(result.hits)} device(s)[/]")
        return 0 if result.total else 1
    pattern = re.compile(args.pattern, re.I if args.ignore_case else 0)
    matches = 0
    devices: set[str] = set()
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == "device.json":
            continue
        rel = path.relative_to(repo).as_posix()
        for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            if pattern.search(line):
                matches += 1
                devices.add(path.parent.name if path.parent.name != "commands" else path.parent.parent.name)
                if not args.files:
                    console.print(f"{rel}:{number}: {line.strip()}", markup=False, highlight=False)
    if args.files:
        for name in sorted(devices):
            console.print(name)
    console.print(f"[grey62]{matches} match(es) on {len(devices)} device(s)[/]")
    return 0 if matches else 1


def _stored_config(settings: Settings, device: Device) -> str | None:
    """The latest backed-up running configuration of a device, from the local clone or mirror."""
    from netledger.inventory import device_dir

    path = f"{device_dir(device, settings.git)}/running-config.{device.platform_info.extension}"
    if settings.git.backend == "github":
        mirror = settings.data_path / "mirror" / path
        if mirror.is_file():
            return mirror.read_text(encoding="utf-8", errors="replace")
        from netledger.storage.github import GitHubStore

        store = GitHubStore(settings.git)
        store.prepare()
        return store.read(path)
    repo = settings.resolve_path(settings.git.workdir) if settings.git.workdir else settings.data_path / "repo"
    target = repo / path
    return target.read_text(encoding="utf-8", errors="replace") if target.is_file() else None


def cmd_sanitize(args: argparse.Namespace) -> int:
    from netledger.platforms import get_platform, resolve_platform
    from netledger.sanitize import Sanitizer
    from netledger.storage import StoreError

    platform = None
    names: list[str] = []
    if args.device:
        if args.file not in (None, "-"):
            err.print("[red]Give either a file or --device, not both.[/]")
            return 2
        settings = _settings(args)
        device = next((d for d in load_inventory(settings) if d.name == args.device), None)
        if device is None:
            err.print(f"[red]No device named {args.device!r} in the inventory.[/]")
            return 2
        try:
            text = _stored_config(settings, device)
        except StoreError as exc:
            err.print(f"[red]Cannot read the stored configuration:[/] {exc}")
            return 2
        if text is None:
            err.print(f"[yellow]No stored configuration for {device.name} yet.[/] Run 'netledger backup -d {device.name}' first.")
            return 2
        platform = device.platform_info
        names = [device.name, device.host]
    elif args.file in (None, "-"):
        text = sys.stdin.read()
    else:
        try:
            text = Path(args.file).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            err.print(f"[red]Cannot read {args.file}:[/] {exc}")
            return 2
    if args.platform:
        key = resolve_platform(args.platform)
        if key is None:
            err.print(f"[red]Unknown platform {args.platform!r}.[/] 'netledger platforms' lists them.")
            return 2
        platform = get_platform(key)
    sanitizer = Sanitizer(platform, keep_private=args.keep_private, names=names)
    output = sanitizer.sanitize(text)
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(output)
    elif hasattr(sys.stdout, "buffer"):
        sys.stdout.flush()
        sys.stdout.buffer.write(output.encode("utf-8"))
        sys.stdout.buffer.flush()
    else:
        sys.stdout.write(output)
    err.print(f"[green]Sanitized:[/] {sanitizer.summary()}. Read it through before you share it.", highlight=False)
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    from netledger import demo

    setup_logging(args.log_level or "WARNING", args.log_format or "auto", args.log_file)
    return demo.run(Path(args.directory), console, port=args.port, serve=not args.no_serve, host=args.host)


def cmd_version(args: argparse.Namespace) -> int:
    import platform as py_platform

    def version_of(name: str) -> str:
        try:
            from importlib.metadata import version

            return version(name)
        except Exception:  # noqa: BLE001
            return "not installed"

    console.print(f"NetLedger {__version__}")
    console.print(f"  napalm {version_of('napalm')} · netmiko {version_of('netmiko')} · python {py_platform.python_version()} ({sys.platform})")
    return 0


# --------------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netledger",
        description="Network configuration backup to Git, change tracking and health monitoring.",
    )
    parser.add_argument("-V", "--version", action="version", version=f"NetLedger {__version__}")
    parser.add_argument("-c", "--config", help="path to netledger.yaml (default: $NETLEDGER_CONFIG or ./netledger.yaml)")
    parser.add_argument("--log-level", help="DEBUG, INFO, WARNING, ERROR")
    parser.add_argument("--log-format", choices=("auto", "text", "json"))
    parser.add_argument("--log-file", help="also write logs to this file (rotated at 10 MB)")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    filters = argparse.ArgumentParser(add_help=False)
    group = filters.add_argument_group("device filters (combine freely; globs allowed)")
    group.add_argument("-d", "--device", action="append", default=[], metavar="NAME", help="device name or host")
    group.add_argument("-s", "--site", action="append", default=[], metavar="SITE")
    group.add_argument("-g", "--group", action="append", default=[], metavar="GROUP")
    group.add_argument("-t", "--tag", action="append", default=[], metavar="TAG")
    group.add_argument("-p", "--platform", action="append", default=[], metavar="PLATFORM")

    p = sub.add_parser("init", help="create starter netledger.yaml, inventory.yaml and netledger.env")
    p.add_argument("directory", nargs="?", default=".")
    p.add_argument("--force", action="store_true", help="overwrite existing files")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("validate", help="check configuration, inventory, credentials and drivers")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("inventory", parents=[filters], help="list devices")
    p.add_argument("--format", choices=("table", "json", "yaml"), default="table")
    p.set_defaults(func=cmd_inventory)

    p = sub.add_parser("platforms", help="list supported platforms")
    p.set_defaults(func=cmd_platforms)

    p = sub.add_parser("test", parents=[filters], help="connect to devices and show facts")
    p.add_argument("--show-config", action="store_true", help="also fetch the running configuration")
    p.add_argument("--lines", type=int, default=15, help="configuration lines to print with --show-config")
    p.add_argument("--health", action="store_true", help="also read environment data (CPU, memory, sensors)")
    p.set_defaults(func=cmd_test)

    for name, func, help_text in (
        ("backup", cmd_backup, "back up configurations and commit changes to Git"),
        ("run", cmd_run, "backup followed by a health check"),
    ):
        p = sub.add_parser(name, parents=[filters], help=help_text)
        p.add_argument("--dry-run", action="store_true", help="collect and diff, but do not commit")
        p.add_argument("--diff", action="store_true", help="print diffs of changed configurations")
        p.add_argument("--no-push", action="store_true", help="commit locally but do not push")
        p.add_argument("--no-notify", action="store_true", help="do not send notifications")
        p.add_argument("--workers", type=int, help="parallel connections")
        p.add_argument("--json", action="store_true", help="machine-readable output")
        p.set_defaults(func=func)

    p = sub.add_parser("health", parents=[filters], help="check CPU, memory, temperature, fans and power (exit code 0/1/2/3 like Nagios)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--no-notify", action="store_true", help="do not send notifications")
    p.set_defaults(func=cmd_health)

    p = sub.add_parser("serve", help="run continuously: scheduler, web dashboard and Prometheus metrics")
    p.add_argument("--host", help="listen address (default from config)")
    p.add_argument("--port", type=int, help="listen port (default from config)")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("notify-test", help="send a test message to every configured notifier")
    p.set_defaults(func=cmd_notify_test)

    p = sub.add_parser("search", help="search backed-up configurations (regular expression, or an IP address / subnet)")
    p.add_argument("pattern", help="regular expression, or an IP address / network such as 10.1.1.7 or 10.1.0.0/16")
    p.add_argument("-i", "--ignore-case", action="store_true")
    p.add_argument("-l", "--files", action="store_true", help="only list matching devices")
    p.add_argument("--ip", action="store_true", help="IP-aware search: subnets containing the address, ACLs, routes, objects")
    p.add_argument("--regex", action="store_true", help="treat the pattern as a regular expression even if it looks like an address")
    p.set_defaults(func=cmd_search)

    p = sub.add_parser("sanitize", help="remove secrets, addresses and names from a configuration or command output before sharing it")
    p.add_argument("file", nargs="?", default="-", help="configuration or command output (default: standard input)")
    p.add_argument("--platform", help="the platform it comes from, for its secret rules (default: guessed from the syntax)")
    p.add_argument("-o", "--output", help="write the result to this file instead of standard output")
    p.add_argument("--keep-private", action="store_true", help="leave RFC 1918 and IPv6 unique-local addresses as they are")
    p.add_argument("--device", metavar="NAME", help="sanitize the latest backed-up configuration of this inventory device")
    p.set_defaults(func=cmd_sanitize)

    p = sub.add_parser("demo", help="try NetLedger with simulated devices (no hardware needed)")
    p.add_argument("--dir", dest="directory", default="netledger-demo", help="demo directory (default: ./netledger-demo)")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--host", default="127.0.0.1", help="dashboard listen address (use 0.0.0.0 in a container)")
    p.add_argument("--no-serve", action="store_true", help="exit after the tour instead of starting the dashboard")
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("version", help="show versions")
    p.set_defaults(func=cmd_version)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    for attr in ("device", "site", "group", "tag", "platform"):
        if not hasattr(args, attr):
            setattr(args, attr, [])
    try:
        return int(args.func(args) or 0)
    except ConfigError as exc:
        err.print(f"[bold red]Configuration error:[/] {exc}", highlight=False)
        return 3 if args.command == "health" else 2
    except KeyboardInterrupt:
        return 130
