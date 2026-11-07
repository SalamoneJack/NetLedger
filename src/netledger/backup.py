"""Backup runs: collect configurations, normalize, diff, commit, check compliance and alert."""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from netledger.compliance import ComplianceResult, evaluate
from netledger.config import CommandSpec, Settings
from netledger.connection import DeviceError, describe_error, device_session, run_parallel
from netledger.events import Event
from netledger.intel import Analysis, analyze, commit_summary
from netledger.inventory import Device, device_dir
from netledger.normalize import Normalizer
from netledger.platforms import resolve_platform
from netledger.state import StateStore
from netledger.storage import Store, StoreError, WebLinks, create_store
from netledger.storage.github import INIT_MARKER
from netledger.utils import atomic_write, diff_stats, iso, now, slugify, truncate_lines, unified_diff
from netledger.windows import ChangeCalendar

log = logging.getLogger(__name__)

CONFIG_KINDS = ("running", "startup", "candidate")
INDEX_MARKER = "<!-- netledger:index -->"
PROJECT_URL = "https://github.com/SalamoneJack/NetLedger"

_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()


def _repository_lock(key: str) -> threading.Lock:
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(key, threading.Lock())


@dataclass
class Collected:
    configs: dict[str, str] = field(default_factory=dict)
    facts: dict[str, Any] = field(default_factory=dict)
    outputs: list[tuple[CommandSpec, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error: str | None = None
    error_kind: str | None = None
    duration: float = 0.0


@dataclass
class FileChange:
    path: str
    kind: str
    old: str | None
    new: str | None
    diff: str = ""
    added: int = 0
    removed: int = 0

    @property
    def action(self) -> str:
        return "A" if self.old is None else "D" if self.new is None else "M"


@dataclass
class DeviceResult:
    device: Device
    status: str
    duration: float = 0.0
    error: str | None = None
    error_kind: str | None = None
    changes: list[FileChange] = field(default_factory=list)
    commit: str | None = None
    warnings: list[str] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)
    meta: dict[str, str] = field(default_factory=dict)
    compliance: list[ComplianceResult] = field(default_factory=list)
    unsaved: bool | None = None
    masked_diff: str = ""
    analysis: Analysis | None = None
    unplanned: bool | None = None

    @property
    def config_changes(self) -> list[FileChange]:
        return [c for c in self.changes if c.kind in CONFIG_KINDS]

    @property
    def config_changed(self) -> bool:
        return bool(self.config_changes)

    @property
    def initial(self) -> bool:
        changes = self.config_changes
        return bool(changes) and all(c.old is None for c in changes)

    def stats(self) -> tuple[int, int]:
        changes = self.config_changes
        return sum(c.added for c in changes), sum(c.removed for c in changes)


@dataclass
class BackupReport:
    started: float
    finished: float = 0.0
    results: list[DeviceResult] = field(default_factory=list)
    commits: int = 0
    pushed: bool = False
    store: str = ""
    dry_run: bool = False
    error: str | None = None
    publish_message: str = ""
    events: list[Event] = field(default_factory=list)

    @property
    def ok(self) -> list[DeviceResult]:
        return [r for r in self.results if r.status == "ok"]

    @property
    def failed(self) -> list[DeviceResult]:
        return [r for r in self.results if r.status == "failed"]

    @property
    def changed(self) -> list[DeviceResult]:
        return [r for r in self.results if r.changes]

    @property
    def duration(self) -> float:
        return max(0.0, (self.finished or now()) - self.started)


def build_commit_message(device: Device, result: DeviceResult) -> str:
    platform = device.platform_info
    configs = result.config_changes
    if result.initial:
        subject = f"{device.name}: initial backup"
    elif configs:
        kinds = "/".join(k for k in CONFIG_KINDS if any(c.kind == k for c in configs))
        added, removed = result.stats()
        subject = f"{device.name}: {kinds} config changed (+{added}/-{removed})"
    elif any(c.kind == "command" for c in result.changes):
        subject = f"{device.name}: command output updated"
    elif any(c.kind == "stale" for c in result.changes):
        subject = f"{device.name}: removed files no longer collected"
    else:
        subject = f"{device.name}: device details updated"
    lines = [subject, "", f"Device:     {device.name} ({device.host})", f"Platform:   {platform.name}"]
    model = result.facts.get("model")
    version = result.facts.get("os_version")
    if model or version:
        lines.append(f"Model:      {', '.join(v for v in (model, version) if v)}")
    if device.site:
        lines.append(f"Site:       {device.site}")
    if configs and not result.initial:
        who, when = result.meta.get("changed_by"), result.meta.get("changed_at")
        if who:
            lines.append(f"Changed by: {who}" + (f" at {when}" if when else ""))
        elif when:
            lines.append(f"Changed at: {when}")
        if result.unplanned:
            lines.append("Window:     outside the approved change windows")
        if result.analysis:
            lines += commit_summary(result.analysis)
    lines += ["", "Files:"]
    for change in result.changes:
        stat = f" (+{change.added}/-{change.removed})" if change.action == "M" else ""
        lines.append(f"  {change.action} {change.path}{stat}")
    return "\n".join(lines) + "\n"


def render_index(entries: list[tuple[Device, dict[str, Any]]], settings: Settings) -> str:
    def cell(value: Any) -> str:
        text = str(value or "").replace("|", "\\|").replace("\n", " ").strip()
        return text or "-"

    rows = sorted(entries, key=lambda e: (e[0].site.lower(), e[0].name.lower()))
    sites = {d.site for d, _ in rows if d.site}
    platforms = {d.platform for d, _ in rows}
    lines = [
        "# Network configuration backups",
        "",
        INDEX_MARKER,
        f"Maintained automatically by [NetLedger]({PROJECT_URL}). Every device has a folder with its configuration",
        "and a `device.json` summary. Do not edit files here by hand: they are rewritten on the next backup.",
        "",
        f"**{len(rows)} devices** · {len(sites)} sites · {len(platforms)} platforms",
        "",
        "| Device | Site | Platform | Model | OS version | Serial | Last changed |",
        "|---|---|---|---|---|---|---|",
    ]
    for device, meta in rows:
        folder = device_dir(device, settings.git)
        name = f"[{cell(device.name)}]({folder})" if meta else f"{cell(device.name)} *(pending)*"
        changed = (meta.get("last_changed") or "")[:10]
        lines.append(
            f"| {name} | {cell(device.site)} | {cell(device.platform_info.name)} | {cell(meta.get('model'))} "
            f"| {cell(meta.get('os_version'))} | {cell(meta.get('serial_number'))} | {cell(changed)} |"
        )
    return "\n".join(lines) + "\n"


class BackupRunner:
    def __init__(
        self,
        settings: Settings,
        state: StateStore,
        dispatcher: Any | None = None,
        store_factory: Callable[[Settings], Store] = create_store,
    ):
        self.settings = settings
        self.state = state
        self.dispatcher = dispatcher
        self.store_factory = store_factory
        self.normalizer = Normalizer(settings.normalize)
        self._meta_cache: dict[str, dict[str, Any]] = {}
        self._commits = 0
        self._index_warned = False
        self.links: WebLinks | None = None
        self.calendar = self._calendar(settings)

    @staticmethod
    def _calendar(settings: Settings) -> ChangeCalendar:
        from netledger.scheduler import ScheduleError, load_timezone

        try:
            tz = load_timezone(settings.changes.timezone or settings.schedule.timezone)
        except ScheduleError as exc:
            log.warning("change windows: %s; using local time", exc)
            tz = None
        return ChangeCalendar(settings.changes.windows, tz)

    # ------------------------------------------------------------------ collection (worker threads)

    def retrieve_kinds(self, device: Device) -> list[str]:
        if device.collector == "oxidized":
            return ["running"]
        platform = device.platform_info
        wanted = device.retrieve or list(self.settings.backup.retrieve)
        kinds = [
            k for k in wanted
            if k == "running" or (k == "startup" and platform.startup) or (k == "candidate" and platform.candidate)
        ]
        return kinds or ["running"]

    def commands_for(self, device: Device) -> list[CommandSpec]:
        if device.collector == "oxidized":
            return []
        entries: list[Any] = []
        for key, commands in self.settings.backup.commands.items():
            if key == "*" or (resolve_platform(key) or key) == device.platform:
                entries.extend(commands)
        entries.extend(device.commands)
        specs: list[CommandSpec] = []
        seen: set[str] = set()
        for entry in entries:
            spec = entry if isinstance(entry, CommandSpec) else CommandSpec(command=entry) if isinstance(entry, str) else CommandSpec(**entry)
            if spec.command not in seen:
                seen.add(spec.command)
                specs.append(spec)
        return specs

    def collect(self, device: Device) -> Collected:
        started = time.monotonic()
        result = Collected()
        kinds = self.retrieve_kinds(device)
        try:
            with device_session(device, self.settings) as driver:
                configs = driver.get_config(retrieve="all" if len(kinds) > 1 else kinds[0], full=self.settings.backup.full)
                result.configs = {kind: str(configs.get(kind) or "") for kind in kinds}
                if self.settings.backup.facts:
                    try:
                        result.facts = dict(driver.get_facts())
                    except Exception as exc:  # noqa: BLE001
                        result.warnings.append(f"facts: {describe_error(exc)}")
                for spec in self.commands_for(device):
                    try:
                        output = driver.cli([spec.command])
                        result.outputs.append((spec, str(output.get(spec.command, ""))))
                    except Exception as exc:  # noqa: BLE001
                        result.warnings.append(f"command {spec.command!r}: {describe_error(exc)}")
        except DeviceError as exc:
            result.error, result.error_kind = str(exc), exc.kind
        except Exception as exc:  # noqa: BLE001
            result.error, result.error_kind = f"{type(exc).__name__}: {describe_error(exc)}", "error"
        result.duration = time.monotonic() - started
        return result

    # ------------------------------------------------------------------ orchestration (main thread)

    def run(
        self,
        devices: list[Device],
        inventory: list[Device] | None = None,
        dry_run: bool = False,
        push: bool = True,
        progress: Callable[[DeviceResult], None] | None = None,
    ) -> BackupReport:
        store = self.store_factory(self.settings)
        with _repository_lock(store.describe()):  # one writer per repository (scheduled backups, Oxidized processing)
            return self._run(store, devices, inventory, dry_run, push, progress)

    def _run(
        self,
        store: Store,
        devices: list[Device],
        inventory: list[Device] | None,
        dry_run: bool,
        push: bool,
        progress: Callable[[DeviceResult], None] | None,
    ) -> BackupReport:
        inventory = list(inventory) if inventory is not None else list(devices)
        # pruning needs a run over every device NetLedger backs up itself; Oxidized devices have their own job in
        # 'serve', and pruning keeps the folders of everything still in the inventory either way
        full_run = {d.name for d in devices} >= {d.name for d in inventory if d.backup and d.collector != "oxidized"}
        report = BackupReport(started=now(), dry_run=dry_run)
        self._meta_cache = {}
        self._commits = 0
        self.links = store.links
        report.store = store.describe()
        try:
            store.prepare()
        except StoreError as exc:
            report.error = str(exc)
            report.finished = now()
            self._record_run(report)
            return report

        events: list[Event] = []
        pending: dict[str, str | None] = {}
        pending_lines: list[str] = []
        targets = [d for d in devices if d.backup and d.collector != "oxidized"]
        backed_up = [d for d in inventory if d.backup]
        for device, collected in run_parallel(targets, self.collect, self.settings.backup.workers):
            result = self._process(device, collected, store, backed_up, dry_run, events, pending, pending_lines)
            report.results.append(result)
            if progress:
                progress(result)
        from_oxidized = [d for d in devices if d.backup and d.collector == "oxidized"]
        if from_oxidized:
            for result in self._run_oxidized(from_oxidized, store, backed_up, dry_run, events, pending, pending_lines):
                report.results.append(result)
                if progress:
                    progress(result)
        report.results.sort(key=lambda r: r.device.name.lower())

        if not dry_run:
            try:
                self._finish(store, backed_up, full_run, pending, pending_lines)
                if push:
                    published = store.publish()
                    report.pushed = published.pushed
                    report.publish_message = published.message
                else:
                    report.publish_message = "push skipped"
            except StoreError as exc:
                report.error = str(exc)
                log.error("%s", exc)
        report.commits = self._commits
        report.finished = now()
        report.events = events
        if not dry_run:
            self.state.record_events(events)
            self._record_run(report)
            if self.dispatcher and events:
                self.dispatcher.dispatch(events)
        return report

    def _run_oxidized(
        self,
        devices: list[Device],
        store: Store,
        inventory: list[Device],
        dry_run: bool,
        events: list[Event],
        pending: dict[str, str | None],
        pending_lines: list[str],
    ) -> list[DeviceResult]:
        """Process what Oxidized collected since the last run: every new version is a change of its own."""
        from netledger.oxidized import OxidizedError, oxidized_sources, read_versions

        by_name = {d.name: d for d in devices}
        results: list[DeviceResult] = []
        for source in oxidized_sources(self.settings):
            mine = [d for d in devices if d.oxidized.get("source") == source.key]
            if not mine:
                continue
            try:
                batch = read_versions(source, self.settings, mine, self.state.cursor(source.key))
            except OxidizedError as exc:
                log.error("%s", exc)
                for device in mine:
                    result = DeviceResult(device=device, status="ok")
                    results.append(self._fail(device, result, f"cannot read Oxidized: {exc}", self.state.section(device.name, "backup"), events, dry_run))
                continue
            versions = batch.versions
            if self.settings.git.commit_mode == "per-run":  # one commit per run: keep the newest version of each device
                newest = {version.device: version for version in versions}
                versions = [version for version in versions if newest[version.device] is version]
            done: dict[str, DeviceResult] = {}
            for version in versions:
                done[version.device] = self._process(
                    by_name[version.device], Collected(configs={"running": version.text}), store, inventory, dry_run, events,
                    pending, pending_lines, when=version.timestamp, author=version.author, quiet=version.quiet,
                )
            failures = dict(batch.failures)
            for device in mine:
                previous = self.state.section(device.name, "backup")
                if device.name in failures:
                    results.append(self._fail(device, DeviceResult(device=device, status="ok"), failures[device.name], previous, events, dry_run))
                elif device.name in done:
                    results.append(done[device.name])
                else:
                    results.append(self._unchanged(device, previous, events, dry_run))
            if not dry_run:
                self.state.set_cursor(source.key, batch.cursor)
        return results

    def _unchanged(self, device: Device, previous: dict[str, Any], events: list[Event], dry_run: bool) -> DeviceResult:
        """Nothing new from Oxidized for a device: still a successful check."""
        result = DeviceResult(device=device, status="ok")
        if dry_run:
            return result
        stamp = now()
        if previous.get("status") == "failed" and int(previous.get("consecutive_failures") or 0) >= self.settings.backup.failure_alert_after:
            events.append(Event(
                "backup_recovered", "info", f"{device.name}: configuration backup recovered", "Backups are succeeding again.",
                device=device.name, site=device.site or None, platform=device.platform, timestamp=stamp,
            ))
        self.state.update(device.name, "backup", {"status": "ok", "error": None, "last_attempt": stamp, "consecutive_failures": 0})
        return result

    def _finish(
        self,
        store: Store,
        inventory: list[Device],
        full_run: bool,
        pending: dict[str, str | None],
        pending_lines: list[str],
    ) -> None:
        git = self.settings.git
        if git.commit_mode == "per-run" and pending:
            index = self._index_update(store, inventory)
            if index is not None:
                pending[git.index_path] = index
            count = len(pending_lines)
            subject = f"Backup: {count} device{'s' if count != 1 else ''} changed"
            if self._commit(store, pending, subject + "\n\n" + "\n".join(pending_lines) + "\n"):
                pending.clear()
        if git.prune and full_run:
            removed = self._prune_changes(store, inventory)
            if removed:
                names = sorted(p.rsplit("/", 2)[-2] for p in removed if p.endswith("/device.json")) or ["(unknown)"]
                index = self._index_update(store, inventory)
                if index is not None:
                    removed[git.index_path] = index
                self._commit(store, removed, f"Remove {len(names)} device(s) no longer in inventory\n\n" + "\n".join(f"- {n}" for n in names) + "\n")
        index = self._index_update(store, inventory)
        if index is not None:
            self._commit(store, {git.index_path: index}, "Update device index\n")

    def _commit(self, store: Store, changes: dict[str, str | None], message: str) -> str | None:
        sha = store.commit(changes, message)
        if sha:
            self._commits += 1
        return sha

    def _change(self, path: str, kind: str, old: str | None, new: str | None) -> FileChange:
        diff = unified_diff(old, new, path)
        added, removed = diff_stats(diff)
        return FileChange(path, kind, old, new, diff, added, removed)

    def _load_meta(self, store: Store, device: Device) -> dict[str, Any]:
        if device.name not in self._meta_cache:
            text = store.read(f"{device_dir(device, self.settings.git)}/device.json")
            try:
                self._meta_cache[device.name] = json.loads(text) if text else {}
            except ValueError:
                self._meta_cache[device.name] = {}
        return self._meta_cache[device.name]

    def _build_meta(self, device: Device, facts: dict[str, Any], old: dict[str, Any], changed: bool, stamp: float | None = None) -> dict[str, Any]:
        platform = device.platform_info

        def pick(key: str) -> Any:
            value = facts.get(key)
            if value in (None, "", -1, "unknown"):
                return old.get(key, "")
            return value

        meta = {
            "name": device.name,
            "host": device.host,
            "platform": platform.key,
            "platform_name": platform.name,
            "vendor": pick("vendor") or platform.vendor,
            "model": pick("model"),
            "os_version": pick("os_version"),
            "serial_number": pick("serial_number"),
            "hostname": pick("hostname"),
            "site": device.site,
            "role": device.role,
            "tags": sorted(device.tags),
            "last_changed": iso(stamp or now()) if changed or not old.get("last_changed") else old["last_changed"],
        }
        if device.description:
            meta["description"] = device.description
        return meta

    def _process(
        self,
        device: Device,
        collected: Collected,
        store: Store,
        inventory: list[Device],
        dry_run: bool,
        events: list[Event],
        pending: dict[str, str | None],
        pending_lines: list[str],
        when: float | None = None,
        author: str | None = None,
        quiet: bool = False,
    ) -> DeviceResult:
        """``when`` / ``author``: when and by whom the configuration was captured, if not now by NetLedger
        (an Oxidized commit). ``quiet``: record the configuration without reporting it as a change."""
        stamp = when if when is not None else now()
        platform = device.platform_info
        ddir = device_dir(device, self.settings.git)
        result = DeviceResult(device=device, status="ok", duration=collected.duration, warnings=list(collected.warnings), facts=collected.facts)
        previous = self.state.section(device.name, "backup")
        if not dry_run:
            self._record_info(device, ddir, collected.facts)
        if collected.error:
            return self._fail(device, result, collected.error, previous, events, dry_run, collected.error_kind)

        files: dict[str, tuple[str, str]] = {}
        compliance_text: str | None = None
        for kind in self.retrieve_kinds(device):
            raw = collected.configs.get(kind, "")
            if not raw.strip():
                if kind == "running":
                    return self._fail(device, result, "device returned an empty running configuration", previous, events, dry_run)
                result.warnings.append(f"{kind} configuration was empty")
                continue
            normalized = self.normalizer.normalize(raw, platform)
            if kind == "running":
                result.meta = normalized.meta
                if author and not result.meta.get("changed_by"):
                    result.meta["changed_by"] = author
                if when is not None and result.meta.get("changed_by") and not result.meta.get("changed_at"):
                    result.meta["changed_at"] = iso(when)
                compliance_text = normalized.text if self.normalizer.mode == "keep" else self.normalizer.normalize(raw, platform, secrets="keep").text
            files[f"{ddir}/{kind}-config.{platform.extension}"] = (kind, normalized.text)
        command_paths = {}
        for spec in self.commands_for(device):
            command_paths[spec.command] = f"{ddir}/commands/{slugify(spec.name or spec.command)}.txt"
        for spec, output in collected.outputs:
            files[command_paths[spec.command]] = ("command", self.normalizer.normalize_output(output, platform, spec.exclude))

        running_path = f"{ddir}/running-config.{platform.extension}"
        guard = self.settings.backup.shrink_guard
        if running_path in files and guard > 0:
            old_running = store.read(running_path)
            if old_running:
                old_lines, new_lines = old_running.count("\n"), files[running_path][1].count("\n")
                if old_lines > 20 and new_lines < old_lines * guard:
                    return self._fail(
                        device, result,
                        f"running configuration shrank from {old_lines} to {new_lines} lines; not committing it "
                        "(truncated output or missing privileges?). Set backup.shrink_guard: 0 to allow.",
                        previous, events, dry_run,
                    )
        startup_path = f"{ddir}/startup-config.{platform.extension}"
        if running_path in files and startup_path in files:
            result.unsaved = files[running_path][1] != files[startup_path][1]

        changes: list[FileChange] = []
        for path, (kind, content) in files.items():
            old = store.read(path)
            if old != content:
                changes.append(self._change(path, kind, old, content))
        meta_path = f"{ddir}/device.json"
        expected = set(files) | {meta_path} | set(command_paths.values())
        expected |= {f"{ddir}/{kind}-config.{platform.extension}" for kind in self.retrieve_kinds(device)}
        for path in store.list_files(ddir):
            if path not in expected:
                changes.append(self._change(path, "stale", store.read(path), None))

        old_meta = self._load_meta(store, device)
        meta = self._build_meta(device, collected.facts, old_meta, any(c.kind in CONFIG_KINDS for c in changes), stamp)
        meta_text = json.dumps(meta, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        old_meta_text = store.read(meta_path)
        if old_meta_text != meta_text:
            changes.append(self._change(meta_path, "meta", old_meta_text, meta_text))
        self._meta_cache[device.name] = meta
        result.changes = changes

        if compliance_text and self.settings.compliance:
            result.compliance = evaluate(
                self.settings.compliance, device, compliance_text, mask=lambda text: self.normalizer.mask(text, platform) or text
            )
        if result.config_changed:
            result.masked_diff = "".join(
                unified_diff(self.normalizer.mask(c.old, platform), self.normalizer.mask(c.new, platform), c.path)
                for c in result.config_changes
            )
            primary = next((c for c in result.config_changes if c.kind == "running"), result.config_changes[0])
            try:
                result.analysis = analyze(
                    self.normalizer.mask(primary.old, platform), self.normalizer.mask(primary.new, platform), platform.key,
                    risk=self.settings.risk.resolve(device.risk, device.risk_origin),
                )
            except Exception as exc:  # noqa: BLE001 - analysis is advisory; never fail a backup over it
                log.warning("%s: change analysis failed: %s", device.name, exc)
            if not result.initial and self.calendar.enabled:
                since = float(previous.get("last_success") or stamp)
                result.unplanned = not self.calendar.overlaps(min(since, stamp), stamp)

        if changes and not dry_run:
            commit_changes: dict[str, str | None] = {c.path: c.new for c in changes}
            if self.settings.git.commit_mode == "per-device":
                index = self._index_update(store, inventory)
                if index is not None:
                    commit_changes[self.settings.git.index_path] = index
                try:
                    result.commit = self._commit(store, commit_changes, build_commit_message(device, result))
                except StoreError as exc:
                    return self._fail(device, result, f"commit failed: {exc}", previous, events, dry_run)
            else:
                pending.update(commit_changes)
                added, removed = result.stats()
                pending_lines.append(f"- {device.name}: {'initial backup' if result.initial else f'+{added}/-{removed}'}")

        if not dry_run:
            if store.local_path is None and running_path in files:
                self._mirror(running_path, files[running_path][1])
            self._record_success(device, result, previous, events, ddir, stamp, quiet)
        return result

    def _mirror(self, path: str, text: str) -> None:
        """Keep the latest configurations on disk for the dashboard search when there is no local clone."""
        try:
            atomic_write(self.settings.data_path / "mirror" / path, text)
        except OSError as exc:
            log.debug("could not mirror %s: %s", path, exc)

    def _fail(
        self,
        device: Device,
        result: DeviceResult,
        error: str,
        previous: dict[str, Any],
        events: list[Event],
        dry_run: bool,
        kind: str | None = None,
    ) -> DeviceResult:
        result.status = "failed"
        result.error = error
        result.error_kind = kind
        if dry_run:
            return result
        failures = int(previous.get("consecutive_failures") or 0) + 1
        self.state.update(device.name, "backup", {
            "status": "failed",
            "error": error,
            "last_attempt": now(),
            "consecutive_failures": failures,
            "duration": round(result.duration, 2),
        })
        if failures == self.settings.backup.failure_alert_after:
            events.append(Event(
                "backup_failed", "warning", f"{device.name}: configuration backup failing",
                f"{failures} consecutive failed backup(s). Last error: {error}",
                device=device.name, site=device.site or None, platform=device.platform, timestamp=now(),
            ))
        return result

    def _record_info(self, device: Device, ddir: str, facts: dict[str, Any]) -> None:
        info = device.summary()
        info["dir"] = ddir
        if self.links:
            info["links"] = {k: v for k, v in {"folder": self.links.tree(ddir), "history": self.links.history(ddir)}.items() if v}
        self.state.set_info(device.name, info)
        clean = {k: facts.get(k) for k in ("vendor", "model", "os_version", "serial_number", "hostname") if facts.get(k)}
        if clean:
            self.state.update(device.name, "facts", clean)

    def _record_success(
        self,
        device: Device,
        result: DeviceResult,
        previous: dict[str, Any],
        events: list[Event],
        ddir: str,
        stamp: float | None = None,
        quiet: bool = False,
    ) -> None:
        stamp = stamp if stamp is not None else now()
        values: dict[str, Any] = {
            "status": "ok",
            "error": None,
            "last_attempt": max(stamp, float(previous.get("last_attempt") or 0)),
            "last_success": stamp,
            "consecutive_failures": 0,
            "duration": round(result.duration, 2),
            "warnings": result.warnings,
            "unsaved_changes": result.unsaved,
        }
        if result.config_changed:
            values["last_change"] = stamp
            values["changes_total"] = int(previous.get("changes_total") or 0) + (0 if result.initial else 1)
            values["last_diff"] = truncate_lines(result.masked_diff, 400)
            values["last_commit"] = result.commit
            values["last_change_by"] = result.meta.get("changed_by") if not result.initial else None
            values["last_analysis"] = result.analysis.to_dict() if result.analysis and not result.initial else None
            values["last_unplanned"] = result.unplanned
            if result.initial:
                values["first_backup"] = stamp
            elif not quiet:
                self._record_change(device, result, previous, events, ddir, stamp)
        if previous.get("status") == "failed" and int(previous.get("consecutive_failures") or 0) >= self.settings.backup.failure_alert_after:
            events.append(Event(
                "backup_recovered", "info", f"{device.name}: configuration backup recovered",
                "Backups are succeeding again.", device=device.name, site=device.site or None, platform=device.platform,
                timestamp=stamp,
            ))
        self.state.update(device.name, "backup", values)

        if result.compliance or self.state.section(device.name, "compliance"):
            before = self.state.section(device.name, "compliance").get("rules", {})
            for item in result.compliance:
                was = (before.get(item.rule) or {}).get("passed")
                if not item.passed and was is not False:
                    events.append(Event(
                        "compliance_failed", item.severity, f"{device.name}: compliance rule '{item.rule}' failed",
                        item.description or "; ".join(item.findings[:3]),
                        device=device.name, site=device.site or None, platform=device.platform,
                        details={"rule": item.rule, "findings": item.findings}, timestamp=stamp,
                    ))
                elif item.passed and was is False:
                    events.append(Event(
                        "compliance_passed", "info", f"{device.name}: compliance rule '{item.rule}' passes again",
                        item.description, device=device.name, site=device.site or None, platform=device.platform,
                        details={"rule": item.rule}, timestamp=stamp,
                    ))
            self.state.update(device.name, "compliance", {
                "checked_at": stamp,
                "rules": {item.rule: item.to_dict() for item in result.compliance},
            }, replace=True)

    def _record_change(
        self, device: Device, result: DeviceResult, previous: dict[str, Any], events: list[Event], ddir: str, stamp: float
    ) -> None:
        platform = device.platform_info
        added, removed = result.stats()
        analysis = result.analysis
        who = result.meta.get("changed_by")
        risk = analysis.risk if analysis else None
        highlights = analysis.highlights[:6] if analysis else []
        reasons = analysis.reasons[:6] if analysis else []
        categories = analysis.categories() if analysis else []
        self.state.record_change({
            "id": f"{int(stamp * 1000)}-{slugify(device.name)}",
            "ts": stamp,
            "device": device.name,
            "site": device.site,
            "platform": platform.key,
            "platform_name": platform.name,
            "commit": result.commit,
            "dir": ddir,
            "path": f"{ddir}/running-config.{platform.extension}",
            "kinds": sorted({c.kind for c in result.config_changes}),
            "added": added,
            "removed": removed,
            "changed_by": who,
            "risk": risk,
            "score": analysis.score if analysis else None,
            "categories": [c["key"] for c in categories],
            "category_labels": [c["label"] for c in categories],
            "highlights": highlights,
            "reasons": reasons,
            "unplanned": result.unplanned,
            "since": previous.get("last_success"),
            "diff": truncate_lines(result.masked_diff, 200),
        }, keep=self.settings.changes.keep)

        links = {}
        if self.links and result.commit:
            links["View commit"] = self.links.commit(result.commit) or ""
        if self.links:
            links["History"] = self.links.history(ddir) or ""
        summary = f"+{added}/-{removed} lines" + (f" · {risk} risk" if risk else "") + (f", changed by {who}" if who else "")
        if result.unplanned:
            summary += " · outside the approved change windows"
        message = summary + "".join(f"\n• {text}" for text in highlights[:4])
        title = f"{device.name}: unplanned configuration change" if result.unplanned else f"{device.name}: configuration changed"
        events.append(Event(
            "config_changed", "warning" if result.unplanned else "info", title, message,
            device=device.name, site=device.site or None, platform=device.platform,
            diff=result.masked_diff, links={k: v for k, v in links.items() if v},
            details={
                "added": added, "removed": removed, "changed_by": who, "commit": result.commit, "risk": risk,
                "score": analysis.score if analysis else None, "categories": [c["label"] for c in categories],
                "highlights": highlights, "reasons": reasons, "unplanned": result.unplanned,
            },
            timestamp=stamp,
        ))

    def _index_update(self, store: Store, inventory: list[Device]) -> str | None:
        git = self.settings.git
        if not git.index:
            return None
        current = store.read(git.index_path)
        if current is not None and INDEX_MARKER not in current and INIT_MARKER not in current:
            if not self._index_warned:
                log.warning("%s exists and was not generated by NetLedger; leaving it alone (set git.index_path)", git.index_path)
                self._index_warned = True
            return None
        entries = [(device, self._load_meta(store, device)) for device in inventory]
        rendered = render_index(entries, self.settings)
        return rendered if rendered != current else None

    def _prune_changes(self, store: Store, inventory: list[Device]) -> dict[str, str | None]:
        base = self.settings.git.base_dir.strip("/")
        if not base:
            log.warning("git.prune needs git.base_dir to be set; skipping prune")
            return {}
        keep = {device_dir(d, self.settings.git) for d in inventory}
        return {path: None for path in store.list_files(base) if not any(path.startswith(k + "/") for k in keep)}

    def _record_run(self, report: BackupReport) -> None:
        self.state.set_run("backup", {
            "started": report.started,
            "finished": report.finished,
            "duration": round(report.duration, 2),
            "devices": len(report.results),
            "ok": len(report.ok),
            "failed": len(report.failed),
            "changed": len([r for r in report.results if r.config_changed]),
            "commits": report.commits,
            "pushed": report.pushed,
            "error": report.error,
            "store": report.store,
        })
        self.state.save()
