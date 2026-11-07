"""Terminal output for CLI commands (Rich tables, colored diffs, summaries)."""

from __future__ import annotations

import sys
from typing import Iterable

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from netledger.backup import BackupReport, DeviceResult
from netledger.health import DeviceHealth, HealthReport
from netledger.inventory import Device
from netledger.utils import format_duration, truncate_lines

STATUS_STYLE = {"ok": "green", "warning": "yellow", "critical": "bold red", "unknown": "grey62"}
STATUS_ICON = {"ok": "●", "warning": "▲", "critical": "■", "unknown": "○"}
RISK_STYLE = {"high": "bold red", "medium": "yellow", "low": "cyan"}


def make_console(**kwargs: object) -> Console:
    for stream in (sys.stdout, sys.stderr):
        encoding = (getattr(stream, "encoding", "") or "").lower().replace("-", "")
        if not stream.isatty() and encoding not in ("utf8", "") and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass
    return Console(highlight=False, **kwargs)  # type: ignore[arg-type]


def _status_text(status: str, label: str | None = None) -> Text:
    return Text(f"{STATUS_ICON.get(status, '•')} {label or status}", style=STATUS_STYLE.get(status, ""))


def backup_table(results: Iterable[DeviceResult]) -> Table:
    table = Table(box=box.SIMPLE_HEAVY, header_style="bold", pad_edge=False, expand=False)
    table.add_column("Device", style="bold")
    table.add_column("Platform")
    table.add_column("Status")
    table.add_column("Changes")
    table.add_column("Time", justify="right")
    table.add_column("Notes", overflow="fold", max_width=58)
    for result in results:
        platform = result.device.platform_info.name
        if result.status == "failed":
            status = _status_text("critical", "failed")
            changes = Text("-", style="grey62")
            notes = Text(result.error or "", style="red")
        else:
            status = _status_text("ok", "ok")
            if result.initial:
                changes = Text("initial backup", style="cyan")
            elif result.config_changed:
                added, removed = result.stats()
                kinds = "/".join(sorted({c.kind for c in result.config_changes}))
                changes = Text.assemble((f"+{added}", "green"), " ", (f"-{removed}", "red"), (f" {kinds}", "grey62"))
                risk = result.analysis.risk if result.analysis else None
                if risk:
                    changes.append(f" {risk.upper()}", style=RISK_STYLE.get(risk, ""))
            elif result.changes:
                changes = Text("metadata", style="grey62")
            else:
                changes = Text("no change", style="grey62")
            parts = []
            if result.meta.get("changed_by") and result.config_changed and not result.initial:
                parts.append(f"changed by {result.meta['changed_by']}")
            if result.unsaved:
                parts.append("running ≠ startup (unsaved)")
            failing = [c.rule for c in result.compliance if not c.passed]
            if failing:
                parts.append(f"compliance: {', '.join(failing)}")
            parts += result.warnings
            notes = Text("; ".join(parts), style="yellow" if (result.unsaved or failing or result.warnings) else "grey62")
        table.add_row(result.device.name, platform, status, changes, format_duration(result.duration), notes)
    return table


def print_backup_report(console: Console, report: BackupReport, show_diff: bool = False) -> None:
    if report.error and not report.results:
        console.print(f"[bold red]Backup could not start:[/] {report.error}")
        return
    console.print(backup_table(report.results))
    changed = [r for r in report.results if r.config_changed and not r.initial]
    initial = [r for r in report.results if r.initial]
    summary = Text.assemble(
        (_count(len(report.results), "device"), "bold"), " · ",
        (f"{len(report.ok)} backed up", "green"), " · ",
        (f"{len(changed)} changed", "yellow" if changed else "grey62"), " · ",
        (f"{len(initial)} new", "cyan" if initial else "grey62"), " · ",
        (f"{len(report.failed)} failed", "red" if report.failed else "grey62"), " · ",
        (f"{report.commits} commit{'s' if report.commits != 1 else ''}", "bold"),
        f" in {format_duration(report.duration)}",
    )
    console.print(summary)
    if report.dry_run:
        console.print("[yellow]Dry run:[/] nothing was committed.")
    elif report.publish_message:
        console.print(f"[grey62]Repository:[/] {report.store} - {report.publish_message}")
    if report.error:
        console.print(f"[bold red]Repository error:[/] {report.error}")
    print_intelligence(console, changed)
    if show_diff:
        for result in report.results:
            diff = result.masked_diff or "".join(c.diff for c in result.config_changes)
            if diff and not result.initial:
                console.rule(f"[bold]{result.device.name}[/]", style="grey35")
                console.print(diff_text(truncate_lines(diff, 120)))


def print_intelligence(console: Console, results: list[DeviceResult]) -> None:
    """What each change touched, how risky it is, in plain language."""
    analysed = [r for r in results if r.analysis and r.analysis.risk and r.analysis.items]
    if not analysed:
        return
    console.print()
    console.print(Text("Change intelligence", style="bold"))
    width = max(len(r.device.name) for r in analysed)
    for result in analysed:
        analysis = result.analysis
        assert analysis is not None
        head = Text.assemble(
            ("  " + result.device.name.ljust(width), "bold"), "  ",
            (f"{analysis.risk.upper():<6}", RISK_STYLE.get(analysis.risk or "", "")), (f" {analysis.score:>3}/100", "grey62"),
        )
        if result.unplanned:
            head.append("  outside change window", style="yellow")
        labels = ", ".join(c["label"] for c in analysis.categories()[:3])
        head.append(f"  {labels}", style="grey62")
        console.print(head)
        for reason in analysis.reasons[:2]:
            console.print(Text.assemble("  " + " " * width + "  ", ("why ", "grey62"), reason), highlight=False)
        for text in analysis.highlights[:3]:
            console.print(Text("  " + " " * width + "  • " + text), highlight=False)
        if len(analysis.highlights) > 3:
            console.print(Text("  " + " " * width + f"    … and {len(analysis.highlights) - 3} more", style="grey62"))


def diff_text(diff: str) -> Text:
    """Colorize a unified diff."""
    text = Text()
    for line in diff.splitlines():
        if line.startswith(("+++", "---")):
            style = "bold"
        elif line.startswith("+"):
            style = "green"
        elif line.startswith("-"):
            style = "red"
        elif line.startswith("@@"):
            style = "cyan"
        else:
            style = "grey70"
        text.append(line + "\n", style=style)
    return text


def _meter(value: float | None, warning: float | None, critical: float | None) -> Text:
    if value is None:
        return Text("-", style="grey62")
    style = "red" if critical is not None and value >= critical else "yellow" if warning is not None and value >= warning else "green"
    filled = max(1, round(value / 10))
    return Text.assemble((f"{value:>3.0f}% ", style), ("━" * filled, style), ("━" * (10 - filled), "grey27"))


def health_table(results: Iterable[DeviceHealth], cpu: tuple[float | None, float | None], memory: tuple[float | None, float | None]) -> Table:
    table = Table(box=box.SIMPLE_HEAVY, header_style="bold", pad_edge=False)
    table.add_column("Device", style="bold")
    table.add_column("Health")
    table.add_column("CPU")
    table.add_column("Memory")
    table.add_column("Temp", justify="right")
    table.add_column("Fans", justify="center")
    table.add_column("PSU", justify="center")
    table.add_column("Uptime", justify="right")
    table.add_column("Notes", overflow="fold", max_width=46)
    for result in results:
        temp = result.max_temperature
        temp_status = next((c.status for c in result.checks if c.name == "temperature"), "ok")
        temp_text = Text(f"{temp:.0f}°C", style=STATUS_STYLE.get(temp_status, "")) if temp is not None else Text("-", style="grey62")

        def hw(items: dict[str, bool]) -> Text:
            if not items:
                return Text("-", style="grey62")
            failed = sum(1 for ok in items.values() if not ok)
            return Text(f"{len(items) - failed}/{len(items)}", style="red" if failed else "green")

        problems = [c.message for c in result.checks if c.status in ("warning", "critical", "unknown")]
        table.add_row(
            result.device.name,
            _status_text(result.status),
            _meter(result.cpu, *cpu),
            _meter(result.memory_pct, *memory),
            temp_text,
            hw(result.fans),
            hw(result.psus),
            format_duration(result.uptime, coarse=True) if result.uptime else "-",
            Text("; ".join(problems), style=STATUS_STYLE.get(result.status, "")),
        )
    return table


def print_health_report(console: Console, report: HealthReport, cpu: tuple[float | None, float | None], memory: tuple[float | None, float | None]) -> None:
    console.print(health_table(report.results, cpu, memory))
    summary = Text.assemble(
        (_count(len(report.results), "device"), "bold"), " · ",
        (f"{report.count('ok')} ok", "green"), " · ",
        (f"{report.count('warning')} warning", "yellow" if report.count("warning") else "grey62"), " · ",
        (f"{report.count('critical')} critical", "red" if report.count("critical") else "grey62"), " · ",
        (f"{report.count('unknown')} unknown", "grey62"),
        f" in {format_duration(report.duration)}",
    )
    console.print(summary)


def inventory_table(devices: Iterable[Device]) -> Table:
    table = Table(box=box.SIMPLE_HEAVY, header_style="bold", pad_edge=False)
    for column in ("Device", "Host", "Platform", "Site", "Role", "Groups", "Tags"):
        table.add_column(column, style="bold" if column == "Device" else "")
    for device in devices:
        table.add_row(
            device.name,
            device.host,
            device.platform_info.name,
            device.site or "-",
            device.role or "-",
            ", ".join(device.groups) or "-",
            ", ".join(device.tags) or "-",
        )
    return table


def _count(number: int, noun: str) -> str:
    return f"{number} {noun}{'' if number == 1 else 's'}"
