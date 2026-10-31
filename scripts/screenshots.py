"""Regenerate the README screenshots from the built-in demo (simulated devices, nothing real).

    python scripts/screenshots.py            # writes docs/images/*.svg and *.png

Terminal screenshots are recorded straight from the CLI with Rich. Console screenshots are taken
with a headless Chrome/Edge (temporary profile) against the real web server.
"""

from __future__ import annotations

import io
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import yaml
from rich.console import Console
from rich.text import Text

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from netledger import cli, demo  # noqa: E402
from netledger.backup import BackupRunner  # noqa: E402
from netledger.config import load_settings  # noqa: E402
from netledger.drivers.simulated import SimulatedDriver  # noqa: E402
from netledger.history import MetricsHistory  # noqa: E402
from netledger.inventory import load_inventory  # noqa: E402
from netledger.scheduler import IntervalSchedule, Scheduler  # noqa: E402
from netledger.server import App, DashboardServer  # noqa: E402
from netledger.state import StateStore  # noqa: E402
from netledger.storage.gitcli import GitCLIStore, remove_tree  # noqa: E402

OUT = ROOT / "docs" / "images"
WEB_URL = "https://github.com/your-org/network-configs"
BROWSERS = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
]
PAGES = [
    # name, path, width, height
    ("dashboard", "/", 1600, 2000),
    ("dashboard-dark", "/?theme=dark", 1600, 1500),
    ("device-timemachine", "/devices/hq-core-sw01", 1600, 2240),
    ("device-forecast", "/devices/dc1-ext-asa01?range=7d&theme=dark", 1600, 1000),
    ("change-ledger", "/changes", 1600, 1420),
    ("where-is", "/search?q=10.10.40.57", 1600, 1000),
    ("network-map", "/topology", 1600, 960),
    ("wallboard", "/wall?theme=dark", 1600, 900),
]


def recorder(width: int = 124) -> Console:
    return Console(record=True, width=width, file=io.StringIO(), color_system="truecolor", highlight=False)


def record(name: str, title: str, argv: list[str], width: int = 124, prompt: str | None = None) -> None:
    console = recorder(width)
    console.print(Text.assemble(("❯ ", "bold green"), (prompt or "netledger " + " ".join(a for a in argv if not a.startswith("-c") and not a.endswith(".yaml")), "bold")))
    cli.console = console
    cli.main(argv)
    console.save_svg(str(OUT / f"{name}.svg"), title=title)
    print(f"  wrote docs/images/{name}.svg")


def record_git_log(settings, device_path: str, name: str = "cli-git-log") -> None:  # noqa: ANN001
    repo = settings.data_path / "repo"
    raw = subprocess.run(
        ["git", "log", "-n", "2", "--format=%H%x1f%an%x1f%ar%x1f%B%x1e", "--", device_path],
        cwd=repo, capture_output=True, text=True, encoding="utf-8", check=True,
    ).stdout
    console = recorder(100)
    console.print(Text.assemble(("❯ ", "bold green"), (f"git log -n 2 -- {device_path}", "bold")))
    for entry in [e for e in raw.split("\x1e") if e.strip()]:
        sha, author, when, body = entry.strip("\n").split("\x1f")
        console.print(Text(f"commit {sha}", style="yellow"))
        console.print(f"Author: {author} <netledger@example.net>")
        console.print(f"Date:   {when}\n")
        for index, line in enumerate(body.strip("\n").splitlines()):
            stripped = line.strip()
            style = (
                "bold" if index == 0 else "green" if stripped.startswith("A ") else "cyan" if stripped.startswith("M ")
                else "bold red" if stripped.startswith("Risk:") and "high" in stripped else "yellow" if stripped.startswith("Window:") else ""
            )
            console.print(Text("    " + line, style=style))
        console.print()
    console.save_svg(str(OUT / f"{name}.svg"), title="git log - backup repository")
    print(f"  wrote docs/images/{name}.svg")


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def browser() -> str | None:
    env = os.environ.get("NETLEDGER_SCREENSHOT_BROWSER")
    for candidate in ([env] if env else []) + BROWSERS:
        if candidate and Path(candidate).exists():
            return candidate
    return shutil.which("google-chrome") or shutil.which("chromium")


def shoot(exe: str, url: str, out: Path, width: int, height: int) -> None:
    profile = tempfile.mkdtemp(prefix="netledger-shot-")
    try:
        subprocess.run(
            [exe, "--headless=new", f"--user-data-dir={profile}", "--no-first-run", "--no-default-browser-check",
             "--disable-extensions", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=1",
             f"--window-size={width},{height}", "--virtual-time-budget=6000", f"--screenshot={out}", url],
            check=True, capture_output=True, timeout=120,
        )
    finally:
        shutil.rmtree(profile, ignore_errors=True)
    print(f"  wrote {out.relative_to(ROOT)}")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    workdir = Path(tempfile.mkdtemp(prefix="netledger-demo-"))
    os.environ["COLUMNS"] = "124"
    try:
        settings = demo.prepare(workdir / "demo")
        config = settings.config_path
        # Push to a real (local, bare) remote, but show it as a GitHub repository in the output.
        remote = workdir / "network-configs.git"
        subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
        data = yaml.safe_load(config.read_text(encoding="utf-8"))
        data["git"].update({"backend": "git", "url": remote.as_uri(), "web_url": WEB_URL})
        config.write_text(demo.MARKER + "\n" + yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        GitCLIStore.describe = lambda self: "github.com/your-org/network-configs@main"  # type: ignore[method-assign]
        settings = load_settings(config)
        args = ["-c", str(config), "--log-level", "ERROR"]

        print("six weeks of history")
        now = time.time()
        state = StateStore(settings.data_path / "state.json")
        demo.build_history(settings, state, end=now - 47 * 60)
        history = MetricsHistory.for_settings(settings)
        assert history is not None
        since = demo.backfill_health(settings, history)
        history.close()

        print("terminal screenshots")
        SimulatedDriver.revision = 2
        SimulatedDriver.latency_scale = 0.35
        record("cli-diff", "netledger backup --dry-run --diff", [*args, "backup", "--dry-run", "--diff", "-d", "hq-core-sw01"],
               prompt="netledger backup --dry-run --diff -d hq-core-sw01", width=100)
        with demo.simulated_time(now - 37 * 60):
            record("cli-backup", "netledger backup", [*args, "backup"], prompt="netledger backup")
        with demo.simulated_time(now - 4 * 60):
            devices = load_inventory(settings)
            BackupRunner(settings, StateStore(settings.data_path / "state.json")).run(devices, inventory=devices)
        record("cli-health", "netledger health", [*args, "health"], prompt="netledger health", width=132)
        demo.settle_health(StateStore(settings.data_path / "state.json"), since)
        record("cli-search", "netledger search 10.10.40.57", [*args, "search", "10.10.40.57"], prompt="netledger search 10.10.40.57", width=124)
        record("cli-platforms", "netledger platforms", [*args, "platforms"], prompt="netledger platforms", width=132)
        record_git_log(settings, "configs/hq/hq-core-sw01")

        exe = browser()
        if not exe:
            print("no Chrome/Edge found; skipping console screenshots")
            return 0
        print("console screenshots")
        state = StateStore(settings.data_path / "state.json")
        scheduler = Scheduler()
        scheduler.add("backup", IntervalSchedule(56 * 60), lambda: None)
        scheduler.add("health", IntervalSchedule(5 * 60 - 18), lambda: None)
        app = App(settings, state, scheduler, inventory_loader=lambda: [d.summary() for d in load_inventory(settings)])
        app.ready = True
        server = DashboardServer(app, "127.0.0.1", free_port())
        server.start()
        base = f"http://127.0.0.1:{server.port}"
        try:
            for name, path, width, height in PAGES:
                shoot(exe, base + path, OUT / f"{name}.png", width, height)
        finally:
            server.stop()
    finally:
        remove_tree(workdir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
