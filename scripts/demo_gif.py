"""Record the README demo GIF from the built-in demo (simulated devices, nothing real).

    pip install playwright           # drives your installed Chrome/Edge; no browser download needed
    python scripts/demo_gif.py       # writes docs/images/demo.gif (needs ffmpeg on PATH)

The browser runs headless with a temporary profile. Each step is captured as a crisp screenshot and
ffmpeg turns the sequence into a looping GIF with per-frame timing.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import screenshots as shots  # noqa: E402  (also puts src/ on sys.path)

from netledger import demo  # noqa: E402
from netledger.backup import BackupRunner  # noqa: E402
from netledger.config import Settings, load_settings  # noqa: E402
from netledger.drivers.simulated import SimulatedDriver  # noqa: E402
from netledger.health import HealthRunner  # noqa: E402
from netledger.history import MetricsHistory  # noqa: E402
from netledger.inventory import load_inventory  # noqa: E402
from netledger.scheduler import IntervalSchedule, Scheduler  # noqa: E402
from netledger.server import App, DashboardServer  # noqa: E402
from netledger.state import StateStore  # noqa: E402
from netledger.storage.gitcli import GitCLIStore, remove_tree  # noqa: E402

OUT = shots.OUT / "demo.gif"
VIEWPORT = {"width": 1440, "height": 900}
GIF_WIDTH = 1200


def environment(workdir: Path) -> Settings:
    """The demo network with six weeks of history, shown as a GitHub repository."""
    settings = demo.prepare(workdir / "demo")
    config = settings.config_path
    remote = workdir / "network-configs.git"
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
    data = yaml.safe_load(config.read_text(encoding="utf-8"))
    data["git"].update({"backend": "git", "url": remote.as_uri(), "web_url": shots.WEB_URL})
    config.write_text(demo.MARKER + "\n" + yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    GitCLIStore.describe = lambda self: "github.com/your-org/network-configs@main"  # type: ignore[method-assign]
    settings = load_settings(config)

    now = time.time()
    path = settings.data_path / "state.json"
    demo.build_history(settings, StateStore(path), end=now - 47 * 60)
    history = MetricsHistory.for_settings(settings)
    assert history is not None
    since = demo.backfill_health(settings, history)
    history.close()
    SimulatedDriver.revision = 2
    SimulatedDriver.latency_scale = 0.2
    devices = load_inventory(settings)
    with demo.simulated_time(now - 37 * 60):
        BackupRunner(settings, StateStore(path)).run(devices, inventory=devices)
    with demo.simulated_time(now - 4 * 60):
        BackupRunner(settings, StateStore(path)).run(devices, inventory=devices)
    HealthRunner(settings, StateStore(path)).run(devices)
    demo.settle_health(StateStore(path), since)
    return settings


def record(base: str, frames_dir: Path, executable: str) -> list[tuple[Path, float]]:
    from playwright.sync_api import sync_playwright

    frames: list[tuple[Path, float]] = []

    def snap(page, seconds: float) -> None:  # noqa: ANN001
        target = frames_dir / f"frame{len(frames):03d}.png"
        page.screenshot(path=str(target))
        frames.append((target, seconds))

    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=executable, headless=True, args=["--hide-scrollbars", "--disable-extensions"])
        page = browser.new_context(viewport=VIEWPORT, device_scale_factor=1).new_page()

        page.goto(base + "/", wait_until="networkidle")
        page.wait_for_timeout(900)
        snap(page, 2.8)

        # Ctrl+K: type an address and ask where it lives
        page.keyboard.press("Control+K")
        page.wait_for_selector(".pal input")
        page.wait_for_timeout(250)
        snap(page, 0.45)
        address = "10.10.40.57"
        for index, char in enumerate(address):
            page.keyboard.type(char)
            if index % 2 == 1 or index == len(address) - 1:
                page.wait_for_timeout(60)
                snap(page, 0.13)
        page.wait_for_timeout(150)
        snap(page, 1.1)
        page.keyboard.press("Enter")
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(300)
        snap(page, 3.2)

        # straight to the configuration line in the time machine
        page.click(".best a.dev >> nth=0")
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(1100)
        snap(page, 2.8)

        # what changed, and how risky it was
        page.click('[data-tm-view] button[data-v="diff"]')
        page.wait_for_timeout(800)
        page.evaluate("document.querySelector('#timemachine').scrollIntoView({block: 'start'})")
        page.wait_for_timeout(300)
        snap(page, 3.2)
        page.click(".tm-list .v:has-text('ip route')")
        page.wait_for_timeout(900)
        snap(page, 2.6)

        page.goto(base + "/changes", wait_until="networkidle")
        page.wait_for_timeout(300)
        snap(page, 2.8)

        page.goto(base + "/topology", wait_until="networkidle")
        page.wait_for_timeout(1000)
        snap(page, 1.2)
        page.locator(".topo .node", has_text="hq-core-sw01").first.hover()
        page.wait_for_timeout(400)
        snap(page, 2.2)
        page.mouse.move(8, 8)
        page.click("[data-theme-toggle]")
        page.wait_for_timeout(500)
        snap(page, 2.0)
        page.goto(base + "/", wait_until="networkidle")
        page.wait_for_timeout(900)
        snap(page, 3.0)
        browser.close()
    return frames


def encode(frames: list[tuple[Path, float]], out: Path) -> None:
    listing = frames[0][0].parent / "frames.txt"
    lines = []
    for path, seconds in frames:
        lines += [f"file '{path.as_posix()}'", f"duration {seconds}"]
    lines.append(f"file '{frames[-1][0].as_posix()}'")
    listing.write_text("\n".join(lines) + "\n", encoding="utf-8")
    # One palette for the whole animation: per-frame palettes and frame differencing corrupt colours.
    graph = (
        f"scale={GIF_WIDTH}:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=256:stats_mode=full[p];"
        "[b][p]paletteuse=dither=sierra2_4a"
    )
    subprocess.run(
        ["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", str(listing), "-vf", graph,
         "-fps_mode", "vfr", "-loop", "0", str(out)],
        check=True,
    )


def main() -> int:
    exe = shots.browser()
    if not exe or not shutil.which("ffmpeg"):
        print("needs Chrome/Edge and ffmpeg")
        return 1
    workdir = Path(tempfile.mkdtemp(prefix="netledger-gif-"))
    try:
        settings = environment(workdir)
        scheduler = Scheduler()
        scheduler.add("backup", IntervalSchedule(56 * 60), lambda: None)
        scheduler.add("health", IntervalSchedule(5 * 60 - 18), lambda: None)
        app = App(settings, StateStore(settings.data_path / "state.json"), scheduler,
                  inventory_loader=lambda: [d.summary() for d in load_inventory(settings)])
        app.ready = True
        server = DashboardServer(app, "127.0.0.1", shots.free_port())
        server.start()
        try:
            frames_dir = workdir / "frames"
            frames_dir.mkdir()
            frames = record(f"http://127.0.0.1:{server.port}", frames_dir, exe)
        finally:
            server.stop()
        encode(frames, OUT)
        print(f"wrote {OUT.relative_to(shots.ROOT)} ({OUT.stat().st_size / 1e6:.1f} MB, {len(frames)} frames)")
    finally:
        remove_tree(workdir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
