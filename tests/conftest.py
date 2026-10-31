from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable

import pytest
import yaml

from netledger.config import Settings, load_settings
from netledger.drivers.simulated import SimulatedDriver

HAS_GIT = shutil.which("git") is not None
needs_git = pytest.mark.skipif(not HAS_GIT, reason="git executable not available")


@pytest.fixture(autouse=True)
def _reset_simulation(monkeypatch: pytest.MonkeyPatch) -> None:
    SimulatedDriver.revision = 1
    monkeypatch.setattr(SimulatedDriver, "revision", 1)
    monkeypatch.setattr(SimulatedDriver, "revisions", {})
    monkeypatch.setattr(SimulatedDriver, "epoch", 99)
    monkeypatch.setattr(SimulatedDriver, "latency_scale", 1.0)
    monkeypatch.setattr(SimulatedDriver, "clock", None)
    for var in ("NETLEDGER_CONFIG", "NETLEDGER_DATA_DIR", "NETLEDGER_ENV_FILE", "NETLEDGER_USERNAME", "NETLEDGER_PASSWORD"):
        monkeypatch.delenv(var, raising=False)


def simulated(name: str, platform: str, **args: Any) -> dict[str, Any]:
    return {
        "name": name,
        "host": f"192.0.2.{abs(hash(name)) % 200 + 10}",
        "platform": platform,
        "driver": "simulated",
        "optional_args": {"latency": 0, **args},
    }


@pytest.fixture
def make_env(tmp_path: Path) -> Callable[..., Settings]:
    """Write netledger.yaml + inventory.yaml into tmp_path and load them."""

    def factory(devices: list[dict[str, Any]], **config: Any) -> Settings:
        base: dict[str, Any] = {
            "inventory": ["inventory.yaml"],
            "credentials": {"default": {"username": "u", "password": "p"}},
            "git": {"backend": "local"},
            "backup": {"workers": 4},
        }
        for key, value in config.items():
            if isinstance(value, dict) and isinstance(base.get(key), dict):
                base[key] = {**base[key], **value}
            else:
                base[key] = value
        (tmp_path / "netledger.yaml").write_text(yaml.safe_dump(base), encoding="utf-8")
        (tmp_path / "inventory.yaml").write_text(yaml.safe_dump({"devices": devices}), encoding="utf-8")
        return load_settings(tmp_path / "netledger.yaml")

    return factory


@pytest.fixture
def bare_remote(tmp_path: Path) -> str:
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
    return remote.as_uri()


def git(cwd: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        cwd=str(cwd), capture_output=True, text=True, check=True,
    )
    return result.stdout
