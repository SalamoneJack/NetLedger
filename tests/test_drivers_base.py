"""Built-in driver plumbing with a fake Netmiko connection."""

from __future__ import annotations

from typing import Any

import pytest
from napalm.base.exceptions import CommandErrorException, ConnectAuthError, ConnectionException

from netledger.drivers.fortinet import FortiOSDriver
from netledger.drivers.generic import GenericDriver
from netledger.drivers.mikrotik import RouterOSDriver


class FakeConnection:
    def __init__(self, outputs: dict[str, str], prompt: str = "dev#", **kwargs: Any):
        self.outputs = outputs
        self.prompt = prompt
        self.kwargs = kwargs
        self.sent: list[tuple[str, dict[str, Any]]] = []
        self.base_prompt = prompt.rstrip("#> ")
        self._vdoms = kwargs.pop("_vdoms", False)
        self.prompt_pattern = r"[#$]"

    def find_prompt(self) -> str:
        return self.prompt

    def send_command(self, command: str, **kwargs: Any) -> str:
        self.sent.append((command, kwargs))
        return self.outputs.get(command, "")

    def is_alive(self) -> bool:
        return True

    def disconnect(self) -> None:
        pass

    def check_enable_mode(self) -> bool:
        return True


def connect(monkeypatch: pytest.MonkeyPatch, outputs: dict[str, str], **conn: Any) -> list[dict[str, Any]]:
    created: list[dict[str, Any]] = []

    def handler(**kwargs: Any) -> FakeConnection:
        created.append(kwargs)
        return FakeConnection(outputs, **conn)

    monkeypatch.setattr("netmiko.ConnectHandler", handler)
    return created


def test_connection_arguments_and_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    created = connect(monkeypatch, {"display current": "sysname x\n"})
    driver = GenericDriver("10.0.0.1", "u", "p", timeout=20, optional_args={
        "netmiko_device_type": "huawei", "config_command": "display current", "port": 2222,
        "ssh_config_file": "~/.ssh/config", "transport": "telnet", "not_a_netmiko_arg": 1,
    })
    driver.open()
    kwargs = created[0]
    assert kwargs["device_type"] == "huawei_telnet" and kwargs["port"] == 2222 and kwargs["ssh_config_file"] == "~/.ssh/config"
    assert kwargs["conn_timeout"] == 20.0 and "not_a_netmiko_arg" not in kwargs
    assert driver.get_config(retrieve="running")["running"] == "sysname x\n"
    assert driver.get_facts()["hostname"] == "dev"
    with pytest.raises(NotImplementedError):
        driver.get_environment()


def test_command_errors_are_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    connect(monkeypatch, {"show bogus": "             ^\n% Invalid input detected at '^' marker.\n"})
    driver = GenericDriver("h", "u", "p", optional_args={"netmiko_device_type": "cisco_ios"})
    driver.open()
    with pytest.raises(CommandErrorException):
        driver._send("show bogus")
    assert driver._try("show bogus") is None
    assert driver.cli(["show bogus"])["show bogus"].strip().endswith("marker.")


def test_open_maps_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

    def auth_fail(**_: Any) -> None:
        raise NetmikoAuthenticationException("Authentication to device failed.")

    def timeout(**_: Any) -> None:
        raise NetmikoTimeoutException("TCP connection to device failed.")

    driver = GenericDriver("h", "u", "p", optional_args={"netmiko_device_type": "cisco_ios"})
    monkeypatch.setattr("netmiko.ConnectHandler", auth_fail)
    with pytest.raises(ConnectAuthError):
        driver.open()
    monkeypatch.setattr("netmiko.ConnectHandler", timeout)
    with pytest.raises(ConnectionException, match="TCP connection"):
        driver.open()


def test_fortios_global_context_when_vdoms(monkeypatch: pytest.MonkeyPatch) -> None:
    outputs = {
        "get system status": "Version: FortiGate-200F v7.4.3,build2573,240201 (GA.F)\nSerial-Number: FG200F123\nHostname: fw1\n",
        "get system performance status": "CPU states: 5% user 1% system 0% nice 94% idle\nMemory: 1000k total, 400k used (40.0%)\nUptime: 2 days,  3 hours,  4 minutes\n",
        "execute sensor list": "10 DTS CPU0         alarm=0  value=45  threshold_status=0\n",
    }
    connect(monkeypatch, outputs, prompt="fw1 #", _vdoms=True)
    driver = FortiOSDriver("h", "u", "p")
    driver.open()
    facts = driver.get_facts()
    env = driver.get_environment()
    sent = [command for command, _ in driver.device.sent]
    assert facts["model"] == "FortiGate-200F" and facts["uptime"] == 2 * 86400 + 3 * 3600 + 240
    assert env["cpu"] == {0: {"%usage": 6.0}} and env["memory"] == {"available_ram": 1024000, "used_ram": 409600}
    assert env["temperature"]["DTS CPU0"]["temperature"] == 45.0
    assert sent[:3] == ["config global", "get system status", "end"]
    assert sent.count("get system performance status") == 1  # cached between facts and environment


def test_routeros_show_sensitive_on_v7(monkeypatch: pytest.MonkeyPatch) -> None:
    connect(monkeypatch, {"/system resource print": "   version: 7.14.3 (stable)\n"}, prompt="[admin@r1] >")
    driver = RouterOSDriver("h", "u", "p", optional_args={"show_sensitive": True})
    driver.open()
    assert driver.config_command == "/export terse show-sensitive"
