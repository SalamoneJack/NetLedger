"""Netmiko-backed NAPALM driver base class used by the built-in platform drivers."""

from __future__ import annotations

import logging
import re
from typing import Any

from napalm.base import NetworkDriver
from napalm.base.exceptions import (
    CommandErrorException,
    ConnectAuthError,
    ConnectionClosedException,
    ConnectionException,
)
from napalm.base.netmiko_helpers import netmiko_args

from netledger.drivers.parsing import hostname_from_prompt

log = logging.getLogger(__name__)

GENERIC_ERRORS = (
    r"% ?Invalid input",
    r"% ?Incomplete command",
    r"% ?Ambiguous command",
    r"% ?Unknown command",
    r"% ?Unrecognized command",
    r"^Invalid command",
    r"Unrecognized command",
    r"^Syntax error",
    r"command not found",
)


def empty_environment() -> dict[str, Any]:
    return {
        "fans": {},
        "temperature": {},
        "power": {},
        "cpu": {},
        "memory": {"available_ram": -1, "used_ram": -1},
    }


class CLIDriver(NetworkDriver):
    """A NAPALM driver implemented on top of Netmiko.

    Subclasses set the Netmiko device type and commands, and implement ``_facts`` and
    ``_environment``. Any value can be overridden per device through ``optional_args``:
    ``config_command``, ``startup_command``, ``full_config_command``, ``command_timeout``,
    ``netmiko_device_type`` and ``transport`` (``ssh``/``telnet``). Remaining Netmiko
    connection arguments (``ssh_config_file``, ``key_file``, ``disabled_algorithms``, ...)
    are passed through.
    """

    platform = "generic"
    vendor = ""
    netmiko_device_type = ""
    config_command: str | None = "show running-config"
    full_config_command: str | None = None
    startup_command: str | None = None
    candidate_command: str | None = None
    error_patterns: tuple[str, ...] = GENERIC_ERRORS
    needs_enable = False

    def __init__(
        self,
        hostname: str,
        username: str,
        password: str,
        timeout: int = 60,
        optional_args: dict[str, Any] | None = None,
    ) -> None:
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        args = dict(optional_args or {})
        self.optional_args = args
        cls = type(self)
        self.config_command = args.pop("config_command", cls.config_command)
        self.startup_command = args.pop("startup_command", cls.startup_command)
        self.full_config_command = args.pop("full_config_command", cls.full_config_command)
        self.candidate_command = args.pop("candidate_command", cls.candidate_command)
        self.command_timeout = float(args.pop("command_timeout", max(float(timeout) * 2, 120.0)))
        transport = str(args.pop("transport", "ssh")).lower()
        device_type = str(args.pop("netmiko_device_type", "") or cls.netmiko_device_type)
        if not device_type:
            raise ConnectionException(f"{cls.__name__}: no Netmiko device type configured (optional_args.netmiko_device_type)")
        if transport == "telnet" and not device_type.endswith("_telnet"):
            device_type = f"{device_type}_telnet"
        self.device_type = device_type
        connection = netmiko_args(args)
        connection.setdefault("port", 23 if transport == "telnet" else 22)
        connection.setdefault("conn_timeout", float(timeout))
        connection.setdefault("banner_timeout", max(15.0, float(timeout) / 2))
        connection.setdefault("auth_timeout", float(timeout))
        self._connection_args: dict[str, Any] = {
            "device_type": device_type,
            "host": hostname,
            "username": username,
            "password": password,
            "timeout": timeout,
            **connection,
        }
        self.device: Any = None
        self._prompt = ""
        self._cache: dict[str, str] = {}

    # ------------------------------------------------------------------ connection

    def open(self) -> None:
        from netmiko import ConnectHandler
        from netmiko.exceptions import NetmikoAuthenticationException

        try:
            self.device = ConnectHandler(**self._connection_args)
        except NetmikoAuthenticationException as exc:
            raise ConnectAuthError(f"authentication failed for {self.username}@{self.hostname}: {exc}") from exc
        except ValueError as exc:
            raise ConnectionException(f"{self.hostname}: {exc}") from exc
        except Exception as exc:  # noqa: BLE001 - normalize every transport error
            raise ConnectionException(f"{self.hostname}: {type(exc).__name__}: {exc}") from exc
        try:
            self._prompt = self.device.find_prompt()
        except Exception:  # noqa: BLE001
            self._prompt = getattr(self.device, "base_prompt", "") or ""
        if self.needs_enable:
            try:
                if not self.device.check_enable_mode():
                    self.device.enable()
            except Exception as exc:  # noqa: BLE001
                self.close()
                raise ConnectAuthError(f"{self.hostname}: could not enter privileged mode: {exc}") from exc
        self._after_open()

    def _after_open(self) -> None:
        """Hook for subclasses (detect modes, set output format, ...)."""

    def close(self) -> None:
        if self.device is not None:
            try:
                self.device.disconnect()
            except Exception:  # noqa: BLE001
                pass
            self.device = None

    def is_alive(self) -> dict[str, bool]:
        if self.device is None:
            return {"is_alive": False}
        try:
            return {"is_alive": bool(self.device.is_alive())}
        except Exception:  # noqa: BLE001
            return {"is_alive": False}

    # ------------------------------------------------------------------ commands

    def _is_error(self, output: str) -> bool:
        lines = [line for line in output.strip().splitlines() if line.strip()]
        if len(lines) > 8:
            return False
        head = "\n".join(lines[:4])
        return any(re.search(p, head, re.I | re.M) for p in self.error_patterns)

    def _send(self, command: str, raise_on_error: bool = True, use_cache: bool = False, **kwargs: Any) -> str:
        if use_cache and command in self._cache:
            return self._cache[command]
        if self.device is None:
            raise ConnectionClosedException(f"{self.hostname}: not connected")
        kwargs.setdefault("read_timeout", self.command_timeout)
        try:
            output = self.device.send_command(command, **kwargs)
        except OSError as exc:
            raise ConnectionClosedException(f"{self.hostname}: {exc}") from exc
        output = str(output)
        if raise_on_error and self._is_error(output):
            first = next((line.strip() for line in output.splitlines() if line.strip()), "")
            raise CommandErrorException(f"{command!r} failed: {first}")
        if use_cache:
            self._cache[command] = output
        return output

    def _try(self, command: str, **kwargs: Any) -> str | None:
        """Run a command, returning None (instead of raising) when the device rejects it."""
        try:
            return self._send(command, **kwargs)
        except CommandErrorException as exc:
            log.debug("%s: %s", self.hostname, exc)
            return None

    def cli(self, commands: list[str], encoding: str = "text") -> dict[str, str]:
        if encoding != "text":
            raise NotImplementedError("only text encoding is supported")
        return {command: self._send(command, raise_on_error=False) for command in commands}

    # ------------------------------------------------------------------ getters

    def _get_config_text(self, command: str, kind: str) -> str:
        return self._send(command)

    def get_config(
        self, retrieve: str = "all", full: bool = False, sanitized: bool = False, format: str = "text"
    ) -> dict[str, str]:
        configs = {"running": "", "startup": "", "candidate": ""}
        if retrieve in ("all", "running") and self.config_command:
            command = self.full_config_command if full and self.full_config_command else self.config_command
            configs["running"] = self._get_config_text(command, "running")
            self._cache["__running__"] = configs["running"]
        if retrieve in ("all", "startup") and self.startup_command:
            configs["startup"] = self._get_config_text(self.startup_command, "startup")
        if retrieve in ("all", "candidate") and self.candidate_command:
            configs["candidate"] = self._get_config_text(self.candidate_command, "candidate")
        return configs

    def _hostname(self) -> str:
        return hostname_from_prompt(self._prompt or getattr(self.device, "base_prompt", ""))

    def _facts(self) -> dict[str, Any]:
        return {}

    def get_facts(self) -> dict[str, Any]:
        facts: dict[str, Any] = {
            "uptime": -1.0,
            "vendor": self.vendor,
            "model": "",
            "hostname": self._hostname(),
            "fqdn": "",
            "os_version": "",
            "serial_number": "",
            "interface_list": [],
        }
        facts.update({k: v for k, v in self._facts().items() if v not in (None, "")})
        if facts.get("uptime") is None:
            facts["uptime"] = -1.0
        facts["uptime"] = float(facts["uptime"])
        if not facts["fqdn"]:
            facts["fqdn"] = facts["hostname"]
        return facts

    def _environment(self, env: dict[str, Any]) -> None:
        raise NotImplementedError(f"{type(self).__name__} does not support environment data")

    def get_environment(self) -> dict[str, Any]:
        env = empty_environment()
        self._environment(env)
        return env


def set_memory(env: dict[str, Any], total: int | None, used: int | None, percent: float | None = None) -> None:
    """Fill NAPALM memory fields (``available_ram`` is the total, as documented by NAPALM)."""
    if total and used is not None and total > 0:
        env["memory"] = {"available_ram": int(total), "used_ram": int(used)}
    elif percent is not None:
        env["memory"] = {"available_ram": -1, "used_ram": -1, "%usage": float(percent)}


def set_cpu(env: dict[str, Any], values: list[float] | dict[Any, float]) -> None:
    items = values.items() if isinstance(values, dict) else enumerate(values)
    env["cpu"] = {key: {"%usage": float(value)} for key, value in items if value is not None}


def add_temperature(
    env: dict[str, Any],
    name: str,
    value: float | None,
    alert: bool = False,
    critical: bool = False,
    warn_at: float | None = None,
    crit_at: float | None = None,
) -> None:
    if value is None:
        return
    is_critical = critical or (crit_at is not None and value >= crit_at)
    is_alert = alert or is_critical or (warn_at is not None and value >= warn_at)
    env["temperature"][name] = {"temperature": float(value), "is_alert": bool(is_alert), "is_critical": bool(is_critical)}


def add_fan(env: dict[str, Any], name: str, ok: bool | None) -> None:
    if ok is not None:
        env["fans"][name] = {"status": bool(ok)}


def add_psu(env: dict[str, Any], name: str, ok: bool | None, capacity: float = -1.0, output: float = -1.0) -> None:
    if ok is not None:
        env["power"][name] = {"status": bool(ok), "capacity": float(capacity), "output": float(output)}
