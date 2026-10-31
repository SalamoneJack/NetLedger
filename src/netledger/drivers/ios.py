"""Cisco IOS / IOS-XE: the NAPALM ios driver, keeping the configuration header.

NAPALM's ``get_config`` strips the ``! Last configuration change at ... by <user>`` line.
NetLedger removes volatile header lines itself (see ``ios.*`` rules) but reads them first,
so commit messages can say who made the change.
"""

from __future__ import annotations

from typing import Any

from napalm.ios.ios import IOSDriver as NapalmIOSDriver


class IOSDriver(NapalmIOSDriver):
    def get_config(
        self, retrieve: str = "all", full: bool = False, sanitized: bool = False, format: str = "text"
    ) -> dict[str, Any]:
        if sanitized:
            return super().get_config(retrieve=retrieve, full=full, sanitized=True, format=format)
        configs = {"startup": "", "running": "", "candidate": ""}
        if retrieve in ("startup", "all"):
            configs["startup"] = self._send_command("show startup-config").strip()
        if retrieve in ("running", "all"):
            configs["running"] = self._send_command("show running-config" + (" all" if full else "")).strip()
        return configs
