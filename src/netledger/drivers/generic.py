"""Generic driver: back up any of Netmiko's 200+ device types with a single command.

Example inventory entry::

    - name: core-xr1
      host: 10.0.0.9
      platform: generic
      optional_args:
        netmiko_device_type: cisco_xr
        config_command: show running-config
"""

from __future__ import annotations

from typing import Any

from netledger.drivers.base import CLIDriver


class GenericDriver(CLIDriver):
    platform = "generic"
    vendor = "Generic"
    netmiko_device_type = ""
    config_command = "show running-config"

    def _environment(self, env: dict[str, Any]) -> None:
        raise NotImplementedError("the generic driver has no health data; connectivity is still checked")
