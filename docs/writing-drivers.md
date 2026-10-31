# Writing a driver

Adding a platform takes three pieces:

1. **A NAPALM driver.** Use an existing NAPALM driver, or write a class on top of
   `netledger.drivers.base.CLIDriver` (Netmiko under the hood).
2. **A platform entry** in `src/netledger/platforms.py`: name, aliases, file extension and
   normalization rules.
3. **Tests** with real (sanitized) command output in `tests/test_parsers.py`.

## 1. The driver

```python
# src/netledger/drivers/acme.py
from __future__ import annotations

import re
from typing import Any

from netledger.drivers.base import CLIDriver, add_fan, add_temperature, set_cpu, set_memory
from netledger.drivers.parsing import parse_duration, search


def parse_version(text: str) -> dict[str, Any]:
    """Pure function: easy to unit test without hardware."""
    return {
        "os_version": search(r"^Software:\s*(\S+)", text) or "",
        "model": search(r"^Model:\s*(\S+)", text) or "",
        "serial_number": search(r"^Serial:\s*(\S+)", text) or "",
        "uptime": parse_duration(search(r"^Uptime:\s*(.+)$", text)),
    }


class AcmeOSDriver(CLIDriver):
    platform = "acmeos"
    vendor = "Acme"
    netmiko_device_type = "cisco_ios"          # closest Netmiko type for the CLI behaviour
    config_command = "show configuration"
    startup_command = "show startup-configuration"
    error_patterns = (r"^% Unknown command",)   # first lines that mean "command failed"
    needs_enable = False

    def _facts(self) -> dict[str, Any]:
        # use_cache=True: get_facts and get_environment can share one command
        return parse_version(self._send("show version", use_cache=True))

    def _environment(self, env: dict[str, Any]) -> None:
        cpu = search(r"CPU:\s*(\d+)%", self._try("show cpu") or "")   # _try: None if unsupported
        if cpu:
            set_cpu(env, [float(cpu)])
        set_memory(env, total=8 * 1024**3, used=2 * 1024**3)            # bytes (or percent=...)
        add_temperature(env, "Inlet", 31.0, warn_at=60, crit_at=75)
        add_fan(env, "Fan 1", ok=True)
```

What `CLIDriver` gives you:

- Connection handling, mapping Netmiko errors to NAPALM's `ConnectAuthError` / `ConnectionException`,
  telnet support (`optional_args.transport`) and every Netmiko connection option.
- `get_config()` built from `config_command` / `startup_command` / `candidate_command` /
  `full_config_command`. Each one can be overridden per device through `optional_args`.
- `get_facts()` defaults (hostname from the prompt) merged with your `_facts()`.
- `get_environment()` calling your `_environment()`. Raise `NotImplementedError` (the default) if
  the platform has no health data; NetLedger then checks reachability only.
- `cli()`, used for `backup.commands`.
- `self._send(cmd)` raises `CommandErrorException` when the output looks like an error;
  `self._try(cmd)` returns `None` instead.

Return values follow NAPALM's models: `available_ram` is **total** memory in bytes, CPU values are
percentages, temperatures are Celsius with `is_alert`/`is_critical`.

## 2. The platform entry

```python
Platform(
    "acmeos", "Acme OS", "Acme", "netledger.drivers.acme:AcmeOSDriver",
    aliases=("acme", "acme_os"),
    extension="cfg",
    volatile=(
        Rule("acmeos.generated", r"^! Generated at .*$"),            # drop the line
        Rule("acmeos.counter", r"(config-revision )\d+", r"\1<n>"),  # rewrite part of it
    ),
    secrets=(
        SecretRule("acmeos.user", r"^user \S+ password (?P<secret>\S+)"),
    ),
    meta=(r"^! Changed by (?P<changed_by>\S+) at (?P<changed_at>.+)$",),
    startup=True,
    enable_arg=None,          # optional_args key for the enable password, if any
),
```

- **volatile** rules keep Git history clean: anything that changes without a real configuration
  change (timestamps, counters, re-encrypted values). `replace=None` drops matching lines.
- **secrets** rules need a `(?P<secret>…)` group; they are applied when `normalize.secrets` is `mask`
  or `hmac`, and always to notification and dashboard diffs.
- **meta** patterns extract `changed_by` / `changed_at` for commit messages.
- Rule IDs must be unique: users can disable them with `normalize.disable_rules`.

Out-of-tree drivers work without touching NetLedger. Point a device at your class
(`driver: mypackage.drivers:MyDriver`) or register a platform from your own code with
`netledger.platforms.register_platform(Platform(...))`.

## 3. Tests

```python
def test_acme_version() -> None:
    sample = "Software: 4.2.1\nModel: AX-9000\nSerial: ABC123\nUptime: 3 days, 4 hours\n"
    assert parse_version(sample) == {
        "os_version": "4.2.1", "model": "AX-9000", "serial_number": "ABC123", "uptime": 3 * 86400 + 4 * 3600,
    }
```

Also add a normalization test if you added rules (see `tests/test_normalize.py`), and try the
simulated end-to-end flow with `netledger demo` or the `simulated` driver.
