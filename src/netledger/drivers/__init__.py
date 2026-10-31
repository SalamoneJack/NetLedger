"""Built-in NAPALM drivers for platforms that NAPALM core does not cover (or covers poorly).

Every driver subclasses :class:`napalm.base.NetworkDriver`, so they plug into the same
``open() / get_config() / get_facts() / get_environment() / cli() / close()`` workflow as the
core NAPALM drivers. Output parsing lives in pure functions so it can be unit tested without
hardware.
"""

from netledger.drivers.base import CLIDriver, empty_environment

__all__ = ["CLIDriver", "empty_environment"]
