"""Device sessions: driver resolution, credential fallback, retries, per-device locks, parallelism."""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from typing import Any, Callable, Iterator, Sequence, TypeVar

from netledger.config import ConfigError, CredentialSet, Settings
from netledger.inventory import Device, resolve_credentials
from netledger.platforms import load_driver_class

log = logging.getLogger(__name__)

T = TypeVar("T")
R = TypeVar("R")

AUTH_HINTS = (
    "authentication failed",
    "authentication fail",
    "auth failed",
    "autherror",
    "unauthorized",
    "permission denied",
    "login failed",
    "login incorrect",
    "bad credentials",
    "access denied",
)


class DeviceError(Exception):
    """A device could not be reached, logged into, or did not answer as expected."""

    def __init__(self, message: str, kind: str = "error"):
        super().__init__(message)
        self.kind = kind


_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


def device_lock(name: str) -> threading.Lock:
    """One lock per device so backup and health jobs never open parallel sessions to it."""
    with _locks_guard:
        if name not in _locks:
            _locks[name] = threading.Lock()
        return _locks[name]


def is_auth_error(exc: BaseException) -> bool:
    if any("auth" in cls.__name__.lower() for cls in type(exc).__mro__):
        return True
    text = str(exc).lower()
    return any(hint in text for hint in AUTH_HINTS)


def describe_error(exc: BaseException) -> str:
    text = " ".join(line.strip() for line in str(exc).splitlines() if line.strip())
    if not text:
        return type(exc).__name__
    if len(text) > 400:
        text = text[:397] + "..."
    return text


def _safe_close(driver: Any) -> None:
    try:
        driver.close()
    except Exception:  # noqa: BLE001
        pass


def build_optional_args(device: Device, cred: CredentialSet, settings: Settings, driver_cls: Any) -> dict[str, Any]:
    platform = device.platform_info
    args = dict(device.optional_args)
    if device.port:
        args.setdefault("port", device.port)
    if cred.secret and platform.enable_arg:
        args.setdefault(platform.enable_arg, cred.secret)
    if cred.ssh_key:
        args.setdefault("use_keys", True)
        args.setdefault("key_file", str(settings.resolve_path(cred.ssh_key)))
        if cred.ssh_key_passphrase:
            args.setdefault("passphrase", cred.ssh_key_passphrase)
    if platform.netmiko_based:
        args.setdefault("read_timeout_override", float(settings.backup.command_timeout))
        args.setdefault("command_timeout", float(settings.backup.command_timeout))
    if getattr(driver_cls, "accepts_platform_hint", False):
        args["_netledger_platform"] = platform.key
        args["_netledger_device"] = device.name
    return args


def open_device(
    device: Device,
    settings: Settings,
    timeout: int | None = None,
    retries: int | None = None,
    retry_delay: float | None = None,
) -> Any:
    """Open a NAPALM driver for ``device``, trying each credential set in turn."""
    timeout = int(device.timeout or timeout or settings.backup.timeout)
    retries = settings.backup.retries if retries is None else retries
    delay = settings.backup.retry_delay if retry_delay is None else retry_delay
    try:
        driver_cls = load_driver_class(device.driver_spec)
    except Exception as exc:  # noqa: BLE001
        raise DeviceError(f"cannot load driver {device.driver_spec!r}: {describe_error(exc)}", "config") from exc
    try:
        credentials = resolve_credentials(device, settings)
    except ConfigError as exc:
        raise DeviceError(str(exc), "config") from exc

    auth_failures: list[str] = []
    for index, cred in enumerate(credentials):
        args = build_optional_args(device, cred, settings, driver_cls)
        attempt = 0
        while True:
            driver = driver_cls(device.host, cred.username or "", cred.password or "", timeout=timeout, optional_args=args)
            try:
                driver.open()
            except Exception as exc:  # noqa: BLE001 - drivers raise many exception types
                _safe_close(driver)
                if is_auth_error(exc):
                    auth_failures.append(f"{cred.username or '(no user)'}: {describe_error(exc)}")
                    break
                if attempt < retries:
                    attempt += 1
                    wait = delay * (2 ** (attempt - 1))
                    log.info("%s: connection failed (%s); retry %d/%d in %.0fs", device.name, describe_error(exc), attempt, retries, wait)
                    time.sleep(wait)
                    continue
                raise DeviceError(describe_error(exc), "connect") from exc
            if index:
                log.info("%s: logged in with fallback credential set #%d", device.name, index + 1)
            return driver
    raise DeviceError("authentication failed (" + "; ".join(auth_failures) + ")", "auth")


@contextmanager
def device_session(
    device: Device, settings: Settings, timeout: int | None = None, retries: int | None = None
) -> Iterator[Any]:
    with device_lock(device.name):
        driver = open_device(device, settings, timeout=timeout, retries=retries)
        try:
            yield driver
        finally:
            _safe_close(driver)


def run_parallel(items: Sequence[T], fn: Callable[[T], R], workers: int) -> Iterator[tuple[T, R]]:
    """Run ``fn`` over ``items`` in a thread pool, yielding ``(item, result)`` as each finishes."""
    if not items:
        return
    workers = max(1, min(int(workers), len(items)))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="netledger") as pool:
        futures = {pool.submit(fn, item): item for item in items}
        for future in as_completed(futures):
            yield futures[future], future.result()
