"""Inventory: device model, YAML / CSV / NetBox sources, group inheritance and filters."""

from __future__ import annotations

import csv
import fnmatch
import glob
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml

from netledger.config import ConfigError, CredentialSet, GitSettings, InventorySource, Settings, interpolate
from netledger.platforms import Platform, custom_platform, get_platform, resolve_platform
from netledger.utils import deep_merge, safe_path_component, slugify, unique

log = logging.getLogger(__name__)

DEVICE_FIELDS = frozenset({
    "name", "host", "platform", "driver", "port", "site", "role", "description", "groups", "tags",
    "credentials", "username", "password", "secret", "optional_args", "timeout", "backup", "health",
    "retrieve", "commands", "vars", "enabled",
})
GROUP_FIELDS = (DEVICE_FIELDS - {"name", "host"}) | {"groups"}
RETRIEVE_KINDS = ("running", "startup", "candidate")


@dataclass
class Device:
    name: str
    host: str
    platform: str
    driver: str | None = None
    port: int | None = None
    site: str = ""
    role: str = ""
    description: str = ""
    groups: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    credentials: list[str] = field(default_factory=lambda: ["default"])
    username: str | None = None
    password: str | None = None
    secret: str | None = None
    optional_args: dict[str, Any] = field(default_factory=dict)
    timeout: int | None = None
    backup: bool = True
    health: bool = True
    health_settings: dict[str, Any] = field(default_factory=dict)
    retrieve: list[str] | None = None
    commands: list[Any] = field(default_factory=list)
    vars: dict[str, Any] = field(default_factory=dict)
    source: str = ""
    collector: str = ""  # "oxidized": configurations come from Oxidized, NetLedger does not log in to back up
    oxidized: dict[str, Any] = field(default_factory=dict)  # the Oxidized node behind the device

    @property
    def platform_info(self) -> Platform:
        try:
            return get_platform(self.platform)
        except KeyError:
            return custom_platform(self.platform, self.driver or self.platform)

    @property
    def driver_spec(self) -> str:
        return self.driver or self.platform_info.driver

    def template_vars(self) -> dict[str, str]:
        info = self.platform_info
        return {
            "name": safe_path_component(self.name),
            "host": safe_path_component(self.host),
            "site": safe_path_component(self.site or "unassigned"),
            "role": safe_path_component(self.role or "unassigned"),
            "platform": safe_path_component(info.key),
            "vendor": safe_path_component(slugify(info.vendor) if info.vendor else "unknown"),
            "group": safe_path_component(self.groups[-1] if self.groups else "ungrouped"),
        }

    def summary(self) -> dict[str, Any]:
        """Public, secret-free description of the device."""
        info = self.platform_info
        data = {
            "name": self.name,
            "host": self.host,
            "platform": info.key,
            "platform_name": info.name,
            "vendor": info.vendor,
            "site": self.site,
            "role": self.role,
            "groups": list(self.groups),
            "tags": list(self.tags),
            "description": self.description,
            "backup": self.backup,
            "health": self.health,
        }
        if self.collector:
            data["collector"] = self.collector
        return data


# --------------------------------------------------------------------------- parsing helpers


def _as_list(value: Any, where: str, what: str) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, str):
        return [part.strip() for part in re.split(r"[,;|]", value) if part.strip()]
    if isinstance(value, (list, tuple)):
        return [str(part).strip() for part in value if str(part).strip()]
    raise ConfigError(f"{where}: '{what}' must be a list or a comma-separated string")


def _as_bool(value: Any, where: str, what: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "yes", "on", "1", "false", "no", "off", "0"):
        return value.strip().lower() in ("true", "yes", "on", "1")
    if isinstance(value, int):
        return bool(value)
    raise ConfigError(f"{where}: '{what}' must be true or false")


def _as_int(value: Any, where: str, what: str) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ConfigError(f"{where}: '{what}' must be an integer (got {value!r})") from None


def build_device(raw: dict[str, Any], where: str) -> Device:
    unknown = set(raw) - DEVICE_FIELDS
    if unknown:
        raise ConfigError(
            f"{where}: unknown field(s) {', '.join(sorted(unknown))}. Valid fields: {', '.join(sorted(DEVICE_FIELDS))}"
        )
    name = str(raw.get("name") or "").strip()
    if not name:
        raise ConfigError(f"{where}: device is missing 'name'")
    where = f"{where} ({name})"
    platform_raw = str(raw.get("platform") or "").strip()
    driver = str(raw["driver"]).strip() if raw.get("driver") else None
    if not platform_raw and not driver:
        raise ConfigError(f"{where}: device is missing 'platform'")
    key = resolve_platform(platform_raw) if platform_raw else None
    if key is None:
        if not driver:
            raise ConfigError(
                f"{where}: unknown platform {platform_raw!r}. Run 'netledger platforms' to list supported "
                "platforms, or set 'driver' to use any NAPALM driver."
            )
        key = platform_raw or driver

    health_raw = raw.get("health", True)
    health_settings: dict[str, Any] = {}
    if isinstance(health_raw, dict):
        health_settings = dict(health_raw)
        health_enabled = _as_bool(health_settings.pop("enabled", True), where, "health.enabled")
        unknown_health = set(health_settings) - {"thresholds", "ignore_sensors"}
        if unknown_health:
            raise ConfigError(f"{where}: unknown health setting(s) {sorted(unknown_health)}")
    else:
        health_enabled = _as_bool(health_raw, where, "health")

    retrieve = None
    if raw.get("retrieve") not in (None, ""):
        retrieve = _as_list(raw.get("retrieve"), where, "retrieve")
        bad = [r for r in retrieve if r not in RETRIEVE_KINDS]
        if bad:
            raise ConfigError(f"{where}: retrieve accepts {', '.join(RETRIEVE_KINDS)} (got {bad})")

    commands = raw.get("commands") or []
    if isinstance(commands, (str, dict)):
        commands = [commands]
    for entry in commands:
        if not (isinstance(entry, str) or (isinstance(entry, dict) and entry.get("command"))):
            raise ConfigError(f"{where}: each entry in 'commands' must be a string or have a 'command' key")

    for mapping in ("optional_args", "vars"):
        if raw.get(mapping) is not None and not isinstance(raw.get(mapping), dict):
            raise ConfigError(f"{where}: '{mapping}' must be a mapping")

    credentials = _as_list(raw.get("credentials"), where, "credentials") or ["default"]
    host = str(raw.get("host") or name).strip()
    return Device(
        name=name,
        host=host,
        platform=key,
        driver=driver,
        port=_as_int(raw.get("port"), where, "port"),
        site=str(raw.get("site") or ""),
        role=str(raw.get("role") or ""),
        description=str(raw.get("description") or ""),
        groups=_as_list(raw.get("groups"), where, "groups"),
        tags=_as_list(raw.get("tags"), where, "tags"),
        credentials=credentials,
        username=str(raw["username"]) if raw.get("username") else None,
        password=str(raw["password"]) if raw.get("password") is not None else None,
        secret=str(raw["secret"]) if raw.get("secret") else None,
        optional_args=dict(raw.get("optional_args") or {}),
        timeout=_as_int(raw.get("timeout"), where, "timeout"),
        backup=_as_bool(raw.get("backup", True), where, "backup"),
        health=health_enabled,
        health_settings=health_settings,
        retrieve=retrieve,
        commands=list(commands),
        vars=dict(raw.get("vars") or {}),
    )


def _merge_layers(layers: Iterable[dict[str, Any]]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for layer in layers:
        for key, value in layer.items():
            if key == "groups":
                continue
            if key == "tags":
                merged["tags"] = unique(_as_list(merged.get("tags"), "", "tags") + _as_list(value, "", "tags"))
            elif isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = deep_merge(merged[key], value)
            else:
                merged[key] = value
    return merged


def _expand_groups(
    names: list[str], groups: dict[str, dict[str, Any]], where: str, trail: tuple[str, ...] = ()
) -> list[str]:
    result: list[str] = []
    for name in names:
        if name in trail:
            raise ConfigError(f"{where}: group inheritance loop: {' -> '.join((*trail, name))}")
        if name not in groups:
            raise ConfigError(f"{where}: unknown group {name!r}")
        parents = _as_list(groups[name].get("groups"), where, f"groups.{name}.groups")
        result.extend(_expand_groups(parents, groups, where, (*trail, name)))
        result.append(name)
    return unique(result)


# --------------------------------------------------------------------------- sources


def load_yaml_inventory(path: Path, defaults: dict[str, Any] | None = None) -> list[Device]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML: {exc}") from exc
    if isinstance(data, list):
        data = {"devices": data}
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: expected a mapping with 'devices'")
    unknown = set(data) - {"defaults", "groups", "devices"}
    if unknown:
        raise ConfigError(f"{path}: unknown top-level key(s) {sorted(unknown)} (expected defaults, groups, devices)")
    data = interpolate(data, path.parent, path.name)

    file_defaults = deep_merge(defaults or {}, data.get("defaults") or {})
    groups = data.get("groups") or {}
    if not isinstance(groups, dict):
        raise ConfigError(f"{path}: 'groups' must be a mapping of group name to settings")
    for gname, gdata in list(groups.items()):
        groups[gname] = gdata = gdata or {}
        bad = set(gdata) - GROUP_FIELDS
        if bad:
            raise ConfigError(f"{path}: group {gname!r} has unknown field(s) {sorted(bad)}")

    raw_devices = data.get("devices") or []
    if isinstance(raw_devices, dict):
        raw_devices = [{"name": name, **(attrs or {})} for name, attrs in raw_devices.items()]
    devices = []
    for index, raw in enumerate(raw_devices):
        where = f"{path.name}: devices[{index}]"
        if not isinstance(raw, dict):
            raise ConfigError(f"{where}: each device must be a mapping")
        member_of = _as_list(file_defaults.get("groups"), where, "groups") + _as_list(raw.get("groups"), where, "groups")
        expanded = _expand_groups(unique(member_of), groups, where)
        merged = _merge_layers([file_defaults, *(groups[g] for g in expanded), raw])
        merged["groups"] = expanded
        if merged.get("enabled", True) in (False, "false", "no", 0):
            continue
        merged.pop("enabled", None)
        device = build_device(merged, where)
        device.source = str(path)
        devices.append(device)
    return devices


def _csv_scalar(value: str) -> Any:
    lowered = value.lower()
    if lowered in ("true", "yes"):
        return True
    if lowered in ("false", "no"):
        return False
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    return value


def load_csv_inventory(path: Path, defaults: dict[str, Any] | None = None) -> list[Device]:
    devices = []
    with path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        for line_no, row in enumerate(reader, start=2):
            raw: dict[str, Any] = {}
            for key, value in row.items():
                if key is None:
                    continue
                key, value = key.strip(), (value or "").strip()
                if not key or value == "" or key.startswith("#"):
                    continue
                if "." in key:
                    top, sub = key.split(".", 1)
                    raw.setdefault(top, {})[sub] = _csv_scalar(value)
                else:
                    raw[key] = value
            if not raw or str(raw.get("name", "")).startswith("#"):
                continue
            merged = _merge_layers([defaults or {}, raw])
            merged["groups"] = unique(_as_list((defaults or {}).get("groups"), "", "groups") + _as_list(raw.get("groups"), "", "groups"))
            if str(merged.get("enabled", "true")).lower() in ("false", "no", "0"):
                continue
            merged.pop("enabled", None)
            merged = interpolate(merged, path.parent, path.name)
            device = build_device(merged, f"{path.name}:{line_no}")
            device.source = str(path)
            devices.append(device)
    return devices


def load_netbox_inventory(source: InventorySource) -> list[Device]:
    import requests

    base = (source.url or "").rstrip("/")
    session = requests.Session()
    session.headers.update({"Accept": "application/json", "User-Agent": "netledger"})
    if source.token:
        session.headers["Authorization"] = f"{source.auth_scheme} {source.token}"

    def fetch(endpoint: str) -> list[dict[str, Any]]:
        url: str | None = f"{base}{endpoint}"
        params: dict[str, Any] | None = {**source.filters, "limit": 1000}
        items: list[dict[str, Any]] = []
        while url:
            try:
                resp = session.get(url, params=params, timeout=source.timeout, verify=source.verify_ssl)
                resp.raise_for_status()
            except requests.RequestException as exc:
                raise ConfigError(f"NetBox inventory {base}: {exc}") from exc
            data = resp.json()
            items.extend(data.get("results", []))
            url, params = data.get("next"), None
        return items

    items = fetch("/api/dcim/devices/")
    if source.include_virtual_machines:
        items += fetch("/api/virtualization/virtual-machines/")

    devices = []
    for item in items:
        name = item.get("name")
        if not name:
            continue
        primary = item.get("primary_ip") or item.get("primary_ip4") or item.get("primary_ip6") or {}
        address = (primary or {}).get("address") or ""
        host = address.split("/")[0] if address else name
        platform_obj = item.get("platform") or {}
        slug = platform_obj.get("slug") or ""
        mapped = source.platform_map.get(slug) or source.platform_map.get(platform_obj.get("name") or "")
        if not mapped and slug and resolve_platform(slug):
            mapped = slug
        if not mapped and platform_obj.get("napalm_driver") and resolve_platform(platform_obj["napalm_driver"]):
            mapped = platform_obj["napalm_driver"]
        if not mapped:
            log.warning("NetBox device %s skipped: no NetLedger platform for NetBox platform %r "
                        "(add it to platform_map)", name, slug or None)
            continue
        site = (item.get("site") or {}).get(source.site_field) or ""
        role = (item.get("role") or item.get("device_role") or {}).get("slug") or ""
        tags = [t.get("slug") or t.get("name") for t in item.get("tags") or [] if isinstance(t, dict)]
        raw = deep_merge(source.defaults, {"name": name, "host": host, "platform": mapped, "site": site, "role": role})
        raw["tags"] = unique(_as_list(source.defaults.get("tags"), "", "tags") + tags)
        context = (item.get("config_context") or {}).get("netledger") or {}
        if context:
            raw = deep_merge(raw, context)
        if raw.get("enabled", True) is False:
            continue
        raw.pop("enabled", None)
        device = build_device(raw, f"netbox:{name}")
        device.source = base
        devices.append(device)
    return devices


def _expand_paths(path: Path) -> list[Path]:
    text = str(path)
    if any(ch in text for ch in "*?["):
        return sorted(Path(p) for p in glob.glob(text) if Path(p).is_file())
    if path.is_dir():
        return sorted(p for p in path.iterdir() if p.suffix.lower() in (".yaml", ".yml", ".csv") and p.is_file())
    if path.is_file():
        return [path]
    raise ConfigError(f"inventory file not found: {path}")


def load_file(path: Path, defaults: dict[str, Any] | None = None) -> list[Device]:
    if path.suffix.lower() == ".csv":
        return load_csv_inventory(path, defaults)
    return load_yaml_inventory(path, defaults)


def load_inventory(settings: Settings) -> list[Device]:
    devices: dict[str, Device] = {}
    for source in settings.inventory_sources:
        if source.type == "file":
            loaded: list[Device] = []
            for path in _expand_paths(settings.resolve_path(source.path or "")):
                loaded.extend(load_file(path, source.defaults))
        elif source.type == "oxidized":
            from netledger.oxidized import load_oxidized_inventory

            loaded = load_oxidized_inventory(source, settings)
        else:
            loaded = load_netbox_inventory(source)
        for device in loaded:
            if device.name in devices:
                log.warning("device %s defined more than once; using the definition from %s", device.name, device.source)
            devices[device.name] = device
    return sorted(devices.values(), key=lambda d: d.name.lower())


# --------------------------------------------------------------------------- credentials


def resolve_credentials(device: Device, settings: Settings) -> list[CredentialSet]:
    """Credential sets to try for a device, in order."""
    sets: list[CredentialSet] = []
    if device.username or device.password:
        sets.append(CredentialSet(username=device.username, password=device.password, secret=device.secret))
    for name in device.credentials:
        cred = settings.credential_set(name)
        if cred is None:
            if sets:
                continue
            raise ConfigError(
                f"device {device.name}: credential set {name!r} is not defined in 'credentials' "
                "(or set NETLEDGER_USERNAME / NETLEDGER_PASSWORD for 'default')"
            )
        if device.secret and not cred.secret:
            cred = cred.model_copy(update={"secret": device.secret})
        sets.append(cred)
    if not sets:
        raise ConfigError(f"device {device.name}: no credentials configured")
    return sets


def validate_inventory(devices: list[Device], settings: Settings) -> list[str]:
    """Return a list of human-readable problems (empty when everything looks fine)."""
    from netledger.platforms import load_driver_class

    problems: list[str] = []
    checked_drivers: dict[str, str | None] = {}
    for device in devices:
        if device.collector == "oxidized" and not device.health:
            continue  # Oxidized collects its configuration; NetLedger never logs in to it
        try:
            resolve_credentials(device, settings)
        except ConfigError as exc:
            problems.append(str(exc))
        spec = device.driver_spec
        if spec not in checked_drivers:
            try:
                load_driver_class(spec)
                checked_drivers[spec] = None
            except Exception as exc:  # noqa: BLE001 - surface any import problem
                checked_drivers[spec] = f"{type(exc).__name__}: {exc}"
        if checked_drivers[spec]:
            problems.append(f"device {device.name}: cannot load driver {spec}: {checked_drivers[spec]}")
    return problems


# --------------------------------------------------------------------------- filters / paths


@dataclass
class DeviceFilter:
    names: list[str] = field(default_factory=list)
    sites: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return any((self.names, self.sites, self.groups, self.tags, self.platforms))

    def matches(self, device: Device) -> bool:
        def any_glob(patterns: list[str], values: Iterable[str]) -> bool:
            values = [v.lower() for v in values if v]
            return any(fnmatch.fnmatchcase(v, p.lower()) for p in patterns for v in values)

        if self.names and not any_glob(self.names, [device.name, device.host]):
            return False
        if self.sites and not any_glob(self.sites, [device.site]):
            return False
        if self.groups and not any_glob(self.groups, device.groups):
            return False
        if self.tags and not any_glob(self.tags, device.tags):
            return False
        if self.platforms:
            wanted = {resolve_platform(p) or p.lower() for p in self.platforms}
            if device.platform.lower() not in wanted:
                return False
        return True

    def apply(self, devices: Iterable[Device]) -> list[Device]:
        return [d for d in devices if self.matches(d)]


def _split_path(value: str) -> list[str]:
    return [part for part in re.split(r"[\\/]+", value) if part not in ("", ".", "..")]


def device_dir(device: Device, git: GitSettings) -> str:
    """Repository directory (POSIX style) holding a device's files."""
    rel = git.path.format_map(device.template_vars())
    parts = _split_path(git.base_dir) + [safe_path_component(p) for p in _split_path(rel)]
    return "/".join(parts) or safe_path_component(device.name)
