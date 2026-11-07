"""NetLedger settings: schema, loading, ``${ENV}`` / ``${file:...}`` interpolation and env files."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Union

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    ValidationError,
    field_validator,
    model_validator,
)

Severity = Literal["info", "warning", "critical"]

EVENT_TYPES = (
    "config_changed",
    "backup_failed",
    "backup_recovered",
    "health_warning",
    "health_critical",
    "health_recovered",
    "device_rebooted",
    "compliance_failed",
    "compliance_passed",
    "capacity_forecast",
)

CONFIG_ENV = "NETLEDGER_CONFIG"
DATA_DIR_ENV = "NETLEDGER_DATA_DIR"
ENV_FILE_ENV = "NETLEDGER_ENV_FILE"
CONFIG_FILENAMES = ("netledger.yaml", "netledger.yml")


class ConfigError(Exception):
    """Raised when configuration or inventory is invalid."""


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


# --------------------------------------------------------------------------- credentials


class CredentialSet(_Model):
    username: Optional[str] = None
    password: Optional[str] = None
    secret: Optional[str] = Field(default=None, description="Enable / privileged-mode password")
    ssh_key: Optional[str] = Field(default=None, description="Path to an SSH private key")
    ssh_key_passphrase: Optional[str] = None


# --------------------------------------------------------------------------- inventory sources


class InventorySource(_Model):
    type: Literal["file", "netbox", "oxidized"] = "file"
    path: Optional[str] = None
    # NetBox
    url: Optional[str] = None
    token: Optional[str] = None
    auth_scheme: str = "Token"
    filters: Dict[str, Any] = Field(default_factory=lambda: {"status": "active", "has_primary_ip": "true"})
    platform_map: Dict[str, str] = Field(default_factory=dict)
    include_virtual_machines: bool = False
    verify_ssl: bool = True
    timeout: int = 30
    defaults: Dict[str, Any] = Field(default_factory=dict)
    site_field: Literal["slug", "name"] = "slug"
    # Oxidized: configurations come from Oxidized instead of NetLedger logging in
    mode: Literal["repo", "api"] = Field(default="repo", description="repo: read Oxidized's git output; api: poll oxidized-web")
    username: Optional[str] = Field(default=None, description="Basic auth for the Oxidized API (usually a reverse proxy)")
    password: Optional[str] = None
    router_db: Optional[str] = Field(default=None, description="Oxidized's router.db (name:model[:group]), for each node's platform")
    router_db_delimiter: str = ":"
    groups: List[str] = Field(default_factory=list, description="Only nodes in these Oxidized groups (default: all)")
    devices: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="Per-node settings: platform, host, site, health, ...")
    poll: str = Field(default="every 5m", description="How often 'netledger serve' looks for new configurations")
    hook_token: Optional[str] = Field(default=None, description="Bearer token accepted on POST /api/hooks/oxidized")
    hook_secret: Optional[str] = Field(default=None, description="HMAC-SHA256 secret accepted on POST /api/hooks/oxidized")
    use_commit_author: bool = Field(default=True, description="Use the Oxidized commit author as 'changed by' when the config does not say")

    @model_validator(mode="after")
    def _check(self) -> InventorySource:
        if self.type == "file" and not self.path:
            raise ValueError("inventory source of type 'file' needs a 'path'")
        if self.type == "netbox" and not self.url:
            raise ValueError("inventory source of type 'netbox' needs a 'url'")
        if self.type == "oxidized":
            if self.mode == "repo" and not self.path:
                raise ValueError("an oxidized source in 'repo' mode needs the 'path' of Oxidized's git repository")
            if self.mode == "api" and not self.url:
                raise ValueError("an oxidized source in 'api' mode needs the 'url' of oxidized-web")
            from netledger.scheduler import parse_schedule

            try:
                parse_schedule(self.poll, None)
            except ValueError as exc:
                raise ValueError(f"oxidized poll {self.poll!r}: {exc}") from None
        return self

    @property
    def key(self) -> str:
        """Stable identity of an Oxidized source, for its read cursor."""
        return f"oxidized:{self.mode}:{(self.url or self.path or '').rstrip('/')}"


# --------------------------------------------------------------------------- git / storage


class GitHubAppSettings(_Model):
    app_id: Union[int, str]
    private_key: str = Field(description="PEM private key (use ${file:/path/key.pem})")
    installation_id: Optional[int] = None


class GitSettings(_Model):
    backend: Literal["git", "github", "local"] = "git"
    url: Optional[str] = Field(default=None, description="Remote URL (https:// or git@host:org/repo.git)")
    repo: Optional[str] = Field(default=None, description="owner/name, for the github backend")
    branch: str = "main"
    token: Optional[str] = None
    username: str = "x-access-token"
    ssh_key: Optional[str] = None
    ssh_known_hosts: Optional[str] = None
    api_url: str = "https://api.github.com"
    github_app: Optional[GitHubAppSettings] = None
    workdir: Optional[str] = None
    author_name: str = "NetLedger"
    author_email: str = "netledger@localhost"
    commit_mode: Literal["per-device", "per-run"] = "per-device"
    base_dir: str = "configs"
    path: str = "{name}"
    index: bool = True
    index_path: str = "README.md"
    prune: bool = False
    push: bool = True
    sign_commits: bool = False
    web_url: Optional[str] = None
    verify_ssl: bool = True

    @model_validator(mode="after")
    def _check(self) -> GitSettings:
        if self.backend == "git" and not self.url:
            raise ValueError("git.url is required for the 'git' backend (use backend: local for no remote)")
        if self.backend == "github" and not (self.repo or self.url):
            raise ValueError("git.repo (owner/name) or git.url is required for the 'github' backend")
        if self.backend == "github" and not (self.token or self.github_app):
            raise ValueError("the 'github' backend needs git.token or git.github_app")
        try:
            self.path.format_map(_TemplateProbe())
        except (KeyError, ValueError, IndexError) as exc:
            raise ValueError(f"git.path template is invalid: {exc}") from exc
        return self


class _TemplateProbe(dict):
    def __missing__(self, key: str) -> str:
        allowed = {"name", "site", "role", "platform", "vendor", "group", "host"}
        if key not in allowed:
            raise KeyError(f"unknown placeholder {{{key}}} (use one of: {', '.join(sorted(allowed))})")
        return "x"


# --------------------------------------------------------------------------- normalization


class CustomRule(_Model):
    pattern: str
    replace: Optional[str] = Field(default=None, description="Replacement; omit to drop matching lines")
    platforms: List[str] = Field(default_factory=list)
    multiline: bool = False

    @field_validator("pattern")
    @classmethod
    def _compiles(cls, value: str) -> str:
        try:
            re.compile(value)
        except re.error as exc:
            raise ValueError(f"invalid regular expression {value!r}: {exc}") from exc
        return value


class NormalizeSettings(_Model):
    secrets: Literal["keep", "mask", "hmac"] = "keep"
    secret_key: Optional[str] = None
    disable_rules: List[str] = Field(default_factory=list)
    rules: List[CustomRule] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check(self) -> NormalizeSettings:
        if self.secrets == "hmac" and not self.secret_key:
            raise ValueError("normalize.secret_key is required when normalize.secrets is 'hmac'")
        return self


# --------------------------------------------------------------------------- backup


class CommandSpec(_Model):
    command: str
    name: Optional[str] = None
    exclude: List[str] = Field(default_factory=list)


CommandEntry = Union[str, CommandSpec]


class BackupSettings(_Model):
    enabled: bool = True
    workers: int = Field(default=10, ge=1, le=500)
    timeout: int = Field(default=60, ge=5)
    command_timeout: int = Field(default=180, ge=10)
    retries: int = Field(default=1, ge=0, le=10)
    retry_delay: float = Field(default=5.0, ge=0)
    retrieve: List[Literal["running", "startup", "candidate"]] = Field(default_factory=lambda: ["running"])
    full: bool = False
    facts: bool = True
    commands: Dict[str, List[CommandEntry]] = Field(default_factory=dict)
    failure_alert_after: int = Field(default=2, ge=1)
    shrink_guard: float = Field(default=0.25, ge=0, le=1)


# --------------------------------------------------------------------------- health


class ThresholdPair(_Model):
    warning: Optional[float] = None
    critical: Optional[float] = None


class HealthThresholds(_Model):
    cpu: ThresholdPair = Field(default_factory=lambda: ThresholdPair(warning=80, critical=95))
    memory: ThresholdPair = Field(default_factory=lambda: ThresholdPair(warning=85, critical=95))
    temperature: ThresholdPair = Field(default_factory=ThresholdPair)


class HealthSettings(_Model):
    enabled: bool = True
    workers: int = Field(default=20, ge=1, le=500)
    timeout: int = Field(default=30, ge=5)
    thresholds: HealthThresholds = Field(default_factory=HealthThresholds)
    fan_failure: Severity = "warning"
    psu_failure: Severity = "warning"
    reboot: Severity = "warning"
    unreachable_after: int = Field(default=2, ge=1)
    ignore_sensors: List[str] = Field(default_factory=list)
    history: bool = Field(default=True, description="Keep CPU / memory / temperature history for trends and forecasts")
    history_days: int = Field(default=30, ge=1, le=400)
    forecast_days: float = Field(default=7, ge=0, description="Alert when memory or temperature is predicted to cross a threshold within this many days (0 = off)")
    lldp: bool = Field(default=True, description="Collect LLDP neighbors for the topology map")


# --------------------------------------------------------------------------- change intelligence


class ChangeSettings(_Model):
    windows: List[str] = Field(
        default_factory=list,
        description="Approved change windows, e.g. 'sat 22:00-sun 04:00' or 'weekdays 19:00-21:00'. Changes outside them are flagged.",
    )
    timezone: Optional[str] = Field(default=None, description="Time zone of the windows (default: schedule.timezone, then local time)")
    keep: int = Field(default=1000, ge=0, le=100000, description="Change records kept for the dashboard")

    @field_validator("windows")
    @classmethod
    def _windows(cls, value: List[str]) -> List[str]:
        from netledger.windows import parse_window

        for item in value:
            parse_window(item)
        return value


# --------------------------------------------------------------------------- compliance


class ComplianceRule(_Model):
    name: str
    description: str = ""
    severity: Severity = "warning"
    must_match: Optional[str] = None
    must_not_match: Optional[str] = None
    platforms: List[str] = Field(default_factory=list)
    sites: List[str] = Field(default_factory=list)
    groups: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    devices: List[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check(self) -> ComplianceRule:
        if not (self.must_match or self.must_not_match):
            raise ValueError(f"compliance rule {self.name!r} needs must_match and/or must_not_match")
        for pattern in (self.must_match, self.must_not_match):
            if pattern:
                try:
                    re.compile(pattern, re.M)
                except re.error as exc:
                    raise ValueError(f"compliance rule {self.name!r}: invalid regex {pattern!r}: {exc}") from exc
        return self


# --------------------------------------------------------------------------- notifications


class NotifierSettings(_Model):
    type: Literal["slack", "teams", "discord", "webhook", "email", "pagerduty"]
    name: Optional[str] = None
    url: Optional[str] = None
    events: List[str] = Field(default_factory=lambda: list(EVENT_TYPES))
    min_severity: Severity = "info"
    include_diff: bool = True
    max_diff_lines: int = 60
    max_per_run: int = Field(default=10, ge=1)
    timeout: int = 10
    verify_ssl: bool = True
    headers: Dict[str, str] = Field(default_factory=dict)
    secret: Optional[str] = Field(default=None, description="HMAC secret for signing webhook payloads")
    # email
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    starttls: bool = True
    ssl: bool = False
    from_address: Optional[str] = None
    to: List[str] = Field(default_factory=list)
    # pagerduty
    routing_key: Optional[str] = None

    @field_validator("events")
    @classmethod
    def _events(cls, value: List[str]) -> List[str]:
        if "all" in value:
            return list(EVENT_TYPES)
        unknown = sorted(set(value) - set(EVENT_TYPES))
        if unknown:
            raise ValueError(f"unknown event type(s) {unknown}; valid: {', '.join(EVENT_TYPES)}")
        return value

    @model_validator(mode="after")
    def _check(self) -> NotifierSettings:
        if self.type in ("slack", "teams", "discord", "webhook") and not self.url:
            raise ValueError(f"{self.type} notifier needs a 'url'")
        if self.type == "email" and not (self.smtp_host and self.to and self.from_address):
            raise ValueError("email notifier needs smtp_host, from_address and to")
        if self.type == "pagerduty" and not self.routing_key:
            raise ValueError("pagerduty notifier needs a routing_key")
        return self

    @property
    def label(self) -> str:
        return self.name or self.type


# --------------------------------------------------------------------------- schedule / server / logging


class ScheduleSettings(_Model):
    backup: Optional[str] = "0 * * * *"
    health: Optional[str] = "*/5 * * * *"
    timezone: Optional[str] = None
    run_on_start: bool = True


class ServerSettings(_Model):
    enabled: bool = True
    host: str = "0.0.0.0"
    port: int = Field(default=8080, ge=1, le=65535)
    username: Optional[str] = None
    password: Optional[str] = None
    api_token: Optional[str] = None
    metrics_auth: bool = False
    allow_anonymous_triggers: bool = Field(default=False, description="Allow 'run now' buttons without login (demos/trusted networks only)")
    title: str = "NetLedger"
    theme: Literal["light", "dark", "auto"] = Field(default="light", description="Default dashboard theme (each user can toggle it)")

    @model_validator(mode="after")
    def _check(self) -> ServerSettings:
        if bool(self.username) != bool(self.password):
            raise ValueError("server.username and server.password must be set together")
        return self


class LoggingSettings(_Model):
    level: str = "INFO"
    format: Literal["auto", "text", "json"] = "auto"
    file: Optional[str] = None


# --------------------------------------------------------------------------- root


class Settings(_Model):
    data_dir: Optional[str] = None
    inventory: List[Union[str, InventorySource]] = Field(default_factory=lambda: ["inventory.yaml"])
    credentials: Dict[str, CredentialSet] = Field(default_factory=dict)
    git: GitSettings = Field(default_factory=lambda: GitSettings(backend="local"))
    backup: BackupSettings = Field(default_factory=BackupSettings)
    health: HealthSettings = Field(default_factory=HealthSettings)
    changes: ChangeSettings = Field(default_factory=ChangeSettings)
    normalize: NormalizeSettings = Field(default_factory=NormalizeSettings)
    compliance: List[ComplianceRule] = Field(default_factory=list)
    notifications: List[NotifierSettings] = Field(default_factory=list)
    schedule: ScheduleSettings = Field(default_factory=ScheduleSettings)
    server: ServerSettings = Field(default_factory=ServerSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)

    _config_path: Optional[Path] = PrivateAttr(default=None)

    @property
    def config_path(self) -> Optional[Path]:
        return self._config_path

    @property
    def base_dir(self) -> Path:
        return self._config_path.parent if self._config_path else Path.cwd()

    def resolve_path(self, value: str | os.PathLike[str]) -> Path:
        path = Path(os.path.expandvars(os.path.expanduser(str(value))))
        return path if path.is_absolute() else (self.base_dir / path).resolve()

    @property
    def data_path(self) -> Path:
        env = os.environ.get(DATA_DIR_ENV)
        if env:
            return self.resolve_path(env)
        if self.data_dir:
            return self.resolve_path(self.data_dir)
        return self.base_dir / "data"

    @property
    def inventory_sources(self) -> List[InventorySource]:
        sources = []
        for item in self.inventory:
            sources.append(InventorySource(type="file", path=item) if isinstance(item, str) else item)
        return sources

    def credential_set(self, name: str) -> Optional[CredentialSet]:
        if name in self.credentials:
            return self.credentials[name]
        if name == "default":
            env = os.environ
            if env.get("NETLEDGER_USERNAME"):
                return CredentialSet(
                    username=env.get("NETLEDGER_USERNAME"),
                    password=env.get("NETLEDGER_PASSWORD"),
                    secret=env.get("NETLEDGER_SECRET") or env.get("NETLEDGER_ENABLE"),
                    ssh_key=env.get("NETLEDGER_SSH_KEY"),
                )
        return None


# --------------------------------------------------------------------------- interpolation


_REF_RE = re.compile(r"\$(\$)|\$\{([^}]*)\}")


class _Interpolator:
    def __init__(self, base_dir: Path, source: str):
        self.base_dir = base_dir
        self.source = source

    def __call__(self, value: Any, where: str = "") -> Any:
        if isinstance(value, dict):
            return {k: self(v, f"{where}.{k}" if where else str(k)) for k, v in value.items()}
        if isinstance(value, list):
            return [self(v, f"{where}[{i}]") for i, v in enumerate(value)]
        if isinstance(value, str) and "$" in value:
            return _REF_RE.sub(lambda m: self._resolve(m, where), value)
        return value

    def _resolve(self, match: re.Match[str], where: str) -> str:
        if match.group(1):
            return "$"
        expr = match.group(2).strip()
        if expr.startswith("file:"):
            path = Path(os.path.expanduser(expr[5:].strip()))
            if not path.is_absolute():
                path = self.base_dir / path
            try:
                return path.read_text(encoding="utf-8").rstrip("\r\n")
            except OSError as exc:
                raise ConfigError(f"{self.source}: {where}: cannot read secret file {path}: {exc}") from exc
        if expr.startswith("env:"):
            expr = expr[4:]
        name, default, required_msg = expr, None, None
        if ":-" in expr:
            name, default = expr.split(":-", 1)
        elif ":?" in expr:
            name, required_msg = expr.split(":?", 1)
        name = name.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise ConfigError(f"{self.source}: {where}: invalid variable reference ${{{expr}}}")
        value = os.environ.get(name)
        if value is None or (value == "" and default is not None):
            if default is not None:
                return default
            hint = f" ({required_msg.strip()})" if required_msg else ""
            raise ConfigError(
                f"{self.source}: {where}: environment variable {name} is not set{hint}. "
                f"Set it, add it to netledger.env, or use ${{{name}:-default}}."
            )
        return value


def interpolate(data: Any, base_dir: Path, source: str = "config") -> Any:
    """Expand ``${VAR}``, ``${VAR:-default}``, ``${VAR:?message}`` and ``${file:path}`` in strings."""
    return _Interpolator(base_dir, source)(data)


# --------------------------------------------------------------------------- env files


def parse_env_file(text: str) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            quote, value = value[0], value[1:-1]
            if quote == '"':
                value = value.replace("\\n", "\n").replace('\\"', '"')
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            values[key] = value
    return values


def load_env_file(path: Path, override: bool = False) -> int:
    """Load KEY=VALUE pairs into ``os.environ``. Existing variables win unless ``override``."""
    try:
        values = parse_env_file(path.read_text(encoding="utf-8"))
    except OSError:
        # Missing, or readable only by root because systemd loads it (EnvironmentFile=) - both fine.
        return 0
    count = 0
    for key, value in values.items():
        if override or key not in os.environ:
            os.environ[key] = value
            count += 1
    return count


# --------------------------------------------------------------------------- loading


def default_config_locations() -> List[Path]:
    paths = [Path.cwd() / name for name in CONFIG_FILENAMES]
    if sys.platform == "win32":
        program_data = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
        paths.append(program_data / "NetLedger" / "netledger.yaml")
    else:
        paths.append(Path.home() / ".config" / "netledger" / "netledger.yaml")
        paths.append(Path("/etc/netledger/netledger.yaml"))
    return paths


def find_config(path: str | os.PathLike[str] | None = None) -> Path:
    candidate = path or os.environ.get(CONFIG_ENV)
    if candidate:
        resolved = Path(os.path.expanduser(str(candidate)))
        if resolved.is_dir():
            for name in CONFIG_FILENAMES:
                if (resolved / name).is_file():
                    return resolved / name
        if not resolved.is_file():
            raise ConfigError(f"configuration file not found: {resolved}")
        return resolved
    for location in default_config_locations():
        if location.is_file():
            return location
    raise ConfigError(
        "no configuration file found. Create one with 'netledger init', pass --config, "
        f"or set {CONFIG_ENV}. Searched: " + ", ".join(str(p) for p in default_config_locations())
    )


def format_validation_error(exc: ValidationError, source: str) -> str:
    lines = [f"{source}: invalid configuration"]
    for err in exc.errors():
        loc = ".".join(str(part) for part in err.get("loc", ())) or "(root)"
        msg = err.get("msg", "invalid value")
        if err.get("type") == "extra_forbidden":
            msg = "unknown setting (check for typos)"
        lines.append(f"  - {loc}: {msg}")
    return "\n".join(lines)


def load_settings(path: str | os.PathLike[str] | None = None) -> Settings:
    config_path = find_config(path).resolve()
    env_file = os.environ.get(ENV_FILE_ENV)
    load_env_file(Path(env_file) if env_file else config_path.parent / "netledger.env")
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{config_path}: invalid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{config_path}: top level must be a mapping")
    raw = interpolate(raw, config_path.parent, str(config_path.name))
    try:
        settings = Settings.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(format_validation_error(exc, str(config_path))) from None
    settings._config_path = config_path
    return settings


def settings_from_dict(raw: Dict[str, Any], base_dir: Path | None = None) -> Settings:
    """Build settings from a dict (used by tests and embedding)."""
    base = base_dir or Path.cwd()
    try:
        settings = Settings.model_validate(interpolate(raw, base))
    except ValidationError as exc:
        raise ConfigError(format_validation_error(exc, "settings")) from None
    settings._config_path = base / "netledger.yaml"
    return settings
