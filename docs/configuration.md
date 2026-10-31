# Configuration reference

NetLedger reads one YAML file, `netledger.yaml`. Start from `netledger init`, which writes a fully
commented copy. Unknown keys are rejected with a clear error, so typos never fail silently.

**Where the file is found:** `--config PATH`, then `$NETLEDGER_CONFIG`, then `./netledger.yaml`,
`~/.config/netledger/netledger.yaml`, `/etc/netledger/netledger.yaml` (Linux/macOS) or
`%PROGRAMDATA%\NetLedger\netledger.yaml` (Windows). Relative paths inside the file are relative to
the file's folder.

## Secrets and variables

Any string value can reference the environment or a file:

| Syntax | Meaning |
|---|---|
| `${VAR}` | environment variable; error if not set |
| `${VAR:-default}` | with a default (use `${VAR:-}` for "optional, empty") |
| `${VAR:?message}` | error with your message if not set |
| `${file:/run/secrets/x}` | contents of a file, trailing newline removed (Docker/Kubernetes secrets) |
| `$$` | a literal `$` |

`netledger.env` in the same folder as `netledger.yaml` is loaded automatically (`KEY=VALUE` lines,
`#` comments, optional quotes). Variables already present in the environment win. Point
`$NETLEDGER_ENV_FILE` at a different file if needed.

## Top level

| Key | Default | Description |
|---|---|---|
| `data_dir` | `./data` next to the config | State file, health history (`history.db`) and the local Git working copy. `$NETLEDGER_DATA_DIR` overrides it. |
| `inventory` | `[inventory.yaml]` | Inventory sources: file paths, directories, globs or NetBox sources. See [inventory.md](inventory.md). |
| `credentials` | `{}` | Named credential sets (below). |
| `git` | local repository | Where configurations are committed. |
| `backup` | | Backup behaviour. |
| `normalize` | | Noise removal and secret handling. |
| `health` | | Health-check thresholds, history and forecasts. |
| `changes` | | Change windows and the change ledger. |
| `compliance` | `[]` | Golden-config rules. |
| `notifications` | `[]` | Where events are sent. |
| `schedule` | | When `netledger serve` runs jobs. |
| `server` | | Web console / API / metrics listener. |
| `logging` | | Log level, format and file. |

## credentials

```yaml
credentials:
  default:                      # used by devices that don't name a set
    username: ${NETLEDGER_USERNAME}
    password: ${NETLEDGER_PASSWORD}
    secret: ${NETLEDGER_ENABLE:-}         # enable / privileged password
  local-fallback:
    username: backup
    password: ${file:/run/secrets/local}
  keys:
    username: netledger
    ssh_key: /etc/netledger/id_ed25519    # key authentication
    ssh_key_passphrase: ${KEY_PASSPHRASE:-}
```

Devices list one or more sets (`credentials: [default, local-fallback]`); NetLedger tries them in
order and moves to the next one **only on authentication failures**, so an unreachable device is
not hammered with logins. If no `default` set is defined, `NETLEDGER_USERNAME`,
`NETLEDGER_PASSWORD` and `NETLEDGER_SECRET` from the environment are used.

## git

| Key | Default | Description |
|---|---|---|
| `backend` | `local` if `git` is omitted, otherwise `git` | `git` (any Git server, needs the `git` executable), `github` (GitHub REST API, no git binary), `local` (commit to `data_dir/repo` only). |
| `url` | | Remote URL, `https://…` or `git@host:org/repo.git`. Required for `git`. |
| `repo` | from `url` | `owner/name`, for the `github` backend. |
| `branch` | `main` | Created automatically if missing (from the default branch, or as the first commit of an empty repository). |
| `token` | | HTTPS token (GitHub/GitLab/Gitea PAT, Azure DevOps PAT, Bitbucket app password). |
| `username` | `x-access-token` | Username sent with the token. Bitbucket needs your username; GitLab accepts `oauth2`. |
| `ssh_key` / `ssh_known_hosts` | | Private key (and optional known-hosts file) for SSH remotes. Unknown hosts are accepted on first use. |
| `github_app` | | `{app_id, private_key, installation_id?}` - authenticate as a GitHub App instead of a token (both backends). |
| `api_url` | `https://api.github.com` | GitHub Enterprise Server: `https://github.example.com/api/v3`. |
| `workdir` | `data_dir/repo` | Local working copy for the `git`/`local` backends. |
| `author_name` / `author_email` | `NetLedger` / `netledger@localhost` | Commit identity. |
| `commit_mode` | `per-device` | `per-device`: one commit per changed device. `per-run`: one commit per run. |
| `base_dir` | `configs` | Folder inside the repository. |
| `path` | `{name}` | Per-device folder template: `{name}`, `{site}`, `{role}`, `{platform}`, `{vendor}`, `{group}`, `{host}`. |
| `index` | `true` | Maintain a generated `README.md` index. Never overwrites a README that NetLedger did not create. |
| `index_path` | `README.md` | Where the index goes. |
| `prune` | `false` | Delete folders of devices that left the inventory (only on unfiltered runs). |
| `push` | `true` | Push after committing. |
| `sign_commits` | `false` | Allow `commit.gpgsign` from your git config. Off by default so unattended runs never block on a signing prompt. |
| `web_url` | from `url` | Browser URL used for links (dashboard, notifications). |
| `verify_ssl` | `true` | TLS verification for HTTPS remotes / the GitHub API. |

Token permissions on GitHub: a **fine-grained token** limited to the backup repository with
**Contents: Read and write**, or a classic token with `repo`. For the `github` backend the token
needs the same permission.

## backup

| Key | Default | Description |
|---|---|---|
| `enabled` | `true` | Disable to run health checks only. |
| `workers` | `10` | Parallel device sessions. |
| `timeout` | `60` | Connection / login timeout (seconds). Per device: `timeout:` in the inventory. |
| `command_timeout` | `180` | Maximum wait for a single command (large configurations take time). |
| `retries` / `retry_delay` | `1` / `5` | Retries for connection errors (not authentication errors), with exponential back-off. |
| `retrieve` | `[running]` | Any of `running`, `startup`, `candidate` (only where the platform supports it). |
| `full` | `false` | Include default settings where supported (`show running-config all`, `show full-configuration`). |
| `facts` | `true` | Collect model / serial / OS version for `device.json`, the index and the dashboard. |
| `commands` | `{}` | Extra show commands to archive, per platform or `"*"` (see below). |
| `failure_alert_after` | `2` | Send `backup_failed` after this many consecutive failures. |
| `shrink_guard` | `0.25` | Refuse to commit a running configuration that shrank below this fraction of its previous line count (guards against truncated output or missing privileges). `0` disables. |

```yaml
backup:
  commands:
    ios:
      - show inventory
      - command: show version
        name: version                       # file name: commands/version.txt
        exclude: ["uptime is", "^Configuration register"]   # drop changing lines
    fortios: ["get system ha status"]
    "*": []
```

## normalize

| Key | Default | Description |
|---|---|---|
| `secrets` | `keep` | `keep`, `mask` (replace with `<removed>`) or `hmac` (replace with `<secret:1a2b…>`, a keyed hash: secret changes still show up as diffs, values are never revealed). |
| `secret_key` | | Key for `hmac` (required). Keep it stable or every secret will "change" once. |
| `disable_rules` | `[]` | Built-in rule IDs to switch off, e.g. `fortios.enc` to keep FortiOS encrypted values. Rule IDs are listed in `src/netledger/platforms.py`. |
| `rules` | `[]` | Your own rules: `{pattern, replace?, platforms?, multiline?}`. Without `replace`, matching lines are dropped. |

```yaml
normalize:
  secrets: hmac
  secret_key: ${NETLEDGER_SECRET_KEY}
  rules:
    - pattern: '^! Last reload'                      # drop lines
    - pattern: '(snmp-server location) .*'           # rewrite
      replace: '\1 <hidden>'
      platforms: [ios, nxos]
```

## health

| Key | Default | Description |
|---|---|---|
| `enabled` | `true` | |
| `workers` / `timeout` | `20` / `30` | Health checks are lightweight; run them often. |
| `thresholds.cpu` | `{warning: 80, critical: 95}` | Busiest core, percent. |
| `thresholds.memory` | `{warning: 85, critical: 95}` | Percent used. |
| `thresholds.temperature` | `{warning: null, critical: null}` | Celsius; `null` means "trust the device's own alarm flags". |
| `fan_failure` / `psu_failure` | `warning` | Severity for failed fans / power supplies (`info` to only display them). |
| `reboot` | `warning` | Severity of the `device_rebooted` event. |
| `unreachable_after` | `2` | Consecutive failed checks before a device turns critical. |
| `ignore_sensors` | `[]` | Regexes for sensors, fans or PSUs to ignore everywhere. |
| `history` | `true` | Keep every check in `<data_dir>/history.db` (SQLite) for trends, status strips and forecasts. |
| `history_days` | `30` | Retention of the history. Roughly 7 MB per 100 devices checked every five minutes. |
| `forecast_days` | `7` | Raise `capacity_forecast` when memory or temperature is predicted to cross a threshold within this many days. `0` turns the alert off (forecasts are still shown). |
| `lldp` | `true` | Read LLDP neighbours on every check for the network map. |

Per-device overrides live in the inventory: `health: {thresholds: {...}, ignore_sensors: [...]}`.
Details: [health-checks.md](health-checks.md).

## changes

| Key | Default | Description |
|---|---|---|
| `windows` | `[]` | Approved change windows. A change found by a backup is *unplanned* when no window overlaps the time since the previous successful backup. |
| `timezone` | `schedule.timezone`, then local time | IANA zone the windows are written in, e.g. `Europe/London`. |
| `keep` | `1000` | Change records kept for the console's change ledger (diffs are kept for the newest 100). |

Window syntax: `<days> <HH:MM>-[<day>] <HH:MM>`, where days is `daily`, `weekdays`, `weekends`, a day
(`sat`), a range (`mon-fri`) or a list (`mon,wed`). An end time earlier than the start wraps past
midnight.

```yaml
changes:
  windows:
    - "sat 22:00-sun 04:00"
    - "weekdays 19:00-21:00"
  timezone: America/New_York
```

Unplanned changes are flagged in the console, noted in the commit message (`Window: outside the approved
change windows`) and sent as `config_changed` events with `warning` severity.

## compliance

```yaml
compliance:
  - name: ssh-only
    description: VTY lines must only accept SSH
    platforms: [ios]                    # optional scoping: platforms, sites, groups, tags, devices
    must_not_match: '^\s*transport input .*telnet'
    severity: warning
  - name: ntp
    must_match: '^ntp server '
    platforms: [ios, nxos, eos]
    severity: critical
```

Rules are regular expressions (multi-line mode) evaluated on every backup, against the configuration
**before** secret masking (so you can forbid weak password types). Findings shown in alerts and the
dashboard are masked. Results appear on the device page, in `/metrics`
(`netledger_compliance_ok`) and as `compliance_failed` / `compliance_passed` events on transitions.

## notifications

A list; each entry has a `type` and type-specific settings. Common keys: `name`, `events` (default:
all), `min_severity` (`info`), `include_diff` (`true`), `max_diff_lines` (`60`), `max_per_run`
(`10`; more events are folded into one digest), `timeout`, `verify_ssl`, `headers`.
See [notifications.md](notifications.md).

## schedule

| Key | Default | Description |
|---|---|---|
| `backup` | `0 * * * *` | Cron expression (5 fields, `*/n`, ranges, names), `@hourly`/`@daily`/..., or `every 30m`. Empty disables. |
| `health` | `*/5 * * * *` | Same. |
| `timezone` | local time | IANA name, e.g. `Europe/London`. |
| `run_on_start` | `true` | Run both jobs immediately when `serve` starts. |

A job never overlaps with itself; if a run is still going when the next one is due, it is skipped.

## server

| Key | Default | Description |
|---|---|---|
| `enabled` | `true` | |
| `host` / `port` | `0.0.0.0` / `8080` | `--host` / `--port` override. |
| `username` / `password` | | HTTP basic auth for the dashboard and API. |
| `api_token` | | Bearer token for `POST /api/run/{backup,health}` and the API. |
| `metrics_auth` | `false` | Require auth for `/metrics` too. |
| `allow_anonymous_triggers` | `false` | Allow "run now" without auth (demos / isolated networks only). |
| `title` | `NetLedger` | Console title. |
| `theme` | `light` | Default console theme: `light`, `dark` or `auto` (follows the OS). Each browser remembers its own choice. |

Pages: `/` overview, `/devices/<name>`, `/changes`, `/search`, `/topology`, `/wall`. API and probes are
listed in [console.md](console.md#json-api); plus `/metrics`, `/healthz` and `/readyz`.

## logging

| Key | Default | Description |
|---|---|---|
| `level` | `INFO` | `--log-level` overrides. Set `NETLEDGER_DEBUG_LIBS=1` to also see Netmiko/Paramiko debug output. |
| `format` | `auto` | `auto` (colors on a terminal, JSON on Kubernetes, plain otherwise), `text`, `json`. |
| `file` | | Also log to a rotating file (10 MB x 5). `--log-file` overrides. |
