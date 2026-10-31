# Security

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub security advisories](https://github.com/SalamoneJack/NetLedger/security/advisories/new)
rather than public issues. You will get a response within a few days.

## How NetLedger handles sensitive data

- **Credentials** are never written to logs, state or the backup repository. Use environment
  variables, `${file:...}` references (Kubernetes/Docker secrets) or `netledger.env` with
  restrictive permissions.
- **Git tokens** are passed to git through environment configuration, never on the command line or
  in `.git/config`, and are redacted from error messages.
- **Device configurations contain secrets.** Keep the backup repository private, or set
  `normalize.secrets: mask` / `hmac` before backing up to a repository others can read.
  Notifications and the dashboard always mask secrets in diffs, whatever that setting is.
- **The dashboard** sends a strict Content-Security-Policy and escapes all device-provided text.
  Enable `server.username`/`password` or `server.api_token` when it is reachable by others; "run
  now" triggers are disabled until you do.
- **Git operations** are pinned to NetLedger's own working copy (`GIT_DIR`/`GIT_WORK_TREE`), so a
  damaged clone can never cause commands to run against a parent repository.
- **SSH host keys:** like most network automation tools, Netmiko does not verify host keys by
  default. Set `optional_args: {ssh_strict: true, system_host_keys: true}` (or `alt_host_keys`
  with `alt_key_file`) to enforce known hosts.
- The container image runs as a non-root user and works with a read-only root filesystem.
