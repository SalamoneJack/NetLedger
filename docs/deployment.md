# Deployment

NetLedger is one Python package with two ways of running:

- **`netledger serve`**: always on. A built-in scheduler runs backups and health checks, and serves
  the dashboard, API and Prometheus metrics. Use this on Kubernetes, in Docker, as a systemd service
  or as a Windows background task.
- **`netledger run`** (or `backup` / `health`): one shot, for cron, systemd timers, Windows Task
  Scheduler, CI pipelines or Kubernetes CronJobs.

Run exactly **one** `serve` instance per backup repository and data directory.

**Network access needed:** SSH (or the platform's API: NETCONF 830, HTTPS for eAPI/NX-API) to every
device, HTTPS or SSH to your Git server, and outbound HTTPS to webhook targets.

## Kubernetes

### Helm

```bash
helm install netledger deploy/helm/netledger \
  --namespace netledger --create-namespace \
  -f my-values.yaml
```

A typical `my-values.yaml`:

```yaml
config:                               # becomes netledger.yaml (see docs/configuration.md)
  inventory: [inventory.yaml]
  credentials:
    default: {username: "${NETLEDGER_USERNAME}", password: "${NETLEDGER_PASSWORD}"}
  git:
    url: https://github.com/acme/network-configs.git
    token: ${GIT_TOKEN}
    path: "{site}/{name}"
  notifications:
    - {type: slack, url: "${SLACK_WEBHOOK_URL}", events: [config_changed, health_critical]}
  schedule: {backup: "0 * * * *", health: "*/5 * * * *"}
  server: {port: 8080, api_token: "${NETLEDGER_API_TOKEN}"}
  logging: {format: json}

inventory:                            # becomes inventory.yaml
  devices:
    - {name: core-sw01, host: 10.0.0.11, platform: ios, site: hq}

existingSecret: netledger-secrets     # create it yourself (recommended), or use `secrets:` below

serviceMonitor: {enabled: true}       # Prometheus Operator
prometheusRule: {enabled: true}
ingress:
  enabled: true
  className: nginx
  hosts: [{host: netledger.example.com, paths: [{path: /, pathType: Prefix}]}]
```

Create the secret (or sync it from Vault / External Secrets):

```bash
kubectl -n netledger create secret generic netledger-secrets \
  --from-literal=NETLEDGER_USERNAME=netbackup \
  --from-literal=NETLEDGER_PASSWORD='...' \
  --from-literal=GIT_TOKEN='github_pat_...' \
  --from-literal=SLACK_WEBHOOK_URL='https://hooks.slack.com/...' \
  --from-literal=NETLEDGER_API_TOKEN="$(openssl rand -hex 24)"
```

Config changes roll the pod automatically (checksum annotations). Useful values: `image.tag`,
`persistence.*`, `resources`, `nodeSelector`, `tolerations`, `extraEnv`, `extraVolumes` /
`extraVolumeMounts` (for SSH keys or a CA bundle). See `deploy/helm/netledger/values.yaml`.

### Kustomize (plain manifests)

```bash
cd deploy/kubernetes
cp secret.env.example secret.env          # git-ignored; fill in credentials and GIT_TOKEN
$EDITOR config/netledger.yaml config/inventory.yaml
kubectl apply -k .
kubectl -n netledger port-forward svc/netledger 8080:8080
```

Optional extras are listed (commented) in `kustomization.yaml`: a `ServiceMonitor`, a
`PrometheusRule`, and a `CronJob` alternative to the Deployment.

### Notes

- The pod runs as UID 10001 with a read-only root filesystem, no capabilities and the `restricted`
  Pod Security Standard. `/data` (PVC) holds the Git working copy and state; `/tmp` is an emptyDir.
- `replicas: 1` with the `Recreate` strategy: the scheduler must not run twice.
- NetworkPolicies: allow egress to your management networks, Git server and webhook targets.
- **SSH keys** for Git or devices: mount a Secret (`extraVolumes`) and reference it with
  `git.ssh_key: /etc/netledger-keys/id_ed25519` or a credential set's `ssh_key`.

## Docker

```bash
netledger init            # or copy src/netledger/templates/* next to docker-compose.yml
# edit netledger.yaml, inventory.yaml and netledger.env
docker compose up -d
docker compose logs -f
```

Or plain Docker:

```bash
docker run -d --name netledger -p 8080:8080 \
  --env-file netledger.env \
  -v "$PWD/netledger.yaml:/etc/netledger/netledger.yaml:ro" \
  -v "$PWD/inventory.yaml:/etc/netledger/inventory.yaml:ro" \
  -v netledger-data:/data \
  --read-only --tmpfs /tmp \
  ghcr.io/salamonejack/netledger:latest
```

One-off commands work the same way: `docker run --rm ... ghcr.io/salamonejack/netledger test -d core-sw01`.
Build locally with `docker build -t netledger .`.

## Linux

Debian/Ubuntu, RHEL/Rocky/Alma, SUSE and other systemd distributions, with Python 3.9+ and git:

```bash
git clone https://github.com/SalamoneJack/NetLedger.git && cd NetLedger
sudo deploy/linux/install.sh .            # or: sudo deploy/linux/install.sh netledger
```

The installer creates a `netledger` system user, installs into `/opt/netledger` (a virtualenv),
writes starter files to `/etc/netledger` (`netledger.env` is root-only and loaded by systemd), uses
`/var/lib/netledger` for data, and installs a hardened `netledger.service` (`ProtectSystem=strict`,
`NoNewPrivileges`, no capabilities).

```bash
sudo $EDITOR /etc/netledger/netledger.yaml /etc/netledger/inventory.yaml /etc/netledger/netledger.env
sudo netledger -c /etc/netledger/netledger.yaml validate
sudo systemctl start netledger
journalctl -u netledger -f
```

Upgrade: run the installer again. Uninstall: `sudo deploy/linux/install.sh --uninstall` (keeps
configuration and data).

Prefer a timer over a daemon? `deploy/linux/netledger-oneshot.service` and `.timer` run
`netledger run` hourly instead.

## Windows

Windows Server 2016+ or Windows 10+, with [Python 3.9+](https://www.python.org/downloads/windows/)
and [Git for Windows](https://git-scm.com/download/win). From an **elevated** PowerShell:

```powershell
git clone https://github.com/SalamoneJack/NetLedger.git; cd NetLedger
Set-ExecutionPolicy -Scope Process Bypass
.\deploy\windows\install.ps1 -Source .
```

The installer creates a virtualenv in `C:\Program Files\NetLedger`, writes configuration to
`C:\ProgramData\NetLedger` (ACL restricted to SYSTEM and Administrators), and registers a scheduled
task **NetLedger** that starts `netledger serve` at boot and restarts it every minute if it stops.
Logs go to `C:\ProgramData\NetLedger\logs\netledger.log`.

```powershell
notepad C:\ProgramData\NetLedger\netledger.yaml
notepad C:\ProgramData\NetLedger\inventory.yaml
notepad C:\ProgramData\NetLedger\netledger.env
& "C:\Program Files\NetLedger\Scripts\netledger.exe" -c C:\ProgramData\NetLedger\netledger.yaml validate
Start-ScheduledTask -TaskName NetLedger
```

Run as a domain account (to use Windows-integrated Git credentials or reach devices through a
domain-joined bastion) with a group managed service account:
`.\install.ps1 -ServiceAccount 'CORP\svc-netledger$'`. Uninstall with `-Uninstall`.

## One shot

```bash
# crontab: hourly backup + health, mail on failure
0 * * * *  netledger -c /etc/netledger/netledger.yaml run --log-format text || mail -s "NetLedger" noc@example.com
```

```yaml
# GitHub Actions / GitLab CI against devices reachable from a self-hosted runner
- run: pip install "git+https://github.com/SalamoneJack/NetLedger.git"
- run: netledger -c netledger.yaml backup --json > backup-report.json
```

Exit codes: `backup` returns 0 (ok), 1 (some devices failed), 2 (configuration or repository error);
`health` returns 0/1/2/3 (ok/warning/critical/unknown).

## Choosing a Git backend

| | `git` | `github` | `local` |
|---|---|---|---|
| Needs | `git` executable | nothing extra | `git` executable |
| Hosts | any Git server | GitHub / GitHub Enterprise | none (no push) |
| Auth | HTTPS token, SSH key, GitHub App | token or GitHub App | |
| Local clone | yes (`data_dir/repo`, enables `search` and dashboard history) | no | yes |

All backends handle a repository that changed underneath them: NetLedger replays its commits on
top of the new remote state instead of failing or force-pushing.
