# Troubleshooting

Start with:

```bash
netledger validate                          # configuration, credentials, drivers
netledger test -d DEVICE --show-config --health
netledger --log-level DEBUG backup -d DEVICE --dry-run
NETLEDGER_DEBUG_LIBS=1 netledger --log-level DEBUG test -d DEVICE   # include Netmiko/Paramiko logs
```

For a raw transcript of a CLI session add `optional_args: {session_log: /tmp/DEVICE.log}` to the
device (Netmiko-based platforms). **The log contains passwords**, so delete it afterwards.

## Connecting

**`Authentication failed`.** Check the credential set name and the variables behind it. If several
sets are listed, all were tried. For TACACS/RADIUS, check the AAA server's logs too.

**`TCP connection ... timed out`.** Routing/ACLs between NetLedger and the device, the port
(`port:`), or a management VRF. From Kubernetes, check NetworkPolicies and that the pod network can
reach the management range.

**Old devices: `Incompatible ssh peer`, `no matching key exchange`, `no acceptable host key`.**
Re-enable legacy algorithms for that device:

```yaml
optional_args:
  disabled_algorithms: {pubkeys: [rsa-sha2-512, rsa-sha2-256]}   # allow ssh-rsa
```

Devices without SSH: `optional_args: {transport: telnet}`.

**Behind a bastion / jump host.** Use an SSH config file with `ProxyJump` and point the device (or a
group) at it: `optional_args: {ssh_config_file: /etc/netledger/ssh_config}`.

**`could not enter privileged mode` (ASA, ICX, SMB) or an empty IOS configuration.** Provide the
enable password as `secret` in the credential set, or give the account privilege level 15.

## Backups

**`ReadTimeout` / pattern not detected on large configurations.** Raise `backup.command_timeout`
(default 180 s). FortiGate `show full-configuration` and big ASR/Nexus configurations can take
minutes.

**`running configuration shrank from N to M lines; not committing it`.** This is the shrink guard
protecting the last good backup. It usually means truncated output or missing privileges. If the
change is real (a big cleanup), run once with `backup.shrink_guard: 0`.

**A device commits on every run.** Something in its configuration changes on every read. Find the
line with `git log -p -- configs/<device>` and either report it (we'll add a platform rule) or
drop/rewrite it yourself:

```yaml
normalize:
  rules:
    - pattern: '^! Last reload'
      platforms: [ios]
```

**FortiGate shows `set psksecret ENC <encrypted>`.** Deliberate: FortiOS re-encrypts these on every
read. Disable the `fortios.enc` rule to keep raw values (and accept noisy history), or use
`secrets: hmac` to track real secret changes.

**`git.url is required`.** Set `git.backend: local` to commit to `data_dir/repo` without a remote.

## Git

**`fatal: Authentication failed` / HTTP 403 on push.** The token needs write access to the repository
(fine-grained token: **Contents: Read and write**). The token is never written to `.git/config`, so
`git push` by hand inside `data/repo` will not work without your own credentials. That's expected.

**`the 'git' executable was not found`.** Install Git, or use `git.backend: github`, which talks to
the GitHub API directly.

**`... contains a damaged Git repository`.** With a remote configured, NetLedger moves a damaged
working copy aside and clones again automatically. With `backend: local` the repository is the only
copy, so repair or move it yourself.

**Branch protection.** NetLedger pushes commits directly. Allow the token's identity to bypass branch
protection on the backup branch, or use a dedicated branch (`git.branch: backups`).

## Health

**A metric is missing for my model.** Run `netledger test -d DEVICE --health` and look at the checks.
Then open a [platform issue](https://github.com/SalamoneJack/NetLedger/issues/new?template=platform_request.yml)
with the raw output of the health commands listed in [platforms.md](platforms.md), sanitized.

**False alarms for an empty PSU slot or an unused sensor.** `health.ignore_sensors` (global) or
`health: {ignore_sensors: ["^PS2"]}` on the device.

**Memory looks wrong.** Some drivers report free instead of total memory. Open an issue with
`netledger test -d DEVICE --health` output and the device's own memory command output.

## Dashboard

**`401` in the browser.** `server.username`/`password` is set; log in with those. API clients use
`Authorization: Bearer <server.api_token>`.

**"Run backup" buttons are missing.** Remote triggers are disabled until `server.api_token` or
`server.username`/`password` is configured.
