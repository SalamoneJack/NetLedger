# Already using Oxidized?

Keep it. [Oxidized](https://github.com/ytti/oxidized) is great at collecting configurations from a very
long list of devices. NetLedger can sit on top of it and add what Oxidized does not do: change
intelligence (what a change did, how risky it is and why), change windows, compliance rules,
Slack/Teams/email alerts with the reasons, and the web console with its time machine, change ledger and
"where is" search.

In this mode:

- **NetLedger does not log in to the devices** to back them up. Oxidized does that.
- **NetLedger never writes to Oxidized's repository.** It only reads it, or its API.
- **NetLedger keeps its own history** of what it processed, for the console and its commit messages. A local
  repository is enough (`git.backend: local`), so no remote is needed.
- **Health checks stay optional.** Enable them per device (or for all of them with `defaults`). They log in
  with NetLedger's own credentials.

## Read Oxidized's git output (repo mode)

```yaml
inventory:
  - type: oxidized
    path: /var/lib/oxidized/configs.git      # Oxidized's output.git.repo (read access is enough)
    router_db: /var/lib/oxidized/router.db   # optional: each node's model, for its platform

git:
  backend: local
```

Every commit Oxidized made since the last run becomes a change of its own. It is analysed and alerted
with the commit's time, and with its author as *changed by* when the configuration itself does not say
who changed it. Oxidized's default identity (`Oxidized` / `o@example.com`) is ignored. The first time
NetLedger reads a repository, it records the current configuration of every node without reporting
anything.

- **One repository per group** (Oxidized's `single_repo: false`): point `path` at the folder that holds the
  `<group>.git` repositories. The group of each node comes from its repository's name.
- **Groups in one repository** (`<group>/<node>` files): the group comes from the folder.
- **Oxidized running elsewhere** (in Docker, for example): mount its repository read-only into NetLedger's
  container. NetLedger reads repositories owned by another user without complaint.

## Poll the Oxidized API (api mode)

```yaml
inventory:
  - type: oxidized
    mode: api
    url: http://oxidized:8888                # oxidized-web
    username: ${OXIDIZED_USER:-}             # optional basic auth (usually added by a reverse proxy)
    password: ${OXIDIZED_PASSWORD:-}
```

NetLedger reads `/nodes.json` for the nodes, their models, groups and addresses. When a node's
modification time changes, it fetches the configuration with `/node/fetch/<group>/<node>`, and asks
`/node/version.json` who made the latest version and when (this needs Oxidized's git output).

A node that Oxidized failed to fetch (`no_connection`) counts as a failed backup, so
`backup.failure_alert_after` and the `backup_failed` alert work as usual.

The API mode sees the latest version at each poll. The repo mode sees every commit, even when several
happened between two polls.

## Platforms

Oxidized models map to NetLedger platforms. NetLedger accepts both the model's file name and its class
name, in any case:

| Oxidized model | Platform | Oxidized model | Platform |
|---|---|---|---|
| `ios`, `iosxe` | `ios` | `routeros` | `routeros` |
| `iosxr` | `iosxr` | `procurve` | `procurve` |
| `nxos` | `nxos` | `aoscx` | `aoscx` |
| `asa` | `asa` | `comware`, `h3c` | `comware` |
| `aireos` | `aireos` | `vrp` | `huawei_vrp` |
| `ciscosmb` | `cisco_smb` | `ironware`, `fastiron` | `fastiron` |
| `junos` | `junos` | `os10` | `dellos10` |
| `eos` | `eos` | `xos` | `exos` |
| `fortios`, `fortigate` | `fortios` | `vyos`, `vyatta` | `vyos` |
| `panos`, `panos_api` | `panos` | `edgeos` | `edgeos` |
| | | `gaiaos` | `gaia` |

When the model is not known, as in repo mode without `router_db`, NetLedger recognizes the platform from
the configuration itself, and falls back to `generic`. You can change or extend the mapping, and set
anything per device:

```yaml
inventory:
  - type: oxidized
    path: /var/lib/oxidized/configs.git
    platform_map: {screenos: generic, ios: nxos}  # Oxidized model -> NetLedger platform
    groups: [core, dc1]                           # only these Oxidized groups (default: all)
    defaults:                                     # every device from this source
      site: hq
    devices:                                      # per node, any inventory field
      edge-fw01:
        platform: panos
        health: true                              # health checks for this one
        credentials: [default]
```

The device name is the Oxidized node name. Groups become NetLedger groups, so `-g core` filters and
`git.path: "{group}/{name}"` folders work. A device's address, used only for health checks, is the IP that
the API reports. In repo mode it is the node name (resolved by DNS) unless `devices` sets a `host`.

## React to changes immediately

`netledger serve` looks for new configurations every `poll` (default `every 5m`). To process a change as
soon as Oxidized stores it, let Oxidized call NetLedger with an exec hook:

```yaml
# Oxidized config
hooks:
  netledger:
    type: exec
    events: [post_store]
    async: true
    cmd: 'curl -s -X POST -H "Authorization: Bearer $NETLEDGER_HOOK_TOKEN" -H "Content-Type: application/json" -d "{\"node\": \"$OX_NODE_NAME\", \"group\": \"$OX_NODE_GROUP\"}" http://netledger:8080/api/hooks/oxidized'
```

```yaml
# netledger.yaml
inventory:
  - type: oxidized
    path: /var/lib/oxidized/configs.git
    hook_token: ${NETLEDGER_HOOK_TOKEN}      # Bearer token for POST /api/hooks/oxidized
    # hook_secret: ${NETLEDGER_HOOK_SECRET}  # or an HMAC-SHA256 of the body in X-NetLedger-Signature: sha256=...
```

The hook only starts processing. NetLedger then reads Oxidized as usual, so it never trusts the request
body. Hooks that arrive while a run is busy start one more run when it finishes. `server.api_token` is
accepted too. Without a token or secret, the endpoint is refused.

## LibreNMS

LibreNMS uses Oxidized for configuration backups. Point NetLedger at the same Oxidized instance, through
its API or its git repository, and LibreNMS keeps showing configurations while NetLedger analyses and
alerts on every change.

## Settings

| Key | Default | Description |
|---|---|---|
| `type` | | `oxidized` |
| `mode` | `repo` | `repo` (git output) or `api` (oxidized-web) |
| `path` | | repo: Oxidized's repository, or the folder of its per-group repositories |
| `router_db` / `router_db_delimiter` | / `:` | repo: Oxidized's CSV source (`name:model[:...]`), for the models |
| `url`, `username`, `password` | | api: oxidized-web and optional basic auth; `verify_ssl`, `timeout` apply |
| `platform_map` | `{}` | Oxidized model -> NetLedger platform, on top of the built-in mapping |
| `groups` | all | Only nodes in these Oxidized groups |
| `defaults`, `devices` | | Inventory fields for every device, and per device (by node name) |
| `poll` | `every 5m` | How often `netledger serve` looks for new configurations (cron syntax works too) |
| `hook_token`, `hook_secret` | | Authentication for `POST /api/hooks/oxidized` |
| `use_commit_author` | `true` | Use the commit author as *changed by* when the configuration does not say |

`netledger backup` (or `run`) processes Oxidized sources together with any devices NetLedger backs up
itself, so both can live in one inventory.
