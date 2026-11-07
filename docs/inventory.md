# Inventory

The inventory says which devices exist and how to reach them. Sources are listed under
`inventory:` in `netledger.yaml` and can be mixed:

```yaml
inventory:
  - inventory.yaml              # a file
  - inventory.d/                # every *.yaml, *.yml and *.csv in a folder
  - sites/*.yaml                # a glob
  - path: exports/switches.csv  # with defaults for every device in it
    defaults: {platform: procurve, credentials: switches}
  - type: netbox                # NetBox (see below)
    url: https://netbox.example.com
    token: ${NETBOX_TOKEN}
```

If two sources define the same device name, the later one wins (a warning is logged), which makes
an `overrides.yaml` after a NetBox source a handy pattern. The inventory is re-read at the start of
every run, so changes apply without restarting `netledger serve`.

## YAML

```yaml
defaults:                       # applied to every device in this file
  credentials: default

groups:
  cisco:
    platform: ios
    optional_args: {secret: "${ENABLE}"}
  core:
    groups: [cisco]             # groups can inherit from groups
    role: core
    tags: [critical]
  dc1:
    site: dc1
  lab:
    risk: {multiplier: 0.5}     # lab changes score half as much

devices:
  - name: dc1-core1
    host: 10.20.0.1             # defaults to the name (DNS) when omitted
    groups: [core, dc1]
    tags: [pci]
  - name: dc1-fw1
    host: 10.20.0.2
    platform: fortios
    site: dc1
    credentials: [tacacs, local-fallback]
```

`devices` may also be a mapping (`devices: {dc1-core1: {host: …}}`).

**Merge order:** `defaults` → each group in order (parents before children) → the device. Mappings
such as `optional_args`, `vars` and `health` are merged key by key; `tags` are combined; anything
else is replaced by the more specific layer.

### Device fields

| Field | Description |
|---|---|
| `name` | Unique name; also the folder name in the repository. |
| `host` | IP address or DNS name. Defaults to `name`. |
| `platform` | A NetLedger platform or alias (`netledger platforms`). |
| `driver` | Override the driver: any NAPALM driver name (`sros`, `napalm-ros`'s `ros`...), `napalm:<name>`, `module:Class`, or `simulated`. |
| `port` | TCP port, if not the default. |
| `site`, `role`, `description` | Free text; used in folder templates, filters and the dashboard. |
| `groups`, `tags` | Lists (or comma-separated strings); usable in filters and compliance scoping. |
| `credentials` | Credential set name(s), tried in order. Default `default`. |
| `username`, `password`, `secret` | Inline credentials (prefer credential sets). `secret` = enable password. |
| `optional_args` | Passed to the NAPALM driver (and on to Netmiko). See below. |
| `timeout` | Connection timeout for this device. |
| `backup`, `health` | `false` to skip a device in that job. `health` may also be `{thresholds: …, ignore_sensors: […]}`. |
| `retrieve` | Override `backup.retrieve`, e.g. `[running, startup]`. |
| `commands` | Extra show commands for this device (same format as `backup.commands`). |
| `vars` | Your own data; ignored by NetLedger. |
| `risk` | How this device's changes are scored: `{categories: {...}, weights: {...}, multiplier: 1.5}`, the same keys as the global [`risk`](configuration.md#risk) block. Set it on a group to cover a whole class of devices, e.g. `lab: {risk: {multiplier: 0.5}}`. In CSV use `risk.multiplier` or `risk.categories.services` headers. |
| `enabled` | `false` removes the device from every job. |

### Useful optional_args

| Key | Applies to | Purpose |
|---|---|---|
| `transport: telnet` | ios, built-in drivers | For devices without SSH. |
| `secret` | ios, nxos, built-in drivers | Enable password (usually set via credentials). |
| `ssh_config_file` | Netmiko-based | Use `~/.ssh/config`, e.g. for `ProxyJump` through a bastion. |
| `disabled_algorithms` | Netmiko-based | Talk to old SSH servers, e.g. `{pubkeys: [rsa-sha2-512, rsa-sha2-256]}`. |
| `ssh_strict`, `system_host_keys`, `alt_host_keys`, `alt_key_file` | Netmiko-based | Enforce SSH host-key verification. |
| `config_command`, `startup_command` | built-in drivers | Override the commands used to read configurations. |
| `netmiko_device_type` | built-in drivers, `generic` | Override / set the Netmiko device type. |
| `config_format` | `panos` | `set` (default), `xml`, `json` or `default`. |
| `show_sensitive` | `routeros` | Include secrets in RouterOS 7 exports. |
| `session_log` | Netmiko-based | Write the raw session to a file for troubleshooting (contains secrets!). |

## CSV

Spreadsheet exports work directly. The header row names the fields; list values use `;` or `|`;
dotted headers create nested values.

```csv
name,host,platform,site,tags,credentials,port,optional_args.secret
core-sw01,10.0.0.11,ios,hq,core;critical,default,,
fw01,10.0.0.1,fortios,hq,security,default,,
old-sw01,10.0.9.9,ios,hq,legacy,default,,${OLD_SWITCH_ENABLE}
```

A complete example is in [examples/inventory.csv](../examples/inventory.csv). Set `enabled` to
`false` to skip a row. `${VAR}` references work in cells.

## NetBox

```yaml
inventory:
  - type: netbox
    url: https://netbox.example.com
    token: ${NETBOX_TOKEN}
    auth_scheme: Token                 # "Bearer" for NetBox v2 tokens
    filters:                           # any /api/dcim/devices/ query parameters
      status: active
      has_primary_ip: "true"
      tag: netledger-backup
    platform_map:                      # NetBox platform slug (or name) -> NetLedger platform
      cisco-ios-xe: ios
      fortigate: fortios
    site_field: slug                   # or name
    include_virtual_machines: false
    defaults:                          # applied to every NetBox device
      credentials: default
```

- The host is the primary IP address (prefix length removed), falling back to the device name.
- The platform comes from `platform_map`, then the slug itself if it is a known NetLedger platform
  or alias, then NetBox's `napalm_driver` field. Unmapped devices are skipped with a warning.
- Site, role and tags are copied over.
- Anything under the `netledger` key of a device's **config context** is merged into that device, so
  `{"netledger": {"port": 2222, "credentials": ["local"]}}` works per device, site or role.

## Filters

Every device command accepts filters; multiple values of one filter are OR'ed, different filters
are AND'ed, and globs are allowed:

```bash
netledger backup -d 'core-*' -d fw01        # names or hosts
netledger health -s hq -t critical          # site AND tag
netledger test -p fortigate -g firewalls    # platform aliases work
```
