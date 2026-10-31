# Platforms

Every platform maps to a NAPALM driver plus normalization rules (volatile-line removal, secret
patterns and "changed by" extraction). Use the platform key or any alias in the inventory;
`netledger platforms` prints the full list.

NAPALM core drivers are used where they exist. For everything else NetLedger ships its own NAPALM
drivers built on Netmiko. They implement `get_config`, `get_facts`, `get_environment`, `cli` and
`is_alive`, so they also work in your own NAPALM scripts:

```python
from netledger.drivers.fortinet import FortiOSDriver
with FortiOSDriver("fw01.example.com", "admin", "secret") as fw:
    print(fw.get_environment()["cpu"])
```

> **About parsers:** built-in health parsers are written against documented and sampled vendor
> output and are covered by unit tests. CLI output varies between OS releases. If a metric is
> missing for your model, run `netledger test -d DEVICE --health`, then open an issue with the raw
> output of the commands listed below (sanitized). Configuration backup only depends on the config
> command and works regardless.

## Cisco

| Key | Aliases | Transport | Config | Health commands |
|---|---|---|---|---|
| `ios` | `cisco_ios`, `iosxe`, `ios_xe`, `catalyst` | SSH/telnet (NAPALM `ios`) | `show running-config`, `show startup-config` | NAPALM: `show environment all`, `show processes cpu`, `show memory statistics` |
| `nxos` | `cisco_nxos`, `nxos_ssh`, `nexus` | SSH (NAPALM `nxos_ssh`) | `show running-config` / `startup-config` | NAPALM |
| `nxos_api` | `nxapi` | NX-API (NAPALM `nxos`) | | NAPALM; needs `feature nxapi` |
| `iosxr` | `cisco_xr` | XML agent (NAPALM `iosxr`) | running, candidate | NAPALM; needs `xml agent tty` |
| `iosxr_netconf` | | NETCONF | running, candidate | NAPALM |
| `asa` | `cisco_asa` | SSH | `show running-config` (`all` with `backup.full`), `show startup-config` | `show cpu usage`, `show memory`, `show environment` |
| `aireos` | `cisco_wlc`, `wlc` | SSH | `show run-config commands` | `show cpu`, `show memory statistics`, `show sysinfo` |
| `cisco_smb` | `cisco_s300`, `sg300`, `sg350`, `cbs` | SSH | `show running-config`, `show startup-config` | `show cpu utilization`, `show system` |

- **IOS/IOS-XE:** NetLedger extends NAPALM's driver to keep the `! Last configuration change at …
  by <user>` header, so commit messages say who made the change (the header is then removed from
  the stored file). `ntp clock-period`, byte counts and exec-prompt timestamps are stripped.
- **ASA:** `show running-config` masks some keys as `*****`. For a fully restorable backup set
  `optional_args: {config_command: "more system:running-config"}` (and keep the repository private).

## Fortinet

| Key | Aliases | Config | Health commands |
|---|---|---|---|
| `fortios` | `fortinet`, `fortigate`, `forti` | `show` (`show full-configuration` with `backup.full`) | `get system status`, `get system performance status`, `execute sensor list` |

- **Multi-VDOM** devices are detected automatically; health commands run in `config global`.
- **Noise removal:** FortiOS re-encrypts reversible secrets (`set psksecret ENC …`) with a random salt
  every time the configuration is displayed, and `#conf_file_ver` changes constantly. NetLedger
  normalizes both, plus encrypted private keys, so a FortiGate only commits when its configuration
  really changes. Stable password hashes (`ENC SH2…`) are kept. To keep the raw encrypted values,
  add `fortios.enc` and `fortios.private-key` to `normalize.disable_rules`.
- Use an administrator profile with read access to system settings. `execute sensor list` needs
  hardware; FortiGate-VM simply reports no sensors.

## Juniper and Arista

| Key | Aliases | Transport | Notes |
|---|---|---|---|
| `junos` | `juniper`, `srx`, `ex`, `mx`, `qfx` | NETCONF over SSH | `set system services netconf ssh`. `## Last commit … by user` feeds "changed by". Secrets marked `## SECRET-DATA` are masked. |
| `eos` | `arista`, `arista_eos` | eAPI (HTTPS) | `management api http-commands` / `no shutdown`. |

## Palo Alto Networks

| Key | Aliases | Config | Health commands |
|---|---|---|---|
| `panos` | `paloalto`, `pan_os`, `palo` | `show config running` in `set` format | `show system info`, `show system resources`, `show system environmentals` |

`set` format diffs beautifully. Use `optional_args: {config_format: xml}` for restorable XML.
Health reflects the management plane; environmentals exist on hardware models only.

## HPE / Aruba / H3C

| Key | Aliases | Config | Health commands |
|---|---|---|---|
| `comware` | `hp_comware`, `h3c` | `display current-configuration` / `saved-configuration` | `display cpu-usage`, `display memory`, `display environment`, `display fan`, `display power` |
| `procurve` | `hp_procurve`, `aruba_osswitch`, `aos_s` | `show running-config`, `show config` | `show system`, `show system temperature`, `show system fans`, `show system power-supply` |
| `aoscx` | `aruba_aoscx`, `aos_cx` | `show running-config` / `startup-config` | `show system`, `show environment temperature`, `… fan`, `… power-supply` |

## Huawei

| Key | Aliases | Config | Health commands |
|---|---|---|---|
| `huawei_vrp` | `huawei`, `vrp` | `display current-configuration` / `saved-configuration` | `display version`, `display esn`, `display cpu-usage`, `display memory-usage`, `display temperature all`, `display fan`, `display power` |

`!Last configuration was updated at … by <user>` feeds "changed by".

## MikroTik

| Key | Aliases | Config | Health commands |
|---|---|---|---|
| `routeros` | `mikrotik`, `ros` | `/export terse` (one line per command, ideal for diffs) | `/system resource print`, `/system health print` (v6 and v7 formats) |

The export timestamp is normalized. RouterOS 7 hides secrets in exports by default; set
`optional_args: {show_sensitive: true}` to include them.

## Others

| Key | Aliases | Config | Health |
|---|---|---|---|
| `dellos10` | `dell_os10`, `os10` | `show running-configuration` / `startup-configuration` | `show processes node-id 1`, `show environment`, `show system` |
| `exos` | `extreme_exos`, `extreme`, `switch_engine` | `show configuration` | `show cpu-monitoring`, `show memory`, `show temperature`, `show fans`, `show power` |
| `fastiron` | `ruckus_fastiron`, `icx`, `brocade_fastiron` | `show running-config` / `show configuration` | `show cpu-utilization`, `show memory`, `show chassis` |
| `vyos` | | `show configuration commands` | Linux: `top`, `/proc/meminfo`, thermal zones, `/proc/uptime` |
| `edgeos` | `ubiquiti_edgerouter`, `edgerouter` | `show configuration commands` | as VyOS |
| `gaia` | `checkpoint_gaia`, `checkpoint` | `show configuration` (clish) | `show sysenv all`, `show asset all`, `show uptime` |

**Check Point:** this backs up the Gaia OS configuration of a gateway. Security policy lives on the
management server; back that up with Check Point's own tools.

## Anything else

**Any Netmiko device type** (config backup only):

```yaml
- name: lab-xr1
  host: 10.99.0.9
  platform: generic
  optional_args:
    netmiko_device_type: cisco_xr          # one of Netmiko's 200+ types
    config_command: show running-config
    startup_command: null
```

**Any NAPALM driver**, including community drivers (`pip install napalm-sros`, `napalm-ros`, ...):

```yaml
- name: pe1
  host: 10.0.0.50
  platform: sros               # any label - used for display and rules
  driver: sros                 # NAPALM driver name, or module:Class for your own
```

Unknown platforms get no normalization rules; add your own under `normalize.rules`. To add full
support for a platform, see [writing-drivers.md](writing-drivers.md).
