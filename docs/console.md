# Web console

`netledger serve` (and `netledger demo`) include a web console on port 8080. It is rendered by the
NetLedger process itself: no database, no Node.js build and no CDN, so it works on an isolated
management network. Pages are complete without JavaScript; a small script adds live updates, the
command palette, the network map and the configuration time machine.

| Page | What it is for |
|---|---|
| `/` Overview | Fleet status at a glance: KPIs, the network map, what needs attention, the latest changes, 24-hour fleet health, capacity forecasts and the device table. `?site=hq` narrows it to one site. |
| `/devices/<name>` | One device: faceplate with live LEDs, gauges and health checks, trends, the configuration time machine, compliance, LLDP neighbours and backup details. |
| `/changes` | The change ledger: every configuration change, scored and explained, with filters, a change calendar and the most changed devices. |
| `/search` | "Where is…": IP-aware search across every configuration. |
| `/topology` | The full network map. |
| `/wall` | NOC wallboard for a screen on the wall. |

## Change intelligence

Each change is placed in the configuration sections it touched. NetLedger recognizes indentation
(IOS, NX-OS, EOS, IOS-XR, ASA, AOS-CX, ProCurve, Huawei, Comware, Dell, ...), FortiOS `config`/`edit`
blocks, curly braces (Junos, VyOS), `set` commands (PAN-OS, Gaia) and RouterOS exports. Each section is
classified:

| Category | Examples | Base risk |
|---|---|---|
| Access & AAA | users, passwords, AAA, TACACS/RADIUS, SSH/telnet, VTY lines, SNMP communities, management access | high |
| Firewall & ACLs | ACLs and their attachment to interfaces, firewall policies and rules, zones | high |
| Routing | BGP, OSPF, IS-IS, EIGRP, static routes, route maps, prefix lists, VRFs | high |
| VPN | IPsec, IKE, tunnel groups, WireGuard, SSL VPN | high |
| NAT | NAT rules, masquerade, source/destination translation | high |
| Interfaces | interface sections and their addressing | medium |
| VLANs & switching | VLANs, trunks, spanning tree, LACP, MLAG/vPC, EVPN | medium |
| Firewall objects | address and service objects and groups | medium |
| QoS / System | policy maps; hostname, boot, licences | medium |
| Management services | NTP, DNS, logging, SNMP location, LLDP, DHCP | low |
| Descriptions | description, alias, name and remark changes only | low |

Shutting an interface down is always high risk. Changes over 150 lines are raised one level. The score
(0-100) adds up the sections touched, so many medium changes outrank one. Summaries are written the way an
engineer would say them: `Added VLAN 40 (GUEST-WIFI)`, `bgp group LEAFS: added neighbor 10.255.1.5`,
`firewall policy 2 (Servers): service "HTTPS" → …"SSH"`.

### Why it got that risk

Every change also says **why** it scored what it did, in plain English. NetLedger reads what the change does,
not only which section it touched:

| What changed | Example reason | Risk |
|---|---|---|
| A permit / accept / allow rule now matches more: a host or subnet became `any`, `all` or `0.0.0.0/0`, a prefix got shorter, a wildcard got wider, the service became `ip` / `ALL` / `any`, or the rule gained members | `Policy 12 now allows any source (was 10.20.0.0/24)` | high |
| A rule now matches less | `ACL WEB now allows a narrower source: 10.20.0.0/24 (was any)` | unchanged |
| A new rule | `ACL GUEST entry 20: new rule allows any source, any destination and any service`, `ACL GUEST entry 10: new deny rule tightens access (...)` | high when it allows *any* |
| A deny rule removed, a rule switched from deny to permit, a disabled permit rule enabled | `ACL WEB: deny rule removed, so traffic it blocked may now be allowed` | high |
| An address object that rules refer to now covers more | `Address object LAN-NET now covers 10.20.0.0/16 (was 10.20.0.0/24), ...` | high |
| An ACL attached to or detached from an interface | `ACL GUEST removed from interface Vlan40: inbound traffic there is no longer filtered` | high when detached |
| An interface shut down or set admin-down | `Interface GigabitEthernet1/0/8 shut down: traffic through it stops` | high |
| A routing neighbor removed or shut down, a routing process removed | `BGP neighbor 10.255.1.5 removed: routes learned from it are withdrawn` | high |
| Route redistribution added, removed or changed | `Redistribution added in OSPF 1: redistribute static subnets, so more routes are advertised` | high |
| The default route removed or pointed elsewhere | `Default route changed: traffic with no more specific route takes a new path` | high |
| A local account added (admin rights are high), removed, or given different rights; AAA methods and TACACS/RADIUS servers | `New admin account 'jdoe' (privilege 15)`, `Account 'ops' rights changed: privilege 1 → privilege 15` | high for new admin rights |
| Management access opened up: telnet or HTTP allowed, a VTY access-class removed, a FortiGate admin's trusted hosts widened | `Interface wan1 now accepts https and telnet management access (unencrypted)` | high |
| Static NAT or a virtual IP added (it exposes an inside host), source NAT added, NAT removed | `Static NAT added: WEB-VIP maps 203.0.113.10 to 10.1.1.10, which exposes an inside host` | high for static NAT |
| More than 150 changed lines | `Large change: 212 lines` | raised one level |

Rule widening is understood in IOS / IOS-XE / NX-OS / EOS / IOS-XR access lists (wildcards, `host`, `any`,
prefixes, ports and port ranges), ASA access lists (netmasks), FortiOS `config firewall policy`, PAN-OS
`rulebase security rules` and Junos firewall filter terms and SRX security policies. A section with nothing more
specific to say falls back to its category, for example `Routing change (high risk by default): router bgp 65010`.

Reasons are shown next to the risk badge in the change ledger and the time machine, in the commit message (a
`Why:` block under `Risk:`), by `netledger backup`, and in `config_changed` notifications. The JSON API and
`netledger backup --json` return them as `reasons`, for the whole change and for each section.

### Change windows

```yaml
changes:
  windows: ["sat 22:00-sun 04:00", "weekdays 19:00-21:00"]
  timezone: Europe/London
```

A backup only sees a change when it runs, so NetLedger asks whether any window overlaps the period
between the previous successful backup and the backup that found the change. If none does, the change is
**unplanned**: it is flagged in the console and the commit message, and notified with `warning` severity.
Back up frequently (every 10-15 minutes) for precise results.

## Configuration time machine

The rail at the top of the panel is a timeline of every version of the running configuration, coloured by
risk and sized by how much changed.

- **Click** a version (on the rail or in the list) to see what it changed compared with the version before it.
- **Shift-click** another version to compare against that one instead, for example "what changed in the last
  month".
- **Full config** shows the configuration as it was at that version: syntax highlighting, line numbers,
  find-in-config, and sections that collapse when you click their first line.
- **Download** saves that version (masked) for a restore or a review.

Links are shareable: `/devices/core1?to=<commit>&from=<commit>#timemachine`, or
`/devices/core1?view=config&line=120#timemachine` to open the full configuration at a line (search results
link there).

The time machine reads history from the local clone (`git` and `local` backends) or the GitHub API
(`github` backend).

## Where is…?

| You type | NetLedger finds |
|---|---|
| `10.10.40.57` | The interface subnet that contains it on every device (longest prefix first), the device that owns it if it is an interface address, and the routes, objects and ACLs that cover it. The answer card says where it lives. |
| `10.20.0.0/16` or `10.20.0.0 255.255.0.0` | Every subnet inside the range, every supernet covering it, and exact matches. |
| `snmp-server community` | Case-insensitive text. |
| `/ntp server 10\.\d+/` or `re:^hostname` | A regular expression. Nested quantifiers such as `(a+)+` are refused to protect the server. |

Address notations understood: `A.B.C.D M.M.M.M` (masks), ACL wildcards (`0.0.0.255`), CIDR, `host A.B.C.D`,
`address=A.B.C.D/len` (RouterOS) and IPv6. Default routes are not treated as "where" an address is.
Results show each match's configuration section and link to that line in the time machine. The CLI has the
same search: `netledger search 10.10.40.57`.

## Trends and forecasts

Every health check writes one row per device to `<data_dir>/history.db` (SQLite; `health.history`,
`health.history_days`). The console draws:

- 24-hour status strips and CPU/memory sparklines in the device table,
- a 24-hour fleet health chart on the overview,
- CPU, memory and hottest-sensor charts on each device page (24 hours, 7 days, 30 days), with thresholds.

**Forecasts** fit a straight line to the hourly averages of the last seven days. A forecast is shown when
the trend is clearly rising (at least a day of data, slope above 0.05 per day, R² ≥ 0.5) and will reach
the next threshold within 60 days. A `capacity_forecast` event is sent once per episode when that is
within `health.forecast_days` (default 7). The metric `netledger_forecast_seconds_to_threshold` carries
the same information for Prometheus.

## Network map

During health checks NetLedger reads LLDP neighbours (`health.lldp`, NAPALM `get_lldp_neighbors`). Links
are matched by host name (domain stripped) or address and de-duplicated, so a link seen from only one side
still appears: useful for devices whose driver cannot read LLDP, or that are down. Neighbours that are not
in the inventory (servers, access points) appear as *discovered* nodes; the overview map hides them.

Overlays: **Health** (default), **Changes 24h** (rings on devices changed in the last day, coloured by
risk) and **Vendor**. Drag devices to arrange them (remembered in the browser), scroll to zoom, drag the
background to pan, click a device to open it.

## Everyday use

| Key | Action |
|---|---|
| `Ctrl K` / `⌘ K` | Command palette: devices, pages, actions; type an IP and press Enter to find it |
| `/` | Focus the device filter (or the search box) |
| `g` then `o` `m` `c` `s` `w` | Go to overview, map, changes, search, wallboard |
| `Shift` + click | In the time machine: choose the base version |

The console polls `/api/live` every few seconds. Panels that changed are replaced in place, job progress
appears in the sidebar, and new events (config changes, alerts, forecasts) pop up as notifications. The
theme defaults to light (`server.theme`); the toggle in the top bar is remembered per browser.

## JSON API

Everything the console shows is available as JSON (same authentication as the console):

| Endpoint | Returns |
|---|---|
| `GET /api/status` | Version, last runs, schedule |
| `GET /api/devices`, `/api/devices/<name>` | Device state: info, facts, backup, health, compliance, last change |
| `GET /api/devices/<name>/versions` | Configuration versions with risk, summary and engineer |
| `GET /api/devices/<name>/diff?from=<sha>&to=<sha>` | Masked unified diff and change analysis |
| `GET /api/devices/<name>/config?rev=<sha>` | Masked configuration at a version (`&download=1` for a file) |
| `GET /api/devices/<name>/trends?range=24h\|7d\|30d` | History series |
| `GET /api/changes?limit=&device=` | The change ledger, newest first |
| `GET /api/search?q=` | Search results (`&regex=1` to force a regular expression) |
| `GET /api/topology` | Nodes and links |
| `GET /api/live?cursor=` | Revision, job progress and new events, for polling |
| `POST /api/run/backup`, `/api/run/health` | Start a job (`Authorization: Bearer <api_token>`) |

## Security

The console never displays a secret: configurations, diffs and search results are masked with the platform's
secret rules even when the repository keeps them (`normalize.secrets: keep`). Pages are served with a strict
Content Security Policy (`script-src 'self'`, no inline scripts) and everything a device can influence is
escaped. Use `server.username`/`password` or `api_token`, and put it behind TLS (an ingress or reverse proxy)
outside a lab.
