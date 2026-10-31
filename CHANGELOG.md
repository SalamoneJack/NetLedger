# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-30

### Added

- Configuration backup through NAPALM for Cisco IOS/IOS-XE, NX-OS, IOS-XR, Arista EOS and Juniper Junos.
- Built-in NAPALM drivers for Fortinet FortiGate (multi-VDOM aware), Cisco ASA, Cisco AireOS WLC,
  Cisco Small Business, Palo Alto PAN-OS, Huawei VRP, HPE Comware/H3C, HPE Aruba AOS-S (ProCurve),
  HPE Aruba AOS-CX, MikroTik RouterOS, Dell OS10, Extreme EXOS, VyOS, Ubiquiti EdgeOS, Ruckus ICX and
  Check Point Gaia, plus a generic driver for any of Netmiko's device types.
- Git storage: any Git server over HTTPS token or SSH key, or the GitHub REST API (no git binary needed),
  GitHub App authentication, per-device or per-run commits, generated repository index.
- Noise-free history: per-platform rules strip timestamps, byte counts and re-encrypted secrets;
  optional secret masking or keyed hashing.
- Commit messages with "changed by" details parsed from device headers.
- Health checks for CPU, memory, temperature, fans, power supplies, reachability and reboots with
  thresholds, per-device overrides and transition-based alerting.
- Compliance (golden configuration) rules evaluated on every backup.
- Unsaved-configuration detection (running vs. startup).
- Notifications to Slack, Microsoft Teams, Discord, e-mail, PagerDuty and signed webhooks.
- Change intelligence: every change is placed in the sections it touched (indentation, FortiOS blocks,
  Junos braces, set commands, RouterOS), classified, risk-scored and summarized in plain English in the
  console, commit messages and notifications. Change windows flag unplanned changes.
- Web console: overview with KPIs, live network map, attention list, change ledger, 24-hour fleet health and
  capacity forecasts; device pages with an equipment faceplate, gauges, trends and a configuration time
  machine (any-to-any diffs, full configurations at any version, downloads); a change ledger page;
  "Where is" IP-aware search; a full network map; a NOC wallboard; command palette; live updates; light
  (default) and dark themes. Secrets are always masked.
- Health history in SQLite with trends, status strips and memory/temperature exhaustion forecasts
  (`capacity_forecast` event, `netledger_forecast_seconds_to_threshold` metric).
- LLDP neighbour collection for the network map.
- `netledger search` understands IP addresses and subnets in every vendor notation.
- JSON API, Prometheus metrics and Kubernetes probes.
- Inventory from YAML (with group inheritance), CSV and NetBox.
- Built-in scheduler, `netledger demo` with simulated devices, Docker image, Kubernetes manifests,
  Helm chart, systemd installer and Windows installer.
