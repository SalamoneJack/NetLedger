# Health checks

`netledger health` (and the `health` job in `netledger serve`) logs in to each device, reads
`get_facts()` and `get_environment()` through NAPALM, and grades the result.

## Checks

| Check | How it is graded |
|---|---|
| **Reachability** | A device that cannot be reached or logged into is `unknown` until it has failed `health.unreachable_after` consecutive checks (default 2), then `critical`. This avoids alerts from a single dropped packet. |
| **CPU** | The busiest CPU/core against `thresholds.cpu` (default warning 80 %, critical 95 %). |
| **Memory** | Used / total against `thresholds.memory` (85 % / 95 %). NetLedger corrects for drivers that report free rather than total memory (NX-API). |
| **Temperature** | Every sensor. A sensor is `warning` when the device flags it as alerting, `critical` when the device flags it critical, and/or when it crosses `thresholds.temperature` if you set them. |
| **Fans / power supplies** | Any failed unit raises `health.fan_failure` / `health.psu_failure` (default `warning`). Absent units are not reported as failures. |
| **Reboots** | If a device's uptime is shorter than the time since the last successful check, it rebooted in between: a `device_rebooted` event is sent and the dashboard shows "rebooted 12m ago". This doesn't change the health status. |

The device status is the worst status of its checks. Devices whose driver has no environment data
(`generic`) are graded on reachability only.

## Per-device settings

```yaml
devices:
  - name: dc1-spine01
    platform: junos
    health:
      thresholds:
        cpu: {warning: 90, critical: 98}      # routing engines run hot
        temperature: {warning: 65}
      ignore_sensors: ["^PEM 1"]              # empty power slot
  - name: lab-sw
    platform: ios
    health: false                             # never health-check this one
```

Groups can carry the same `health:` block, so thresholds can be set per role or site.

## Alerting behaviour

Events are sent on **transitions** only, so you are not paged every five minutes:

- `health_warning` / `health_critical`: the device moved into that state (also on escalation from
  warning to critical).
- `health_recovered`: back to OK after warning or critical.
- `device_rebooted`: always, when detected.
- `capacity_forecast`: when a rising trend is predicted to cross a threshold within
  `health.forecast_days`; sent again only after the prediction has cleared.

State is kept in `data_dir/state.json`. On Kubernetes, keep the persistent volume so restarts don't
reset it.

## History, trends and forecasts

Every check is stored in `data_dir/history.db` (SQLite, `health.history_days` days, 30 by default):
worst status, busiest CPU core, memory, hottest sensor and response time. The [web console](console.md)
uses it for 24-hour status strips, sparklines, fleet health and per-device charts.

Memory and temperature are forecast from the hourly averages of the last seven days. A forecast is shown
when the trend clearly rises (at least a day of data, slope over 0.05 per day, R² ≥ 0.5) and will reach the
next threshold (warning, then critical) within 60 days. Typical catches: memory leaks (IOS, FortiOS
conserve mode), a failing fan tray or blocked airflow that raises temperatures day after day.

Set `health.history: false` to keep nothing, or `health.forecast_days: 0` to show forecasts without
alerting.

## LLDP neighbours

With `health.lldp: true` (default) each check also reads NAPALM `get_lldp_neighbors()` where the driver
supports it (`ios`, `nxos`, `eos`, `junos`, `iosxr` and any NAPALM driver that implements it). The
neighbours appear on the device page and in the [network map](console.md#network-map). A link needs to be
seen from one side only.

## Exit codes

`netledger health` exits like a Nagios plugin, so it can feed existing monitoring:

| Code | Meaning |
|---|---|
| 0 | all devices OK |
| 1 | at least one warning |
| 2 | at least one critical |
| 3 | only unknown results, or a configuration error |

`netledger health --json` prints machine-readable results.

## Prometheus metrics

`netledger serve` exposes `/metrics` (labels: `device`, `site`, `platform`):

| Metric | Type | Description |
|---|---|---|
| `netledger_device_up` | gauge | 1 if the last health check reached the device |
| `netledger_health_status` | gauge | 0 ok, 1 warning, 2 critical, 3 unknown |
| `netledger_cpu_usage_percent` | gauge | busiest core |
| `netledger_memory_usage_percent`, `netledger_memory_used_bytes`, `netledger_memory_total_bytes` | gauge | memory |
| `netledger_temperature_celsius{sensor}` | gauge | each temperature sensor |
| `netledger_temperature_alert{sensor}` | gauge | 1 when a sensor is above a threshold or alarming |
| `netledger_fan_ok{fan}`, `netledger_power_supply_ok{psu}` | gauge | hardware state |
| `netledger_device_uptime_seconds` | gauge | uptime at the last check |
| `netledger_backup_success` | gauge | 1 if the last backup succeeded |
| `netledger_backup_last_success_timestamp_seconds` | gauge | |
| `netledger_backup_last_change_timestamp_seconds` | gauge | last detected configuration change |
| `netledger_backup_consecutive_failures` | gauge | |
| `netledger_config_changes_total` | counter | configuration changes detected |
| `netledger_config_unsaved` | gauge | 1 when running and startup differ |
| `netledger_compliance_ok{rule}` | gauge | 1 when a compliance rule passes |
| `netledger_run_last_timestamp_seconds{job}`, `netledger_run_duration_seconds{job}` | gauge | job runs |
| `netledger_backup_run_error` | gauge | 1 if the last backup run could not reach the repository |
| `netledger_forecast_seconds_to_threshold{metric,level}` | gauge | predicted time until memory or temperature crosses a threshold |

Ready-made alert rules: [deploy/prometheus/netledger-alerts.yml](../deploy/prometheus/netledger-alerts.yml)
(standalone Prometheus) and [deploy/kubernetes/optional/prometheusrule.yaml](../deploy/kubernetes/optional/prometheusrule.yaml)
(Prometheus Operator; also `prometheusRule.enabled` in the Helm chart).
