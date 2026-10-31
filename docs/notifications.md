# Notifications

Notifiers are configured as a list under `notifications:`. Each one can filter by event type and
minimum severity, so you can send config changes to a team channel and only critical problems to
the pager.

```yaml
notifications:
  - type: slack
    name: netops-channel
    url: ${SLACK_WEBHOOK_URL}
    events: [config_changed, compliance_failed, device_rebooted]
  - type: pagerduty
    routing_key: ${PAGERDUTY_ROUTING_KEY}
    events: [health_critical, health_recovered, backup_failed, backup_recovered]
  - type: email
    smtp_host: smtp.example.com
    smtp_username: netledger@example.com
    smtp_password: ${SMTP_PASSWORD}
    from_address: netledger@example.com
    to: [noc@example.com]
    min_severity: warning
```

Run `netledger notify-test` to send a test message through each notifier.

## Events

| Event | Severity | When |
|---|---|---|
| `config_changed` | info, **warning when unplanned** | A device's configuration changed (not sent for the very first backup). Includes the risk, a plain-English summary of what changed and the masked diff. Changes outside `changes.windows` are titled *unplanned configuration change* and sent as `warning`. |
| `backup_failed` | warning | A device failed `backup.failure_alert_after` backups in a row. |
| `backup_recovered` | info | Backups work again after `backup_failed`. |
| `health_warning` / `health_critical` | warning / critical | A device entered that health state. |
| `health_recovered` | info | Back to OK. |
| `device_rebooted` | `health.reboot` (warning) | Uptime shows a reboot since the last check. |
| `compliance_failed` | the rule's severity | A compliance rule started failing. |
| `compliance_passed` | info | It passes again. |
| `capacity_forecast` | warning | Memory or temperature is predicted to cross a threshold within `health.forecast_days`. Sent once per episode. |

Common settings for every notifier:

| Key | Default | Description |
|---|---|---|
| `name` | the type | Label used in logs. |
| `events` | all | Event types to send (`all` is accepted). |
| `min_severity` | `info` | `info`, `warning` or `critical`. |
| `include_diff` | `true` | Attach the configuration diff to `config_changed`. **Secrets are always masked in notification diffs**, whatever `normalize.secrets` says. |
| `max_diff_lines` | `60` | Longer diffs are truncated (with a link to the full commit). |
| `max_per_run` | `10` | If one run produces more events for this notifier, they are folded into one digest message. |
| `timeout`, `verify_ssl`, `headers` | `10`, `true`, `{}` | HTTP settings. |

## Slack

Create an [incoming webhook](https://api.slack.com/messaging/webhooks) and set `url`. Messages use
Block Kit: title, details, the diff in a code block and buttons linking to the commit and history.

## Microsoft Teams

Create a webhook with the **Workflows** app ("Post to a channel when a webhook request is received")
and set `url`. NetLedger posts an Adaptive Card with facts, the diff and action buttons.

## Discord

Channel settings → Integrations → Webhooks → copy the URL. Messages are embeds with a color per
severity and the diff as a `diff` code block.

## Email

| Key | Default | Description |
|---|---|---|
| `smtp_host`, `smtp_port` | , `587` | Mail server. |
| `starttls` / `ssl` | `true` / `false` | STARTTLS on 587, or implicit TLS (`ssl: true`, usually port 465). |
| `smtp_username`, `smtp_password` | | Optional authentication. |
| `from_address`, `to` | | Sender and list of recipients. |

## PagerDuty

Use an Events API v2 integration key as `routing_key`. Problems **trigger** incidents and recoveries
**resolve** them automatically. The dedup key is per device and category (`health`, `backup`, each
compliance rule), so a device's incident opens and closes cleanly.

## Generic webhook

```yaml
- type: webhook
  url: https://automation.example.com/hooks/netledger
  secret: ${WEBHOOK_SECRET}          # optional HMAC-SHA256 signature
  headers: {X-Team: netops}
```

NetLedger POSTs JSON:

```json
{
  "source": "netledger",
  "version": "1.0.0",
  "type": "config_changed",
  "severity": "info",
  "title": "core-sw01: configuration changed",
  "message": "+14/-0 lines, changed by jsmith",
  "device": "core-sw01",
  "site": "hq",
  "platform": "ios",
  "diff": "--- a/configs/...\n+++ b/configs/...\n...",
  "links": {"View commit": "https://github.com/your-org/network-configs/commit/5d7dfde0..."},
  "details": {"added": 14, "removed": 0, "changed_by": "jsmith", "commit": "5d7dfde0..."},
  "timestamp": "2026-10-30T14:39:02Z"
}
```

With `secret` set, the request carries `X-NetLedger-Signature: sha256=<hex>`, the HMAC-SHA256 of the
raw body. Verify it before trusting the payload.
