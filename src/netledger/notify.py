"""Notifications: Slack, Microsoft Teams, Discord, generic webhooks, email and PagerDuty."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any

import requests

from netledger import __version__
from netledger.config import NotifierSettings, Settings
from netledger.events import Event, severity_at_least
from netledger.utils import iso, truncate_lines

log = logging.getLogger(__name__)

ICONS = {
    "config_changed": "📝",
    "backup_failed": "❌",
    "backup_recovered": "✅",
    "health_warning": "⚠️",
    "health_critical": "🚨",
    "health_recovered": "✅",
    "device_rebooted": "🔄",
    "compliance_failed": "📋",
    "compliance_passed": "✅",
    "capacity_forecast": "📈",
    "digest": "📬",
    "test": "🔔",
}
COLORS = {"critical": 0xE5484D, "warning": 0xF5A524, "info": 0x3B82F6, "recovered": 0x22C55E}


def _color(event: Event) -> int:
    return COLORS["recovered"] if event.is_recovery else COLORS.get(event.severity, COLORS["info"])


def _context(event: Event) -> str:
    parts = [p for p in (f"Site: {event.site}" if event.site else "", f"Platform: {event.platform}" if event.platform else "") if p]
    return " · ".join(parts)


class Notifier:
    def __init__(self, cfg: NotifierSettings, title: str = "NetLedger"):
        self.cfg = cfg
        self.title = title
        self.session = requests.Session()
        self.session.headers["User-Agent"] = f"netledger/{__version__}"

    @property
    def name(self) -> str:
        return self.cfg.label

    def accepts(self, event: Event) -> bool:
        if event.type == "test":
            return True
        return event.type in self.cfg.events and severity_at_least(event.severity, self.cfg.min_severity)

    def diff_block(self, event: Event, max_chars: int) -> str | None:
        if not (event.diff and self.cfg.include_diff):
            return None
        return truncate_lines(event.diff.rstrip("\n"), self.cfg.max_diff_lines, max_chars)

    def post(self, payload: Any, url: str | None = None, headers: dict[str, str] | None = None, data: bytes | None = None) -> None:
        resp = self.session.post(
            url or self.cfg.url or "",
            json=None if data is not None else payload,
            data=data,
            headers={**self.cfg.headers, **(headers or {})},
            timeout=self.cfg.timeout,
            verify=self.cfg.verify_ssl,
        )
        if resp.status_code >= 300:
            raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:200]}")

    def send(self, event: Event) -> None:
        raise NotImplementedError

    def digest(self, events: list[Event]) -> Event:
        worst = max(events, key=lambda e: {"info": 0, "warning": 1, "critical": 2}.get(e.severity, 0)).severity
        lines = [f"{ICONS.get(e.type, '•')} {e.title}" + (f" — {e.message}" if e.message else "") for e in events[:40]]
        if len(events) > 40:
            lines.append(f"... and {len(events) - 40} more")
        return Event("digest", worst, f"{len(events)} NetLedger events", "\n".join(lines))


class SlackNotifier(Notifier):
    def send(self, event: Event) -> None:
        icon = ICONS.get(event.type, "•")
        blocks: list[dict[str, Any]] = [
            {"type": "section", "text": {"type": "mrkdwn", "text": truncate_lines(f"{icon} *{event.title}*\n{event.message}", 60, 2900)}},
        ]
        if _context(event):
            blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": _context(event)}]})
        diff = self.diff_block(event, 2800)
        if diff:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"```{diff}```"}})
        if event.links:
            blocks.append({
                "type": "actions",
                "elements": [
                    {"type": "button", "text": {"type": "plain_text", "text": label[:75]}, "url": url}
                    for label, url in list(event.links.items())[:5]
                ],
            })
        self.post({"text": f"{icon} {event.title}", "blocks": blocks})


class TeamsNotifier(Notifier):
    """Microsoft Teams via Workflows / incoming-webhook URLs using an Adaptive Card."""

    def send(self, event: Event) -> None:
        color = "Good" if event.is_recovery else {"critical": "Attention", "warning": "Warning"}.get(event.severity, "Accent")
        body: list[dict[str, Any]] = [
            {"type": "TextBlock", "text": f"{ICONS.get(event.type, '')} {event.title}", "weight": "Bolder", "size": "Medium", "wrap": True, "color": color},
        ]
        if event.message:
            body.append({"type": "TextBlock", "text": truncate_lines(event.message, 40, 3000), "wrap": True})
        facts = [{"title": k, "value": v} for k, v in (("Device", event.device), ("Site", event.site), ("Platform", event.platform), ("Time", iso(event.timestamp))) if v]
        if facts:
            body.append({"type": "FactSet", "facts": facts})
        diff = self.diff_block(event, 6000)
        if diff:
            body.append({"type": "TextBlock", "text": diff, "fontType": "Monospace", "wrap": True, "size": "Small"})
        card = {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.4",
            "body": body,
            "actions": [{"type": "Action.OpenUrl", "title": label, "url": url} for label, url in list(event.links.items())[:5]],
        }
        self.post({"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]})


class DiscordNotifier(Notifier):
    def send(self, event: Event) -> None:
        description = event.message or ""
        diff = self.diff_block(event, 3500)
        if diff:
            description += f"\n```diff\n{diff}\n```"
        embed: dict[str, Any] = {
            "title": f"{ICONS.get(event.type, '')} {event.title}"[:256],
            "description": description[:4096],
            "color": _color(event),
            "timestamp": iso(event.timestamp),
            "footer": {"text": self.title},
        }
        fields = [{"name": k, "value": v, "inline": True} for k, v in (("Site", event.site), ("Platform", event.platform)) if v]
        fields += [{"name": label, "value": f"[open]({url})", "inline": True} for label, url in list(event.links.items())[:3]]
        if fields:
            embed["fields"] = fields
        self.post({"username": self.title, "embeds": [embed]})


class WebhookNotifier(Notifier):
    def send(self, event: Event) -> None:
        payload = {"source": "netledger", "version": __version__, **event.to_dict(), "timestamp": iso(event.timestamp)}
        if not self.cfg.include_diff:
            payload.pop("diff", None)
        body = json.dumps(payload, default=str).encode()
        headers = {"Content-Type": "application/json"}
        if self.cfg.secret:
            signature = hmac.new(self.cfg.secret.encode(), body, hashlib.sha256).hexdigest()
            headers["X-NetLedger-Signature"] = f"sha256={signature}"
        self.post(None, data=body, headers=headers)


class EmailNotifier(Notifier):
    def send(self, event: Event) -> None:
        message = EmailMessage()
        message["Subject"] = f"[{self.title}] {event.title}"
        message["From"] = self.cfg.from_address or ""
        message["To"] = ", ".join(self.cfg.to)
        lines = [event.title, "", event.message or ""]
        context = _context(event)
        if context:
            lines += ["", context]
        if event.links:
            lines += [""] + [f"{label}: {url}" for label, url in event.links.items()]
        diff = self.diff_block(event, 20000)
        if diff:
            lines += ["", "Changes:", diff]
        lines += ["", "--", f"Sent by NetLedger {__version__}"]
        message.set_content("\n".join(lines))
        host, port = self.cfg.smtp_host or "localhost", self.cfg.smtp_port
        context_ssl = ssl.create_default_context()
        if not self.cfg.verify_ssl:
            context_ssl.check_hostname = False
            context_ssl.verify_mode = ssl.CERT_NONE
        if self.cfg.ssl:
            server: smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=self.cfg.timeout, context=context_ssl)
        else:
            server = smtplib.SMTP(host, port, timeout=self.cfg.timeout)
        try:
            if self.cfg.starttls and not self.cfg.ssl:
                server.starttls(context=context_ssl)
            if self.cfg.smtp_username:
                server.login(self.cfg.smtp_username, self.cfg.smtp_password or "")
            server.send_message(message)
        finally:
            try:
                server.quit()
            except smtplib.SMTPException:
                pass


class PagerDutyNotifier(Notifier):
    URL = "https://events.pagerduty.com/v2/enqueue"

    @staticmethod
    def _dedup(event: Event) -> str:
        if event.type.startswith("health_"):
            category = "health"
        elif event.type.startswith("backup_"):
            category = "backup"
        elif event.type.startswith("compliance_"):
            category = f"compliance:{event.details.get('rule', '')}"
        else:
            category = f"{event.type}:{int(event.timestamp)}"
        return f"netledger:{event.device or 'global'}:{category}"

    def send(self, event: Event) -> None:
        payload: dict[str, Any] = {
            "routing_key": self.cfg.routing_key,
            "event_action": "resolve" if event.is_recovery else "trigger",
            "dedup_key": self._dedup(event),
        }
        if not event.is_recovery:
            payload["payload"] = {
                "summary": f"{event.title}: {event.message}"[:1024],
                "source": event.device or "netledger",
                "severity": event.severity if event.severity in ("critical", "warning", "info") else "error",
                "component": event.platform,
                "group": event.site,
                "custom_details": {**event.details, "message": event.message},
            }
            if event.links:
                payload["links"] = [{"href": url, "text": label} for label, url in event.links.items()]
        self.post(payload, url=self.cfg.url or self.URL)

    def digest(self, events: list[Event]) -> Event:  # PagerDuty needs one event per incident
        raise NotImplementedError


NOTIFIERS = {
    "slack": SlackNotifier,
    "teams": TeamsNotifier,
    "discord": DiscordNotifier,
    "webhook": WebhookNotifier,
    "email": EmailNotifier,
    "pagerduty": PagerDutyNotifier,
}


class Dispatcher:
    def __init__(self, settings: Settings):
        self.notifiers = [NOTIFIERS[cfg.type](cfg, settings.server.title) for cfg in settings.notifications]

    def dispatch(self, events: list[Event]) -> dict[str, int]:
        """Deliver events; returns the number of messages sent per notifier. Never raises."""
        sent: dict[str, int] = {}
        for notifier in self.notifiers:
            mine = [e for e in events if notifier.accepts(e)]
            if not mine:
                continue
            batch: list[Event] = mine
            if len(mine) > notifier.cfg.max_per_run:
                try:
                    batch = [notifier.digest(mine)]
                except NotImplementedError:
                    batch = mine
            count = 0
            for event in batch:
                try:
                    notifier.send(event)
                    count += 1
                except Exception as exc:  # noqa: BLE001 - notifications must never break a run
                    log.warning("notification via %s failed: %s", notifier.name, exc)
            sent[notifier.name] = count
        return sent

    def test(self) -> dict[str, str]:
        results = {}
        event = Event("test", "info", "NetLedger test notification", "If you can read this, notifications are working.")
        for notifier in self.notifiers:
            try:
                notifier.send(event)
                results[notifier.name] = "ok"
            except Exception as exc:  # noqa: BLE001
                results[notifier.name] = f"failed: {exc}"
        return results
