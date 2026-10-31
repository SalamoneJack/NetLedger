from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

import pytest

from netledger.config import settings_from_dict
from netledger.events import Event
from netledger.notify import Dispatcher


class Capture:
    def __init__(self, status: int = 200):
        self.posts: list[dict[str, Any]] = []
        self.status = status

    def __call__(self, session: Any, url: str, json: Any = None, data: Any = None, headers: Any = None, timeout: Any = None, verify: Any = None) -> Any:  # noqa: A002
        self.posts.append({"url": url, "json": json, "data": data, "headers": headers or {}})
        status = self.status

        class Resp:
            status_code = status
            text = "error" if status >= 300 else "ok"

        return Resp()


@pytest.fixture
def capture(monkeypatch: pytest.MonkeyPatch) -> Capture:
    cap = Capture()
    monkeypatch.setattr("requests.Session.post", lambda self, *args, **kwargs: cap(self, *args, **kwargs))
    return cap


def change_event() -> Event:
    return Event(
        "config_changed", "info", "core1: configuration changed", "+2/-1 lines, changed by jsmith",
        device="core1", site="hq", platform="ios", diff="--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new\n",
        links={"View commit": "https://github.com/acme/configs/commit/abc"},
    )


def test_slack_payload(capture: Capture) -> None:
    settings = settings_from_dict({"notifications": [{"type": "slack", "url": "https://hooks.slack.test/x"}]})
    sent = Dispatcher(settings).dispatch([change_event()])
    assert sent == {"slack": 1}
    payload = capture.posts[0]["json"]
    assert payload["text"].endswith("core1: configuration changed")
    texts = json.dumps(payload["blocks"])
    assert "```--- a/x" in texts and "View commit" in texts and "Site: hq" in texts


def test_teams_and_discord_payloads(capture: Capture) -> None:
    settings = settings_from_dict({"notifications": [
        {"type": "teams", "url": "https://teams.test/hook"},
        {"type": "discord", "url": "https://discord.test/hook"},
    ]})
    Dispatcher(settings).dispatch([change_event()])
    teams, discord = capture.posts[0]["json"], capture.posts[1]["json"]
    card = teams["attachments"][0]
    assert card["contentType"] == "application/vnd.microsoft.card.adaptive"
    assert card["content"]["actions"][0]["url"].endswith("/commit/abc")
    assert discord["embeds"][0]["description"].count("```diff") == 1


def test_webhook_signature(capture: Capture) -> None:
    settings = settings_from_dict({"notifications": [{"type": "webhook", "url": "https://hook.test", "secret": "s3"}]})
    Dispatcher(settings).dispatch([change_event()])
    post = capture.posts[0]
    expected = hmac.new(b"s3", post["data"], hashlib.sha256).hexdigest()
    assert post["headers"]["X-NetLedger-Signature"] == f"sha256={expected}"
    body = json.loads(post["data"])
    assert body["type"] == "config_changed" and body["device"] == "core1" and body["source"] == "netledger"


def test_filters_digest_and_failures(capture: Capture) -> None:
    settings = settings_from_dict({"notifications": [
        {"type": "slack", "url": "https://a.test", "events": ["health_critical"], "name": "oncall"},
        {"type": "slack", "url": "https://b.test", "min_severity": "warning", "max_per_run": 2, "name": "noc"},
    ]})
    events = [Event("health_warning", "warning", f"sw{i}: health warning") for i in range(3)]
    events.append(Event("config_changed", "info", "x changed"))
    sent = Dispatcher(settings).dispatch(events)
    assert sent == {"noc": 1}  # 3 warnings > max_per_run=2 -> one digest; info filtered; oncall gets nothing
    assert "3 NetLedger events" in json.dumps(capture.posts[0]["json"])
    capture.status = 500
    assert Dispatcher(settings).dispatch([Event("health_critical", "critical", "boom")]) == {"oncall": 0, "noc": 0}


def test_pagerduty_trigger_and_resolve(capture: Capture) -> None:
    settings = settings_from_dict({"notifications": [{"type": "pagerduty", "routing_key": "rk", "events": ["health_critical", "health_recovered"]}]})
    dispatcher = Dispatcher(settings)
    dispatcher.dispatch([Event("health_critical", "critical", "fw1: health critical", "unreachable", device="fw1")])
    dispatcher.dispatch([Event("health_recovered", "info", "fw1: health recovered", device="fw1")])
    trigger, resolve = capture.posts[0]["json"], capture.posts[1]["json"]
    assert capture.posts[0]["url"] == "https://events.pagerduty.com/v2/enqueue"
    assert trigger["event_action"] == "trigger" and trigger["payload"]["severity"] == "critical"
    assert resolve["event_action"] == "resolve" and resolve["dedup_key"] == trigger["dedup_key"] == "netledger:fw1:health"
