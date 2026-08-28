"""Signed webhook alerter + dispatcher WEBHOOK channel (Ask-52).

Delivery is exercised against a real local HTTP sink (in-process
http.server on an ephemeral port) — a genuine network round-trip, not a
mock of the receiver.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from drift.alerts.alert_dispatcher import (
    AlertChannel,
    AlertDispatcher,
    AlertStatus,
)
from drift.alerts.email_alerter import EmailAlerter
from drift.alerts.webhook_alerter import (
    WebhookAlert,
    WebhookAlerter,
    WebhookConfig,
    sign_body,
    verify_signature,
)
from drift.models.drift_event import DriftEvent, DriftSeverity, DriftType
from drift.models.drift_summary import DriftSummary


# --------------------------------------------------------------------------- #
# local HTTP sink — a real receiver
# --------------------------------------------------------------------------- #

class Sink:
    """In-process HTTP receiver recording every delivery attempt."""

    def __init__(self, statuses=None):
        self.requests = []  # list of (headers_dict, body_bytes)
        self.statuses = list(statuses or [])  # e.g. [500, 500, 200]
        self.lock = threading.Lock()
        sink = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length)
                with sink.lock:
                    sink.requests.append(({k.lower(): v for k, v in self.headers.items()}, body))
                    status = sink.statuses.pop(0) if sink.statuses else 200
                self.send_response(status)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/hook"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    @property
    def last(self):
        headers, body = self.requests[-1]
        return headers, body


@pytest.fixture()
def sink():
    s = Sink()
    yield s
    s.close()


SECRET = "whsec-test-secret"


def _summary(critical=0, high=0, medium=0, info=0) -> DriftSummary:
    return DriftSummary(
        baseline_id=uuid4(),
        current_scan_id=uuid4(),
        system_identifier="https://github.com/org/app",
        critical=critical,
        high=high,
        medium=medium,
        info=info,
    )


def _event(severity=DriftSeverity.CRITICAL) -> DriftEvent:
    return DriftEvent(
        baseline_id=uuid4(),
        current_scan_id=uuid4(),
        drift_type=DriftType.NEW_CRYPTO,
        severity=severity,
        detected_at=datetime.now(timezone.utc),
        drift_details={
            "algorithm": "DES",
            "file_path": "P.java",
            "line_number": 1,
            "message": "New weak algorithm introduced",
        },
    )


# --------------------------------------------------------------------------- #
# signature scheme
# --------------------------------------------------------------------------- #

def test_signature_scheme_round_trips_and_rejects_tampering():
    body = b'{"a": 1}'
    header = sign_body(body, "1700000000", SECRET)
    assert header.startswith("t=1700000000,v1=")
    # receiver recomputes over "<t>." + body
    assert verify_signature(body, header, SECRET, max_skew_seconds=1e9)
    # wrong secret / tampered body / garbage header all fail
    assert not verify_signature(body, header, "other-secret", max_skew_seconds=1e9)
    assert not verify_signature(b'{"a": 2}', header, SECRET, max_skew_seconds=1e9)
    assert not verify_signature(body, "garbage", SECRET)
    assert not verify_signature(body, "t=notanumber,v1=zz", SECRET)


# --------------------------------------------------------------------------- #
# delivery through a real HTTP round-trip
# --------------------------------------------------------------------------- #

async def _send(sink, **config_overrides):
    config = WebhookConfig(url=sink.url, secret=SECRET, **config_overrides)
    alert = WebhookAlert(
        severity="CRITICAL",
        system_identifier="https://github.com/org/app",
        scan_id=uuid4(),
        drift_summary=_summary(critical=1),
        critical_events=[_event()],
        high_events=[_event(DriftSeverity.HIGH)],
    )
    return await WebhookAlerter(config).send(alert)


@pytest.mark.asyncio
async def test_delivery_signed_and_schema_stable(sink):
    response = await _send(sink)
    assert 200 <= response["status"] < 300
    headers, body = sink.last

    assert headers.get("content-type") == "application/json"
    # the receiver can authenticate the sender from the signature header
    assert verify_signature(body, headers.get("x-cryptoscan-signature"), SECRET, max_skew_seconds=60)

    payload = json.loads(body)
    assert payload["source"] == "cryptoscan"
    assert payload["alert_type"] == "crypto_drift"
    assert payload["severity"] == "CRITICAL"
    assert payload["summary"]["critical"] == 1
    assert payload["events"][0]["algorithm"] == "DES"
    assert "DES" not in payload["text"] or "CRITICAL" in payload["text"]  # chat-renderable
    assert SECRET not in body.decode()  # the secret never travels in the payload


@pytest.mark.asyncio
async def test_non_2xx_raises_and_unreachable_raises():
    rejecting = Sink(statuses=[500])
    rejecting.close = lambda: None
    with pytest.raises(RuntimeError, match="HTTP 500"):
        await _send(rejecting)
    rejecting.server.shutdown(); rejecting.server.server_close()

    bad = WebhookAlerter(WebhookConfig(url="http://127.0.0.1:1/nope", secret=SECRET, timeout_seconds=0.5))
    with pytest.raises(RuntimeError, match="unreachable"):
        await bad.send(WebhookAlert(
            severity="HIGH", system_identifier="s", scan_id=uuid4(), drift_summary=_summary(high=1),
        ))


def test_unconfigured_is_honest():
    alerter = WebhookAlerter(WebhookConfig(url="", secret=SECRET))
    assert alerter.configured is False
    assert WebhookAlerter().configured is False
    assert WebhookAlerter(WebhookConfig(url="ftp://nope", secret=SECRET)).configured is False


# --------------------------------------------------------------------------- #
# dispatcher integration
# --------------------------------------------------------------------------- #

def _dispatcher(sink, **kw):
    email = MagicMock(spec=EmailAlerter)
    email.send = AsyncMock()
    webhook = WebhookAlerter(WebhookConfig(url=sink.url if sink else "", secret=SECRET))
    dispatcher = AlertDispatcher(
        email_alerter=email, max_retries=kw.pop("max_retries", 3),
        retry_delay=kw.pop("retry_delay", 0.01), webhook_alerter=webhook,
    )
    return dispatcher, email


@pytest.mark.asyncio
async def test_critical_drift_hits_email_and_webhook(sink):
    dispatcher, email = _dispatcher(sink)
    result = await dispatcher.dispatch(
        drift_summary=_summary(critical=2), drift_events=[_event()],
        notification_emails=["sec@example.com"], scan_id=uuid4(),
        system_identifier="https://github.com/org/app",
    )
    channels = {r.channel for r in result.alerts_sent}
    assert channels == {AlertChannel.EMAIL, AlertChannel.WEBHOOK}
    email.send.assert_called_once()
    assert len(sink.requests) == 1  # delivered first try
    headers, body = sink.last
    assert verify_signature(body, headers["x-cryptoscan-signature"], SECRET, max_skew_seconds=60)


@pytest.mark.asyncio
async def test_medium_only_drift_never_webhooks(sink):
    dispatcher, email = _dispatcher(sink)
    result = await dispatcher.dispatch(
        drift_summary=_summary(medium=3), drift_events=[], notification_emails=[],
        scan_id=uuid4(), system_identifier="s",
    )
    assert not sink.requests
    assert all(r.channel == AlertChannel.LOG_ONLY for r in result.alerts_skipped)


@pytest.mark.asyncio
async def test_webhook_retries_then_succeeds(sink):
    sink.statuses = [500, 500]  # receiver rejects twice, accepts third
    dispatcher, _ = _dispatcher(sink, max_retries=3, retry_delay=0.01)
    result = await dispatcher.dispatch(
        drift_summary=_summary(critical=1), drift_events=[_event()],
        notification_emails=[], scan_id=uuid4(), system_identifier="s",
    )
    webhook_records = [r for r in result.alerts_sent + result.alerts_failed if r.channel == AlertChannel.WEBHOOK]
    assert webhook_records[0].status == AlertStatus.SENT
    assert webhook_records[0].retry_count == 2  # third attempt won


@pytest.mark.asyncio
async def test_webhook_failure_recorded_and_breaker_opens(sink):
    sink.statuses = [500] * 6  # receiver rejects every delivery
    dispatcher, _ = _dispatcher(sink, max_retries=1, retry_delay=0.01)
    summary = _summary(critical=1)
    events = [_event()]

    first = await dispatcher.dispatch(summary, events, [], uuid4(), "s")
    assert first.alerts_failed and first.alerts_failed[0].channel == AlertChannel.WEBHOOK
    assert first.alerts_failed[0].error_message  # honest failure trail

    # WEBHOOK breaker opens after repeated failures — later dispatches skip
    for _ in range(4):
        await dispatcher.dispatch(summary, events, [], uuid4(), "s")
    assert dispatcher._circuit_breakers[AlertChannel.WEBHOOK]._state == "open"


@pytest.mark.asyncio
async def test_no_webhook_configured_keeps_legacy_behavior(sink):
    email = MagicMock(spec=EmailAlerter)
    email.send = AsyncMock()
    dispatcher = AlertDispatcher(email_alerter=email, max_retries=1, retry_delay=0.01)
    result = await dispatcher.dispatch(
        _summary(critical=1), [_event()], ["sec@example.com"], uuid4(), "s",
    )
    # email-only, exactly as before the webhook channel existed
    assert [r.channel for r in result.alerts_sent] == [AlertChannel.EMAIL]
    assert not sink.requests
