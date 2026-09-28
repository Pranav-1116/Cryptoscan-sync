"""Alert escalation, cooldown, and signed webhook dispatch."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


import hashlib
import hmac
import http.server
import json
import threading
from datetime import datetime, timedelta, timezone

from network_scanner.alerts.escalation import (
    apply_cooldown,
    classify_severity,
    dispatch_webhook,
    escalate_alerts,
    route_alerts,
    sign_payload,
)

NOW = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)


def _cert(subject, days, fp=None):
    return {
        "subject": subject,
        "fingerprint_sha256": fp or f"fp-{subject}",
        "days_until_expiry": days,
        "usages": [f"{subject}:443"],
    }


# --------------------------------------------------------------------------- #
# escalation (pure)
# --------------------------------------------------------------------------- #

def test_classify_severity_tiers():
    assert classify_severity(-3) == "CRITICAL"   # already expired
    assert classify_severity(0) == "CRITICAL"
    assert classify_severity(3) == "CRITICAL"
    assert classify_severity(7) == "HIGH"
    assert classify_severity(30) == "MEDIUM"
    assert classify_severity(31) == "LOW"
    assert classify_severity(None) == "LOW"


def test_escalate_includes_already_expired():
    """The windowed helper drops expired certs; escalation must not."""
    alerts = escalate_alerts([_cert("expired", -2), _cert("soon", 5), _cert("fine", 90)])
    assert [alert["type"] for alert in alerts] == ["CERTIFICATE_EXPIRED", "CERTIFICATE_EXPIRING"]
    assert alerts[0]["severity"] == "CRITICAL"
    assert "expired 2 days ago" in alerts[0]["message"]
    assert alerts[1]["severity"] == "HIGH"


def test_escalate_sorts_most_severe_first():
    alerts = escalate_alerts([_cert("medium", 20), _cert("critical", -1), _cert("high", 6)])
    assert [alert["severity"] for alert in alerts] == ["CRITICAL", "HIGH", "MEDIUM"]


def test_escalate_skips_unparsable_days():
    assert escalate_alerts([_cert("weird", "not-a-number")]) == []


# --------------------------------------------------------------------------- #
# cooldown (pure)
# --------------------------------------------------------------------------- #

def test_cooldown_suppresses_recent_non_critical():
    alerts = escalate_alerts([_cert("soon", 5)])
    state = {"fp-soon": (NOW - timedelta(hours=2)).isoformat()}
    to_send, new_state = apply_cooldown(alerts, state, now=NOW, cooldown=24.0)
    assert to_send == []
    assert new_state == state  # untouched when suppressed


def test_cooldown_refires_after_window():
    alerts = escalate_alerts([_cert("soon", 5)])
    state = {"fp-soon": (NOW - timedelta(hours=25)).isoformat()}
    to_send, _new = apply_cooldown(alerts, state, now=NOW, cooldown=24.0)
    assert len(to_send) == 1


def test_cooldown_critical_always_fires_and_refreshes_state():
    alerts = escalate_alerts([_cert("burning", 0)])
    state = {"fp-burning": (NOW - timedelta(minutes=5)).isoformat()}
    to_send, new_state = apply_cooldown(alerts, state, now=NOW, cooldown=24.0)
    assert len(to_send) == 1
    assert new_state["fp-burning"] == NOW.isoformat()


def test_cooldown_zero_sends_everything():
    alerts = escalate_alerts([_cert("soon", 5)])
    state = {"fp-soon": NOW.isoformat()}
    to_send, _new = apply_cooldown(alerts, state, now=NOW, cooldown=0.0)
    assert len(to_send) == 1


# --------------------------------------------------------------------------- #
# signing (pure)
# --------------------------------------------------------------------------- #

def test_sign_payload_hmac():
    body = b'{"events": []}'
    signature = sign_payload(body, "s3cret")
    assert signature == hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
    assert sign_payload(body, None) is None
    assert sign_payload(body, "") is None


# --------------------------------------------------------------------------- #
# webhook dispatch (live local receiver)
# --------------------------------------------------------------------------- #

class WebhookReceiver:
    def __init__(self, status=200):
        self.captures = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 — http.server API
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length)
                outer.captures.append({"headers": dict(self.headers.items()), "body": body})
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *_args):
                pass

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.server.timeout = 0.05
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                self.server.handle_request()
            except OSError:
                return
            except Exception as _handler_exc:  # noqa: BLE001 — client disconnects must not noise tests
                logger.debug(
                    "expected_exception_boundary",
                    extra={"error_type": type(_handler_exc).__name__},
                )
                continue

    def close(self):
        self.server.server_close()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}/hook"


def test_dispatch_delivers_signed_batch():
    receiver = WebhookReceiver()
    try:
        alerts = escalate_alerts([_cert("soon", 5), _cert("burning", 0)])
        result = dispatch_webhook(alerts, url=receiver.url, secret="s3cret", retries=2, backoff=0)
        assert result["status"] == "DELIVERED"
        assert result["alerts_sent"] == 2
        assert result["attempts"] == 1
        capture = receiver.captures[0]
        assert capture["headers"]["X-Cryptoscan-Event"] == "certificate.expiry"
        expected = hmac.new(b"s3cret", capture["body"], hashlib.sha256).hexdigest()
        assert capture["headers"]["X-Cryptoscan-Signature"] == expected
        payload = json.loads(capture["body"])
        assert payload["source"] == "cryptoscan-network-scanner"
        assert payload["events"][0]["severity"] == "CRITICAL"  # sorted most severe first
    finally:
        receiver.close()


def test_dispatch_retries_then_fails_honestly():
    receiver = WebhookReceiver(status=500)
    try:
        result = dispatch_webhook(
            escalate_alerts([_cert("soon", 5)]), url=receiver.url, retries=3, backoff=0
        )
        assert result["status"] == "FAILED"
        assert result["attempts"] == 3
        assert result["detail"] == "http_500"
        assert result["alerts_sent"] == 0
        assert len(receiver.captures) == 3  # every retry really happened
    finally:
        receiver.close()


def test_dispatch_without_url_is_skipped():
    result = dispatch_webhook(escalate_alerts([_cert("soon", 5)]), url=None)
    assert result["status"] == "SKIPPED"
    assert result["detail"] == "no webhook url configured"


def test_dispatch_unreachable_url_fails_with_reason():
    result = dispatch_webhook(
        escalate_alerts([_cert("soon", 5)]),
        url="http://127.0.0.1:9/hook",  # discard port, nothing listens
        retries=1,
        backoff=0,
        timeout=1.0,
    )
    assert result["status"] == "FAILED"
    assert result["detail"]


# --------------------------------------------------------------------------- #
# routing (end-to-end, env-driven)
# --------------------------------------------------------------------------- #

def test_route_alerts_end_to_end(monkeypatch):
    receiver = WebhookReceiver()
    try:
        monkeypatch.setenv("CRYPTOSCAN_ALERT_WEBHOOK_URL", receiver.url)
        monkeypatch.setenv("CRYPTOSCAN_ALERT_WEBHOOK_SECRET", "topsecret")
        state = {"fp-soon": NOW.isoformat()}  # recently notified -> suppressed
        routed = route_alerts(
            [_cert("expired", -1), _cert("soon", 5), _cert("fine", 200)],
            state=state,
            now=NOW,
        )
        assert routed["escalated"] == 2
        assert routed["after_cooldown"] == 1  # CRITICAL fired, HIGH suppressed
        assert routed["suppressed"] == 1
        assert routed["severity_counts"] == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0}
        channels = {channel["channel"]: channel for channel in routed["channels"]}
        assert channels["webhook"]["status"] == "DELIVERED"
        assert channels["log"]["alerts_sent"] == 1
        assert routed["notification_state"]["fp-expired"] == NOW.isoformat()
        # the wire batch carries exactly the post-cooldown alert
        payload = json.loads(receiver.captures[0]["body"])
        assert [event["fingerprint"] for event in payload["events"]] == ["fp-expired"]
    finally:
        receiver.close()


def test_route_alerts_without_webhook_config(monkeypatch):
    monkeypatch.delenv("CRYPTOSCAN_ALERT_WEBHOOK_URL", raising=False)
    routed = route_alerts([_cert("soon", 5)], state=None, now=NOW)
    assert [channel["channel"] for channel in routed["channels"]] == ["log"]
    assert routed["channels"][0]["alerts_sent"] == 1
