"""Signed webhook alerter for drift notifications.

Delivers CRITICAL/HIGH drift alerts to any HTTP endpoint that accepts a
JSON webhook — Slack incoming-webhook URLs work out of the box (the
payload carries a rendered ``text`` field), and generic receivers (Jira
automation, Microsoft Teams via connector, Mattermost, Splunk HEC
bridges) get a stable, documented schema.

Every delivery is signed: the ``X-CryptoScan-Signature`` header carries
``t=<unix-ts>,v1=<hmac-sha256>`` computed over ``"<t>." + raw_body`` with
the shared secret, so the receiver can authenticate the sender and reject
replayed old payloads. No secret ever appears in the payload.

Honesty rules (same as the rest of the platform):
  - no URL configured -> alerts are SKIPPED, never fabricated as sent;
  - delivery failures raise, the dispatcher records them as FAILED
    after its retry budget.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import structlog

from drift.models.drift_event import DriftEvent
from drift.models.drift_summary import DriftSummary

logger = structlog.get_logger(__name__)

SIGNATURE_HEADER = "X-CryptoScan-Signature"
MAX_EVENTS_PER_PAYLOAD = 10


@dataclass(frozen=True)
class WebhookConfig:
    """Where and how to deliver webhook alerts."""

    url: str = ""
    secret: str = ""
    timeout_seconds: float = 5.0
    verify_tls: bool = True


@dataclass(frozen=True)
class WebhookAlert:
    """Data required to deliver a drift alert webhook."""

    severity: str
    system_identifier: str
    scan_id: UUID
    drift_summary: DriftSummary
    critical_events: list[DriftEvent] = field(default_factory=list)
    high_events: list[DriftEvent] = field(default_factory=list)
    dashboard_base_url: str = "https://cryptoscan.local"


def _event_rows(events: list[DriftEvent]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for event in events[:MAX_EVENTS_PER_PAYLOAD]:
        details = dict(event.drift_details or {})
        rows.append(
            {
                "drift_type": str(event.drift_type),
                "severity": str(event.severity),
                "algorithm": details.get("algorithm"),
                "file_path": details.get("file_path"),
                "line_number": details.get("line_number"),
                "message": details.get("message") or details.get("reason"),
            }
        )
    return rows


def build_payload(alert: WebhookAlert) -> dict[str, Any]:
    """Stable payload schema for every receiver type."""
    summary = alert.drift_summary
    counts = {
        "critical": summary.critical,
        "high": summary.high,
        "medium": summary.medium,
        "info": summary.info,
        "total_drift_events": summary.total_drift_events,
        "new_crypto": summary.new_crypto_count,
        "removed_crypto": summary.removed_crypto_count,
    }
    events = _event_rows(alert.critical_events) + _event_rows(alert.high_events)
    text = (
        f"CryptoScan {alert.severity} drift on {alert.system_identifier}: "
        f"{summary.critical} critical / {summary.high} high "
        f"({summary.total_drift_events} events, scan {alert.scan_id})"
    )
    return {
        "source": "cryptoscan",
        "alert_type": "crypto_drift",
        "severity": alert.severity,
        "system": alert.system_identifier,
        "scan_id": str(alert.scan_id),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": counts,
        "events": events[:MAX_EVENTS_PER_PAYLOAD],
        "dashboard_url": f"{alert.dashboard_base_url.rstrip('/')}/#/drift",
        # Slack incoming webhooks (and several chat tools) render just this
        "text": text,
    }


def sign_body(body: bytes, timestamp: str, secret: str) -> str:
    """``t=<ts>,v1=<hex hmac>`` over ``<ts>.`` + body (GitHub/Slack scheme)."""
    mac = hmac.new(
        secret.encode("utf-8"),
        timestamp.encode("utf-8") + b"." + body,
        hashlib.sha256,
    )
    return f"t={timestamp},v1={mac.hexdigest()}"


def verify_signature(body: bytes, header: str, secret: str, *, max_skew_seconds: float = 300.0) -> bool:
    """Receiver-side check (exported for receivers and tests)."""
    try:
        parts = dict(item.split("=", 1) for item in header.split(","))
        timestamp, provided = parts["t"], parts["v1"]
        if abs(time.time() - float(timestamp)) > max_skew_seconds:
            return False
    except (ValueError, KeyError, AttributeError, TypeError):
        return False
    expected = sign_body(body, timestamp, secret)
    return hmac.compare_digest(expected, f"t={timestamp},v1={provided}")


class WebhookAlerter:
    """Delivers one signed JSON POST per alert. Raises on non-2xx."""

    def __init__(self, config: WebhookConfig | None = None):
        self.config = config or WebhookConfig()

    @property
    def configured(self) -> bool:
        return bool(self.config and self.config.url and self.config.url.startswith(("http://", "https://")))

    def build_payload(self, alert: WebhookAlert) -> dict[str, Any]:
        return build_payload(alert)

    async def send(self, alert: WebhookAlert) -> dict[str, Any]:
        """POST the alert; returns {"status", "body"} on 2xx, raises otherwise."""
        if not self.configured:
            raise RuntimeError("webhook url not configured")
        body = json.dumps(build_payload(alert)).encode("utf-8")
        timestamp = str(int(time.time()))
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "cryptoscan-webhook/1.0",
            SIGNATURE_HEADER: sign_body(body, timestamp, self.config.secret),
        }
        return await asyncio.to_thread(self._post, body, headers)

    def _post(self, body: bytes, headers: dict[str, str]) -> dict[str, Any]:
        request = urllib.request.Request(self.config.url, data=body, headers=headers, method="POST")
        context = None
        if not self.config.verify_tls and self.config.url.startswith("https://"):
            context = ssl_unverified_context()
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout_seconds, context=context) as response:
                return {"status": response.status, "body": response.read(4096).decode("utf-8", "replace")}
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"webhook delivered but rejected: HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"webhook unreachable: {exc.reason}") from exc


def ssl_unverified_context():
    """TLS verification opt-out for receivers behind self-signed ingress."""
    import ssl

    return ssl._create_unverified_context()  # noqa: SLATE001 — explicit opt-in only
