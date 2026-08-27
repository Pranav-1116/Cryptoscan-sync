"""Alert escalation, cooldown, and webhook dispatch for certificate expiry.

Today ``expiry_alerts`` stops at building a list — nothing reaches a human,
and certificates that are *already expired* (negative days-until-expiry)
never alert at all because ``expiring()`` only keeps ``0 <= days <= N``.
This module closes that loop:

* ``escalate_alerts`` recomputes severity from the raw cert inventory:
  EXPIRED or <=3 days -> CRITICAL, <=7 -> HIGH, <=30 -> MEDIUM, and includes
  already-expired certificates (the "the building is on fire" tier the
  windowed helper drops);
* ``apply_cooldown`` deduplicates against a caller-persisted
  ``{fingerprint: last_notified_iso}`` state so a daily scan does not re-fire
  the same alert every run (default 24h, env-tunable);
* ``dispatch_webhook`` POSTs one signed batch (HMAC-SHA256 over the raw body
  in ``X-Cryptoscan-Signature``) with bounded retries and honest outcomes:
  DELIVERED / FAILED / SKIPPED, never a silent drop;
* ``route_alerts`` fans out to the configured channels — webhook when
  ``CRYPTOSCAN_ALERT_WEBHOOK_URL`` is set, log channel always — and reports
  per-channel results.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable
from urllib.error import URLError
from urllib.request import Request, urlopen

logger = logging.getLogger("network_scanner.alerts")

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def classify_severity(days_until_expiry: int | None) -> str:
    """EXPIRED/<=3d CRITICAL, <=7d HIGH, <=30d MEDIUM, else LOW."""
    try:
        remaining = int(days_until_expiry)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "LOW"
    if remaining < 0 or remaining <= 3:
        return "CRITICAL"
    if remaining <= 7:
        return "HIGH"
    if remaining <= 30:
        return "MEDIUM"
    return "LOW"


def escalate_alerts(certs: Iterable[dict[str, Any]], *, days: int = 30) -> list[dict[str, Any]]:
    """Severity-escalated alerts including already-expired certificates."""
    alerts: list[dict[str, Any]] = []
    for cert in certs or []:
        raw = cert.get("days_until_expiry")
        try:
            remaining = int(raw)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue
        if remaining > days:
            continue
        expired = remaining < 0
        alerts.append(
            {
                "type": "CERTIFICATE_EXPIRED" if expired else "CERTIFICATE_EXPIRING",
                "severity": classify_severity(remaining),
                "message": (
                    f"Certificate expired {-remaining} days ago"
                    if expired
                    else f"Certificate expires in {remaining} days"
                ),
                "certificate": cert.get("subject"),
                "fingerprint": cert.get("fingerprint_sha256"),
                "days_until_expiry": remaining,
                "endpoints": cert.get("usages") or ([cert["endpoint"]] if cert.get("endpoint") else []),
            }
        )
    alerts.sort(key=lambda alert: (SEVERITY_ORDER.get(alert["severity"], 99), -alert["days_until_expiry"]))
    return alerts


def _parse_iso(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)


def cooldown_hours() -> float:
    raw = os.environ.get("CRYPTOSCAN_ALERT_COOLDOWN_HOURS", "").strip()
    if not raw:
        return 24.0
    try:
        return max(0.0, float(raw))
    except ValueError:
        return 24.0


def apply_cooldown(
    alerts: list[dict[str, Any]],
    state: dict[str, str] | None,
    *,
    now: datetime | None = None,
    cooldown: float | None = None,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Split alerts into (to_send, new_state); CRITICAL always re-fires.

    ``state`` maps fingerprint -> last-notified ISO-8601 timestamp and is
    meant to be persisted by the caller between runs.
    """
    stamp = now or datetime.now(timezone.utc)
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    window = timedelta(hours=cooldown_hours() if cooldown is None else cooldown)
    current = dict(state or {})
    to_send: list[dict[str, Any]] = []
    for alert in alerts:
        fingerprint = str(alert.get("fingerprint") or "")
        last = _parse_iso(current.get(fingerprint)) if fingerprint else None
        suppressed = (
            alert.get("severity") != "CRITICAL"
            and last is not None
            and (stamp - last) < window
        )
        if not suppressed:
            to_send.append(alert)
        if fingerprint and (not suppressed or alert.get("severity") == "CRITICAL"):
            current[fingerprint] = stamp.isoformat()
    return to_send, current


def sign_payload(body: bytes, secret: str | None) -> str | None:
    """HMAC-SHA256 hex digest of the raw body; None when no secret is set."""
    if not secret:
        return None
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def dispatch_webhook(
    alerts: list[dict[str, Any]],
    *,
    url: str | None = None,
    secret: str | None = None,
    timeout: float | None = None,
    retries: int | None = None,
    backoff: float = 0.5,
) -> dict[str, Any]:
    """POST one signed batch; bounded retries; honest outcome."""
    url = url if url is not None else os.environ.get("CRYPTOSCAN_ALERT_WEBHOOK_URL", "").strip()
    secret = secret if secret is not None else os.environ.get("CRYPTOSCAN_ALERT_WEBHOOK_SECRET", "").strip()
    if timeout is None:
        try:
            timeout = float(os.environ.get("CRYPTOSCAN_ALERT_WEBHOOK_TIMEOUT", "") or 3.0)
        except ValueError:
            timeout = 3.0
    if retries is None:
        try:
            retries = int(os.environ.get("CRYPTOSCAN_ALERT_WEBHOOK_RETRIES", "") or 3)
        except ValueError:
            retries = 3
    result: dict[str, Any] = {
        "channel": "webhook",
        "url": url or None,
        "alerts_sent": 0,
        "attempts": 0,
        "status": "SKIPPED",
        "detail": None,
    }
    if not url:
        result["detail"] = "no webhook url configured"
        return result
    if not alerts:
        result["detail"] = "no alerts to send"
        return result
    import time

    body = json.dumps(
        {
            "source": "cryptoscan-network-scanner",
            "sent_at": datetime.now(timezone.utc).isoformat(),
            "events": alerts,
        }
    ).encode("utf-8")
    signature = sign_payload(body, secret)
    last_error: str | None = None
    for attempt in range(1, max(1, retries) + 1):
        result["attempts"] = attempt
        request = Request(url, data=body, method="POST")  # noqa: S310 — operator-configured endpoint
        request.add_header("Content-Type", "application/json")
        request.add_header("X-Cryptoscan-Event", "certificate.expiry")
        if signature:
            request.add_header("X-Cryptoscan-Signature", signature)
        try:
            with urlopen(request, timeout=timeout) as response:  # noqa: S310
                status = getattr(response, "status", None) or 200
            if 200 <= status < 300:
                result["status"] = "DELIVERED"
                result["http_status"] = status
                result["alerts_sent"] = len(alerts)
                return result
            last_error = f"http_{status}"
        except URLError as exc:
            code = getattr(exc, "code", None)
            last_error = f"http_{code}" if code else f"{type(exc.reason).__name__}" if exc.reason else exc.__class__.__name__
        except OSError as exc:
            last_error = exc.__class__.__name__
        except ValueError as exc:
            last_error = f"bad_url:{exc}"[:120]
        if attempt < max(1, retries) and backoff > 0:
            time.sleep(backoff * (2 ** (attempt - 1)))
    result["status"] = "FAILED"
    result["detail"] = last_error
    return result


def _log_channel(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    for alert in alerts:
        logger.error(
            "ALERT %s %s %s (fingerprint=%s endpoints=%s)",
            alert.get("severity"),
            alert.get("type"),
            alert.get("message"),
            alert.get("fingerprint"),
            ",".join(str(item) for item in (alert.get("endpoints") or [])),
        )
    return {"channel": "log", "status": "DELIVERED" if alerts else "SKIPPED", "alerts_sent": len(alerts)}


def route_alerts(
    certs: Iterable[dict[str, Any]],
    *,
    state: dict[str, str] | None = None,
    days: int = 30,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Escalate -> cooldown -> fan out to channels; honest per-channel results."""
    alerts = escalate_alerts(certs, days=days)
    to_send, new_state = apply_cooldown(alerts, state, now=now)
    channels = [_log_channel(to_send)]
    if os.environ.get("CRYPTOSCAN_ALERT_WEBHOOK_URL", "").strip():
        channels.append(dispatch_webhook(to_send))
    return {
        "escalated": len(alerts),
        "after_cooldown": len(to_send),
        "suppressed": len(alerts) - len(to_send),
        "severity_counts": {
            level: sum(1 for alert in alerts if alert["severity"] == level)
            for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        },
        "channels": channels,
        "alerts": alerts,
        "notification_state": new_state,
    }
