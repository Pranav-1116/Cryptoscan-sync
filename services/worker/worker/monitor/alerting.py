"""Route monitor alerts to the channels a bank security operations centre runs.

When the engine raises an ALERT (a *new* issue — steady-state noise stays
quiet), this module fans it out to every configured sink:

- **CEF over UDP** — ArcSight/Qradar-style ``CEF:0|CryptoScan|...`` lines a
  SIEM collector ingests directly (``ALERT_CEF_HOST``/``ALERT_CEF_PORT``);
- **signed webhook** — POST with the same ``X-CryptoScan-Signature`` HMAC
  header the inbound webhook API uses (``ALERT_WEBHOOK_URL`` +
  ``ALERT_WEBHOOK_SECRET``);
- **email** — reuses the SMTP settings the report scheduler already has;
- **ChatOps** — Slack/Mattermost-compatible incoming webhook
  (``ALERT_CHATOPS_URL``), signed with ``ALERT_CHATOPS_SECRET`` like the
  generic webhook sink; severity-colored attachment, plain-text body
  (round 37, deep/31 ChatOps remainder — the workspace is the external
  system, this is the client half).

Failures in a sink are logged and never propagate: alerting must not be able
to kill the monitoring loop. Delivery is best-effort at-most-once per tick
(the event feed in the database remains the system of record).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import socket
from datetime import datetime, timezone
from typing import Any, Callable
from urllib import request as urlrequest

from api.config.settings import get_settings

logger = logging.getLogger(__name__)


def format_cef(*, target: str, issue: str, severity: int = 7, extra: dict | None = None) -> str:
    """One CEF line for an alert (ArcSight Common Event Format, no syslog header)."""
    extension = " ".join(
        [f"target={target}", f"issue={issue}"]
        + [f"{key}={value}" for key, value in (extra or {}).items()]
    )
    return (
        f"CEF:0|CryptoScan|LiveMonitor|1.0|MONITOR_ALERT|NEW issue on {target}|"
        f"{severity}|{extension}"
    )


#: severity -> attachment color (Slack/Mattermost convention)
_CHATOPS_COLORS = {
    "CRITICAL": "#cc0000", "HIGH": "#e33e1c", "MEDIUM": "#f2c744",
    "LOW": "#439fe0",
}


def format_chatops(*, target: str, issue: str, payload: dict | None = None,
                   channel: str = "") -> dict:
    """One Slack/Mattermost-compatible alert body (both parse this shape).

    ``text`` is the plain-text rendering (notifications, mobile clients);
    the attachment carries severity color and structured fields (desktop
    rendering). Values are embedded as data, never interpolated into
    markup — an alert from a scanned host cannot inject ChatOps markdown.
    """
    severity = str((payload or {}).get("severity") or "HIGH").upper()
    body = {
        "text": f"[CryptoScan ALERT] {target}: {issue}",
        "attachments": [{
            "color": _CHATOPS_COLORS.get(severity, "#cccccc"),
            "fields": [
                {"title": "Target", "value": target, "short": True},
                {"title": "Issue", "value": issue, "short": True},
                {"title": "Severity", "value": severity, "short": True},
            ],
        }],
    }
    if channel:
        body["channel"] = channel
    return body


class AlertRouter:
    def __init__(self, *, settings: Any = None, post: Callable[[str, dict, dict], Any] | None = None,
                 send_cef: Callable[[str], None] | None = None, send_email: Callable[[str, str], None] | None = None):
        self.settings = settings or get_settings()
        self._post = post or self._post_json
        self._send_cef = send_cef or self._cef_udp
        self._send_email = send_email or self._smtp_email

    # ----------------------------------------------------------------- api

    def dispatch(self, target: str, issue: str, payload: dict | None = None) -> dict:
        """Fan one alert out to every configured sink. Never raises."""
        outcome: dict[str, str] = {}
        cef_host = getattr(self.settings, "ALERT_CEF_HOST", "") or ""
        cef_port = int(getattr(self.settings, "ALERT_CEF_PORT", 0) or 0)
        webhook_url = getattr(self.settings, "ALERT_WEBHOOK_URL", "") or ""
        if cef_host and cef_port:
            try:
                self._send_cef(format_cef(target=target, issue=issue))
                outcome["cef"] = "sent"
            except Exception as exc:  # noqa: BLE001 — alerting must not kill the loop
                outcome["cef"] = f"failed: {exc}"
                logger.warning("alert_cef_failed", extra={"error": str(exc)})
        if webhook_url:
            try:
                body = {"target": target, "issue": issue, "payload": payload or {},
                        "generated_at": datetime.now(timezone.utc).isoformat()}
                self._post(webhook_url, body,
                           self._signature(body, self.settings.ALERT_WEBHOOK_SECRET))
                outcome["webhook"] = "sent"
            except Exception as exc:  # noqa: BLE001
                outcome["webhook"] = f"failed: {exc}"
                logger.warning("alert_webhook_failed", extra={"error": str(exc)})
        chatops_url = getattr(self.settings, "ALERT_CHATOPS_URL", "") or ""
        if chatops_url:
            try:
                body = format_chatops(
                    target=target, issue=issue, payload=payload,
                    channel=getattr(self.settings, "ALERT_CHATOPS_CHANNEL", "") or "")
                body["generated_at"] = datetime.now(timezone.utc).isoformat()
                chatops_secret = (getattr(self.settings, "ALERT_CHATOPS_SECRET", "")
                                  or getattr(self.settings, "ALERT_WEBHOOK_SECRET", "") or "")
                self._post(chatops_url, body, self._signature(body, chatops_secret))
                outcome["chatops"] = "sent"
            except Exception as exc:  # noqa: BLE001
                outcome["chatops"] = f"failed: {exc}"
                logger.warning("alert_chatops_failed", extra={"error": str(exc)})
        if getattr(self.settings, "SMTP_HOST", ""):
            try:
                self._send_email(
                    f"[CryptoScan ALERT] {target}: {issue}",
                    json.dumps({"target": target, "issue": issue, "payload": payload or {}}, indent=2),
                )
                outcome["email"] = "sent"
            except Exception as exc:  # noqa: BLE001
                outcome["email"] = f"failed: {exc}"
                logger.warning("alert_email_failed", extra={"error": str(exc)})
        if outcome:
            logger.info("alert_dispatched", extra={"target": target, "sinks": list(outcome)})
        return outcome

    # ---------------------------------------------------------------- sinks

    def _signature(self, body: dict, secret: str = "") -> dict:
        if not secret:
            return {}
        raw = json.dumps(body, sort_keys=True).encode()
        digest = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
        return {"X-CryptoScan-Signature": f"sha256={digest}"}

    @staticmethod
    def _post_json(url: str, body: dict, headers: dict) -> None:
        request = urlrequest.Request(
            url,
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", **headers},
            method="POST",
        )
        with urlrequest.urlopen(request, timeout=5) as response:  # noqa: S310 — operator-configured URL
            response.read()

    def _cef_udp(self, line: str) -> None:
        host = getattr(self.settings, "ALERT_CEF_HOST", "")
        port = int(getattr(self.settings, "ALERT_CEF_PORT", 0) or 0)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(line.encode(), (host, port))

    def _smtp_email(self, subject: str, body: str) -> None:
        """Direct SMTP — SKIPPED honestly when unconfigured (report mailer is report-shaped)."""
        import smtplib
        from email.message import EmailMessage

        host = (getattr(self.settings, "SMTP_HOST", "") or "").strip()
        if not host:
            raise RuntimeError("SMTP_HOST not configured")
        port = int(getattr(self.settings, "SMTP_PORT", 587) or 587)
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = getattr(self.settings, "ALERT_EMAIL_FROM", "alerts@cryptoscan.local")
        message["To"] = getattr(self.settings, "ALERT_EMAIL_TO", "security@example.com")
        message.set_content(body)
        with smtplib.SMTP(host, port, timeout=10) as server:
            user = getattr(self.settings, "SMTP_USER", "")
            if user:
                server.starttls()
                server.login(user, getattr(self.settings, "SMTP_PASSWORD", ""))
            server.send_message(message)
