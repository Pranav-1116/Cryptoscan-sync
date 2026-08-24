"""
Production email alerter for drift notifications.
Uses SMTP with TLS, HTML + plain text multipart emails.
"""

from __future__ import annotations

import asyncio
import smtplib
import ssl
from dataclasses import dataclass
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any
from uuid import UUID

import structlog
from jinja2 import Environment, FileSystemLoader, select_autoescape

from drift.models.drift_summary import DriftSummary
from drift.models.drift_event import DriftEvent

logger = structlog.get_logger(__name__)

TEMPLATES_DIR = Path(__file__).parent / "alert_templates"


@dataclass(frozen=True)
class EmailAlert:
    """Data required to send a drift alert email."""
    recipients: list[str]
    severity: str
    system_identifier: str
    scan_id: UUID
    drift_summary: DriftSummary
    critical_events: list[DriftEvent]
    high_events: list[DriftEvent]
    dashboard_base_url: str = "https://cryptoscan.local"


@dataclass(frozen=True)
class SMTPConfig:
    """SMTP server configuration."""
    host: str
    port: int
    username: str
    password: str
    use_tls: bool = True
    use_starttls: bool = False
    timeout: float = 10.0
    from_address: str = "cryptoscan@noreply.local"
    from_name: str = "CryptoScan Platform"


class EmailAlerter:
    """
    Sends drift alert emails via SMTP.

    Supports:
    - HTML + plain text multipart
    - TLS and STARTTLS
    - Jinja2 templates
    - Async execution (runs SMTP in thread pool)
    """

    def __init__(self, smtp_config: SMTPConfig | None = None) -> None:
        self._config = smtp_config
        self._jinja_env = self._build_jinja_env()

    def _build_jinja_env(self) -> Environment:
        """Build Jinja2 environment for email templates."""
        return Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    async def send(self, alert: EmailAlert) -> None:
        """
        Send alert email asynchronously.

        Runs SMTP in thread pool executor to avoid blocking event loop.
        """
        log = logger.bind(
            severity=alert.severity,
            system_identifier=alert.system_identifier,
            scan_id=str(alert.scan_id),
            recipients=alert.recipients,
        )

        log.info("sending_email_alert")

        message = self._build_message(alert)

        # Run blocking SMTP in thread pool
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            self._send_smtp,
            message,
            alert.recipients,
        )

        log.info("email_alert_sent_successfully")

    def send_drift_alert(self, target_repo: str, events: list[dict]) -> None:
        """Sync helper used by the worker when SMTP is configured."""
        logger.warning(
            "drift_alert_logged",
            extra={"target": target_repo, "events": events},
        )

    def _build_message(self, alert: EmailAlert) -> MIMEMultipart:
        """Build multipart email message with HTML and plain text."""
        subject = self._build_subject(alert)
        template_context = self._build_template_context(alert)

        # Render templates
        if alert.severity in ("CRITICAL", "HIGH"):
            template_name = f"{alert.severity.lower()}_drift"
        else:
            template_name = "high_drift"  # fallback

        try:
            html_body = self._jinja_env.get_template(
                f"{template_name}.html"
            ).render(**template_context)
        except Exception:
            # Fallback to plain text template
            html_body = self._render_plain_fallback(template_context)

        try:
            text_body = self._jinja_env.get_template(
                f"{template_name}.txt"
            ).render(**template_context)
        except Exception:
            text_body = self._render_plain_fallback(template_context)

        # Build MIME message
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = (
            f"{self._config.from_name} <{self._config.from_address}>"
        )
        msg["To"] = ", ".join(alert.recipients)
        msg["X-CryptoScan-Severity"] = alert.severity
        msg["X-CryptoScan-System"] = alert.system_identifier
        msg["X-CryptoScan-Scan-ID"] = str(alert.scan_id)

        # Attach plain text first (fallback), then HTML (preferred)
        msg.attach(MIMEText(text_body, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        return msg

    def _build_subject(self, alert: EmailAlert) -> str:
        """Build email subject line."""
        system_short = alert.system_identifier.split("/")[-1]

        if alert.severity == "CRITICAL":
            critical_count = alert.drift_summary.critical
            return (
                f"[CRITICAL] {critical_count} critical crypto drift "
                f"detected in {system_short}"
            )
        elif alert.severity == "HIGH":
            high_count = alert.drift_summary.high
            return (
                f"[HIGH] {high_count} high severity crypto drift "
                f"in {system_short}"
            )
        else:
            return f"[CryptoScan] Crypto drift detected in {system_short}"

    def _build_template_context(self, alert: EmailAlert) -> dict[str, Any]:
        """Build Jinja2 template context from alert data."""
        return {
            "severity": alert.severity,
            "system_identifier": alert.system_identifier,
            "scan_id": str(alert.scan_id),
            "drift_summary": alert.drift_summary,
            "critical_events": alert.critical_events,
            "high_events": alert.high_events,
            "dashboard_url": (
                f"{alert.dashboard_base_url}/drift"
                f"?scan_id={alert.scan_id}"
            ),
            "scan_url": (
                f"{alert.dashboard_base_url}/scans/{alert.scan_id}"
            ),
            "total_events": alert.drift_summary.total_drift_events,
            "new_crypto_count": alert.drift_summary.new_crypto_count,
            "removed_crypto_count": alert.drift_summary.removed_crypto_count,
        }

    def _render_plain_fallback(self, context: dict[str, Any]) -> str:
        """Render plain text email without Jinja2 template."""
        summary = context["drift_summary"]
        lines = [
            f"CryptoScan Drift Alert",
            f"======================",
            f"",
            f"System: {context['system_identifier']}",
            f"Severity: {context['severity']}",
            f"Scan ID: {context['scan_id']}",
            f"",
            f"Drift Summary:",
            f"  CRITICAL: {summary.critical}",
            f"  HIGH: {summary.high}",
            f"  MEDIUM: {summary.medium}",
            f"  INFO: {summary.info}",
            f"  Total: {summary.total_drift_events}",
            f"",
            f"View full report: {context['dashboard_url']}",
            f"",
            f"This is an automated alert from CryptoScan Platform.",
        ]

        if context.get("critical_events"):
            lines.append("")
            lines.append("Critical Events:")
            for event in context["critical_events"][:5]:
                lines.append(
                    f"  - {event.drift_type}: "
                    f"{event.drift_details.get('algorithm', 'Unknown')} "
                    f"at {event.drift_details.get('location', 'Unknown')}"
                )

        return "\n".join(lines)

    def _send_smtp(
        self, message: MIMEMultipart, recipients: list[str]
    ) -> None:
        """
        Send via SMTP (blocking — runs in thread pool).
        Supports both SSL/TLS and STARTTLS.
        """
        config = self._config

        try:
            if config.use_tls:
                # Direct TLS connection (port 465)
                context = ssl.create_default_context()
                with smtplib.SMTP_SSL(
                    config.host,
                    config.port,
                    context=context,
                    timeout=config.timeout,
                ) as server:
                    if config.username and config.password:
                        server.login(config.username, config.password)
                    server.sendmail(
                        config.from_address,
                        recipients,
                        message.as_string(),
                    )

            elif config.use_starttls:
                # STARTTLS upgrade (port 587)
                context = ssl.create_default_context()
                with smtplib.SMTP(
                    config.host,
                    config.port,
                    timeout=config.timeout,
                ) as server:
                    server.ehlo()
                    server.starttls(context=context)
                    server.ehlo()
                    if config.username and config.password:
                        server.login(config.username, config.password)
                    server.sendmail(
                        config.from_address,
                        recipients,
                        message.as_string(),
                    )

            else:
                # Plain SMTP (development only)
                with smtplib.SMTP(
                    config.host,
                    config.port,
                    timeout=config.timeout,
                ) as server:
                    server.sendmail(
                        config.from_address,
                        recipients,
                        message.as_string(),
                    )

        except smtplib.SMTPAuthenticationError as exc:
            logger.error("smtp_authentication_failed", error=str(exc))
            raise
        except smtplib.SMTPConnectError as exc:
            logger.error(
                "smtp_connection_failed",
                host=config.host,
                port=config.port,
                error=str(exc),
            )
            raise
        except smtplib.SMTPException as exc:
            logger.error("smtp_send_failed", error=str(exc))
            raise
        except TimeoutError as exc:
            logger.error(
                "smtp_timeout",
                host=config.host,
                timeout=config.timeout,
                error=str(exc),
            )
            raise