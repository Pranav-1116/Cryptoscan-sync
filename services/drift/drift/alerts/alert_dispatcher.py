"""
Alert dispatcher - routes drift alerts to correct channels.
Production-level with retry logic, circuit breaker, and audit trail.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

import structlog

from drift.alerts.email_alerter import EmailAlerter, EmailAlert
from drift.alerts.webhook_alerter import WebhookAlert, WebhookAlerter
from drift.models.drift_summary import DriftSummary
from drift.models.drift_event import DriftEvent

logger = structlog.get_logger(__name__)


class AlertChannel(str, Enum):
    EMAIL = "email"
    WEBHOOK = "webhook"
    LOG_ONLY = "log_only"


class AlertStatus(str, Enum):
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class AlertRecord:
    """Immutable record of alert dispatch attempt."""
    alert_id: UUID
    channel: AlertChannel
    severity: str
    system_identifier: str
    scan_id: UUID
    status: AlertStatus
    dispatched_at: datetime
    error_message: str | None = None
    retry_count: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class DispatchResult:
    """Result of dispatching all alerts for a drift summary."""
    dispatch_id: UUID
    scan_id: UUID
    system_identifier: str
    alerts_sent: list[AlertRecord] = field(default_factory=list)
    alerts_failed: list[AlertRecord] = field(default_factory=list)
    alerts_skipped: list[AlertRecord] = field(default_factory=list)
    total_drift_events: int = 0
    dispatched_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @property
    def success(self) -> bool:
        return len(self.alerts_failed) == 0

    @property
    def summary(self) -> dict[str, Any]:
        return {
            "dispatch_id": str(self.dispatch_id),
            "scan_id": str(self.scan_id),
            "system_identifier": self.system_identifier,
            "sent": len(self.alerts_sent),
            "failed": len(self.alerts_failed),
            "skipped": len(self.alerts_skipped),
            "success": self.success,
        }


class CircuitBreaker:
    """
    Circuit breaker for alert channels.
    Prevents cascade failures when email/webhook is down.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
    ) -> None:
        self._failure_count = 0
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._last_failure_time: float | None = None
        self._state = "closed"  # closed=normal, open=blocking, half-open=testing

    @property
    def is_open(self) -> bool:
        if self._state == "open":
            if self._last_failure_time is not None:
                elapsed = time.monotonic() - self._last_failure_time
                if elapsed >= self._recovery_timeout:
                    self._state = "half-open"
                    return False
            return True
        return False

    def record_success(self) -> None:
        self._failure_count = 0
        self._state = "closed"

    def record_failure(self) -> None:
        self._failure_count += 1
        self._last_failure_time = time.monotonic()
        if self._failure_count >= self._failure_threshold:
            self._state = "open"
            logger.warning(
                "circuit_breaker_opened",
                failure_count=self._failure_count,
                threshold=self._failure_threshold,
            )


class AlertDispatcher:
    """
    Routes drift alerts to appropriate channels based on severity.

    Severity routing:
    - CRITICAL: email (immediate) + signed webhook (Slack/Teams/Jira)
    - HIGH: email (immediate) + signed webhook
    - MEDIUM: log only (included in digest)
    - INFO: log only
    """

    def __init__(
        self,
        email_alerter: EmailAlerter,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        webhook_alerter: WebhookAlerter | None = None,
    ) -> None:
        self._email_alerter = email_alerter
        self._webhook_alerter = webhook_alerter
        self._max_retries = max_retries
        self._retry_delay = retry_delay
        self._circuit_breakers: dict[AlertChannel, CircuitBreaker] = {
            AlertChannel.EMAIL: CircuitBreaker(),
            AlertChannel.WEBHOOK: CircuitBreaker(),
        }
        self._dispatch_history: list[AlertRecord] = []

    async def dispatch(
        self,
        drift_summary: DriftSummary,
        drift_events: list[DriftEvent],
        notification_emails: list[str],
        scan_id: UUID,
        system_identifier: str,
    ) -> DispatchResult:
        """
        Dispatch alerts for a completed drift detection run.

        Args:
            drift_summary: Aggregated drift counts by severity
            drift_events: Individual drift events (for detail)
            notification_emails: Recipients for email alerts
            scan_id: UUID of the triggering scan
            system_identifier: Repo URL or system name

        Returns:
            DispatchResult with full audit of what was sent
        """
        dispatch_id = uuid4()

        log = logger.bind(
            dispatch_id=str(dispatch_id),
            scan_id=str(scan_id),
            system_identifier=system_identifier,
            critical_count=drift_summary.critical,
            high_count=drift_summary.high,
        )

        log.info("alert_dispatch_started")

        result = DispatchResult(
            dispatch_id=dispatch_id,
            scan_id=scan_id,
            system_identifier=system_identifier,
            total_drift_events=drift_summary.total_drift_events,
        )

        # Determine which channels to use based on severity
        channels_needed = self._determine_channels(drift_summary)

        for channel, severity_reason in channels_needed:
            alert_record = await self._dispatch_to_channel(
                channel=channel,
                severity_reason=severity_reason,
                drift_summary=drift_summary,
                drift_events=drift_events,
                notification_emails=notification_emails,
                scan_id=scan_id,
                system_identifier=system_identifier,
            )

            if alert_record.status == AlertStatus.SENT:
                result.alerts_sent.append(alert_record)
            elif alert_record.status == AlertStatus.FAILED:
                result.alerts_failed.append(alert_record)
            else:
                result.alerts_skipped.append(alert_record)

        # Always log summary regardless of channel success
        self._log_dispatch_summary(drift_summary, system_identifier, scan_id)

        log.info(
            "alert_dispatch_completed",
            sent=len(result.alerts_sent),
            failed=len(result.alerts_failed),
            skipped=len(result.alerts_skipped),
        )

        return result

    def _determine_channels(
        self, drift_summary: DriftSummary
    ) -> list[tuple[AlertChannel, str]]:
        """
        Determine which alert channels to use and why.

        Returns list of (channel, severity_reason) tuples.
        """
        channels: list[tuple[AlertChannel, str]] = []

        if drift_summary.critical > 0:
            channels.append((AlertChannel.EMAIL, "CRITICAL"))
            if self._webhook_configured():
                channels.append((AlertChannel.WEBHOOK, "CRITICAL"))

        elif drift_summary.high > 0:
            channels.append((AlertChannel.EMAIL, "HIGH"))
            if self._webhook_configured():
                channels.append((AlertChannel.WEBHOOK, "HIGH"))

        # Medium and info go to log only (digest email handled separately)
        if drift_summary.medium > 0 or drift_summary.info > 0:
            channels.append((AlertChannel.LOG_ONLY, "MEDIUM_OR_INFO"))

        if not channels:
            channels.append((AlertChannel.LOG_ONLY, "NO_DRIFT"))

        return channels

    async def _dispatch_to_channel(
        self,
        channel: AlertChannel,
        severity_reason: str,
        drift_summary: DriftSummary,
        drift_events: list[DriftEvent],
        notification_emails: list[str],
        scan_id: UUID,
        system_identifier: str,
    ) -> AlertRecord:
        """Dispatch to a single channel with retry logic."""

        alert_id = uuid4()

        if channel == AlertChannel.LOG_ONLY:
            logger.info(
                "drift_alert_log_only",
                severity_reason=severity_reason,
                system_identifier=system_identifier,
                scan_id=str(scan_id),
                drift_counts={
                    "critical": drift_summary.critical,
                    "high": drift_summary.high,
                    "medium": drift_summary.medium,
                    "info": drift_summary.info,
                },
            )
            return AlertRecord(
                alert_id=alert_id,
                channel=channel,
                severity=severity_reason,
                system_identifier=system_identifier,
                scan_id=scan_id,
                status=AlertStatus.SKIPPED,
                dispatched_at=datetime.now(timezone.utc),
                metadata={"reason": "log_only_severity"},
            )

        if channel == AlertChannel.WEBHOOK:
            return await self._dispatch_webhook_with_retry(
                alert_id=alert_id,
                severity_reason=severity_reason,
                drift_summary=drift_summary,
                drift_events=drift_events,
                scan_id=scan_id,
                system_identifier=system_identifier,
            )

        if channel == AlertChannel.EMAIL:
            return await self._dispatch_email_with_retry(
                alert_id=alert_id,
                severity_reason=severity_reason,
                drift_summary=drift_summary,
                drift_events=drift_events,
                notification_emails=notification_emails,
                scan_id=scan_id,
                system_identifier=system_identifier,
            )

        # Unknown channel — log and skip
        logger.warning("unknown_alert_channel", channel=channel)
        return AlertRecord(
            alert_id=alert_id,
            channel=channel,
            severity=severity_reason,
            system_identifier=system_identifier,
            scan_id=scan_id,
            status=AlertStatus.SKIPPED,
            dispatched_at=datetime.now(timezone.utc),
            metadata={"reason": "unknown_channel"},
        )

    async def _dispatch_email_with_retry(
        self,
        alert_id: UUID,
        severity_reason: str,
        drift_summary: DriftSummary,
        drift_events: list[DriftEvent],
        notification_emails: list[str],
        scan_id: UUID,
        system_identifier: str,
    ) -> AlertRecord:
        """Send email alert with exponential backoff retry."""

        cb = self._circuit_breakers[AlertChannel.EMAIL]

        if cb.is_open:
            logger.warning(
                "email_circuit_breaker_open",
                system_identifier=system_identifier,
            )
            return AlertRecord(
                alert_id=alert_id,
                channel=AlertChannel.EMAIL,
                severity=severity_reason,
                system_identifier=system_identifier,
                scan_id=scan_id,
                status=AlertStatus.SKIPPED,
                dispatched_at=datetime.now(timezone.utc),
                metadata={"reason": "circuit_breaker_open"},
            )

        if not notification_emails:
            logger.warning(
                "no_notification_emails_configured",
                system_identifier=system_identifier,
            )
            return AlertRecord(
                alert_id=alert_id,
                channel=AlertChannel.EMAIL,
                severity=severity_reason,
                system_identifier=system_identifier,
                scan_id=scan_id,
                status=AlertStatus.SKIPPED,
                dispatched_at=datetime.now(timezone.utc),
                metadata={"reason": "no_recipients_configured"},
            )

        # Build email alert payload
        critical_events = [e for e in drift_events if e.severity == "CRITICAL"]
        high_events = [e for e in drift_events if e.severity == "HIGH"]

        email_alert = EmailAlert(
            recipients=notification_emails,
            severity=severity_reason,
            system_identifier=system_identifier,
            scan_id=scan_id,
            drift_summary=drift_summary,
            critical_events=critical_events[:10],  # Cap at 10 for email size
            high_events=high_events[:10],
        )

        last_error: Exception | None = None

        for attempt in range(self._max_retries):
            try:
                await self._email_alerter.send(email_alert)
                cb.record_success()

                logger.info(
                    "email_alert_sent",
                    alert_id=str(alert_id),
                    recipients=notification_emails,
                    severity=severity_reason,
                    attempt=attempt + 1,
                )

                return AlertRecord(
                    alert_id=alert_id,
                    channel=AlertChannel.EMAIL,
                    severity=severity_reason,
                    system_identifier=system_identifier,
                    scan_id=scan_id,
                    status=AlertStatus.SENT,
                    dispatched_at=datetime.now(timezone.utc),
                    retry_count=attempt,
                    metadata={
                        "recipients": notification_emails,
                        "attempt": attempt + 1,
                    },
                )

            except Exception as exc:
                last_error = exc
                cb.record_failure()

                logger.warning(
                    "email_alert_attempt_failed",
                    alert_id=str(alert_id),
                    attempt=attempt + 1,
                    max_retries=self._max_retries,
                    error=str(exc),
                )

                if attempt < self._max_retries - 1:
                    delay = self._retry_delay * (2**attempt)
                    await asyncio.sleep(delay)

        # All retries exhausted
        logger.error(
            "email_alert_failed_all_retries",
            alert_id=str(alert_id),
            severity=severity_reason,
            system_identifier=system_identifier,
            error=str(last_error),
        )

        return AlertRecord(
            alert_id=alert_id,
            channel=AlertChannel.EMAIL,
            severity=severity_reason,
            system_identifier=system_identifier,
            scan_id=scan_id,
            status=AlertStatus.FAILED,
            dispatched_at=datetime.now(timezone.utc),
            retry_count=self._max_retries,
            error_message=str(last_error),
        )

    def _webhook_configured(self) -> bool:
        return bool(self._webhook_alerter is not None and self._webhook_alerter.configured)

    async def _dispatch_webhook_with_retry(
        self,
        alert_id: UUID,
        severity_reason: str,
        drift_summary: DriftSummary,
        drift_events: list[DriftEvent],
        scan_id: UUID,
        system_identifier: str,
    ) -> AlertRecord:
        """Send signed webhook alert with exponential backoff retry."""

        cb = self._circuit_breakers[AlertChannel.WEBHOOK]

        if cb.is_open:
            logger.warning("webhook_circuit_breaker_open", system_identifier=system_identifier)
            return AlertRecord(
                alert_id=alert_id,
                channel=AlertChannel.WEBHOOK,
                severity=severity_reason,
                system_identifier=system_identifier,
                scan_id=scan_id,
                status=AlertStatus.SKIPPED,
                dispatched_at=datetime.now(timezone.utc),
                metadata={"reason": "circuit_breaker_open"},
            )

        if not self._webhook_configured():
            return AlertRecord(
                alert_id=alert_id,
                channel=AlertChannel.WEBHOOK,
                severity=severity_reason,
                system_identifier=system_identifier,
                scan_id=scan_id,
                status=AlertStatus.SKIPPED,
                dispatched_at=datetime.now(timezone.utc),
                metadata={"reason": "no_webhook_url_configured"},
            )

        critical_events = [e for e in drift_events if e.severity == "CRITICAL"]
        high_events = [e for e in drift_events if e.severity == "HIGH"]
        webhook_alert = WebhookAlert(
            severity=severity_reason,
            system_identifier=system_identifier,
            scan_id=scan_id,
            drift_summary=drift_summary,
            critical_events=critical_events[:10],
            high_events=high_events[:10],
        )

        last_error: Exception | None = None
        for attempt in range(self._max_retries):
            try:
                await self._webhook_alerter.send(webhook_alert)
                cb.record_success()
                logger.info(
                    "webhook_alert_sent",
                    alert_id=str(alert_id),
                    severity=severity_reason,
                    attempt=attempt + 1,
                )
                return AlertRecord(
                    alert_id=alert_id,
                    channel=AlertChannel.WEBHOOK,
                    severity=severity_reason,
                    system_identifier=system_identifier,
                    scan_id=scan_id,
                    status=AlertStatus.SENT,
                    dispatched_at=datetime.now(timezone.utc),
                    retry_count=attempt,
                    metadata={"attempt": attempt + 1},
                )
            except Exception as exc:
                last_error = exc
                cb.record_failure()
                logger.warning(
                    "webhook_alert_attempt_failed",
                    alert_id=str(alert_id),
                    attempt=attempt + 1,
                    max_retries=self._max_retries,
                    error=str(exc),
                )
                if attempt < self._max_retries - 1:
                    await asyncio.sleep(self._retry_delay * (2**attempt))

        logger.error(
            "webhook_alert_failed_all_retries",
            alert_id=str(alert_id),
            severity=severity_reason,
            system_identifier=system_identifier,
            error=str(last_error),
        )
        return AlertRecord(
            alert_id=alert_id,
            channel=AlertChannel.WEBHOOK,
            severity=severity_reason,
            system_identifier=system_identifier,
            scan_id=scan_id,
            status=AlertStatus.FAILED,
            dispatched_at=datetime.now(timezone.utc),
            retry_count=self._max_retries,
            error_message=str(last_error),
        )

    def _log_dispatch_summary(
        self,
        drift_summary: DriftSummary,
        system_identifier: str,
        scan_id: UUID,
    ) -> None:
        """Always log drift summary regardless of alert channel outcome."""
        logger.info(
            "drift_detection_summary",
            system_identifier=system_identifier,
            scan_id=str(scan_id),
            total_events=drift_summary.total_drift_events,
            critical=drift_summary.critical,
            high=drift_summary.high,
            medium=drift_summary.medium,
            info=drift_summary.info,
            new_crypto_count=drift_summary.new_crypto_count,
            removed_crypto_count=drift_summary.removed_crypto_count,
        )

    def get_dispatch_history(self) -> list[AlertRecord]:
        """Return immutable copy of dispatch history."""
        return list(self._dispatch_history)