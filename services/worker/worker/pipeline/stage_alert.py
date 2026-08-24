"""
Pipeline Stage 8: Alerting.
Sends notifications for critical drift and policy violations.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from drift.alerts.email_alerter import EmailAlerter
from database.db.repositories.drift_repository import DriftRepository

from worker.pipeline.pipeline_runner import PipelineContext

logger = logging.getLogger(__name__)


class StageAlert:
    """Alert stage: send notifications."""

    async def execute(self, ctx: PipelineContext) -> PipelineContext:
        """
        If drift events exist:
        1. Query drift_events table for CRITICAL/HIGH events
        2. Fetch repo configuration for notification emails
        3. Send alerts

        Returns: Updated context (no changes).
        """
        if not ctx.drift_events or len(ctx.drift_events) == 0:
            logger.info("no_drift_events_to_alert", extra={"job_id": ctx.job_id})
            return ctx

        logger.info(
            "alert_start",
            extra={
                "job_id": ctx.job_id,
                "drift_count": len(ctx.drift_events),
            },
        )

        try:
            critical_events = [
                e for e in ctx.drift_events if e.get("severity") == "CRITICAL"
            ]
            high_events = [
                e for e in ctx.drift_events if e.get("severity") == "HIGH"
            ]

            if not critical_events and not high_events:
                logger.debug("no_critical_drift_to_alert", extra={"job_id": ctx.job_id})
                return ctx

            # Load repo config for notification emails
            from database.db.connection.session import AsyncSessionFactory
            from database.db.repositories.repo_config_repository import (
                RepoConfigRepository,
            )

            async with AsyncSessionFactory() as db:
                repo_config_repo = RepoConfigRepository(db)
                repo_config = await repo_config_repo.get_by_url(ctx.target_repo)

                if not repo_config or not repo_config.notification_emails:
                    logger.warning(
                        "no_notification_emails_configured",
                        extra={"job_id": ctx.job_id},
                    )
                    return ctx

                # Send alerts
                alerter = EmailAlerter()

                if critical_events:
                    await alerter.send_critical_alert(
                        repo_name=repo_config.repo_name,
                        scan_id=ctx.scan_id,
                        drift_count=len(critical_events),
                        recipients=repo_config.notification_emails,
                    )

                if high_events:
                    await alerter.send_high_alert(
                        repo_name=repo_config.repo_name,
                        scan_id=ctx.scan_id,
                        drift_count=len(high_events),
                        recipients=repo_config.notification_emails,
                    )

                logger.info(
                    "alert_sent",
                    extra={
                        "job_id": ctx.job_id,
                        "critical": len(critical_events),
                        "high": len(high_events),
                        "recipients": len(repo_config.notification_emails),
                    },
                )

                return ctx

        except Exception as exc:
            logger.exception(
                "alert_failed",
                extra={
                    "job_id": ctx.job_id,
                    "error": str(exc),
                },
            )
            # Don't re-raise — alerting is non-critical
            return ctx