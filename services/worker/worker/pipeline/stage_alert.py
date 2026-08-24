"""Pipeline stage: notify on high/critical drift."""

from __future__ import annotations

import logging

from worker.config.settings import get_settings
from worker.pipeline.pipeline_runner import PipelineContext

logger = logging.getLogger(__name__)


def execute(ctx: PipelineContext) -> PipelineContext:
    critical = [e for e in ctx.drift_events if e.get("severity") in {"CRITICAL", "HIGH"}]
    if not critical:
        return ctx
    logger.warning("drift_alert", extra={"job_id": ctx.job_id, "scan_id": ctx.scan_id, "events": critical})
    settings = get_settings()
    if getattr(settings, "SMTP_HOST", ""):
        try:
            from drift.alerts.email_alerter import EmailAlerter

            EmailAlerter().send_drift_alert(ctx.target_repo, critical)
        except Exception:
            logger.exception("email_alert_failed")
    return ctx


class StageAlert:
    def execute(self, ctx: PipelineContext) -> PipelineContext:
        return execute(ctx)
