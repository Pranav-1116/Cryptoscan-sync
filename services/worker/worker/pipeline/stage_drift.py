"""Standalone adapter for the worker's approved-baseline comparison stage.

The production runner owns the comparison, proposal and idempotent persistence
rules; invoking this adapter must not use a second, diverging implementation.
"""

from __future__ import annotations

import logging

from worker.pipeline.pipeline_runner import PipelineContext, PipelineRunner

logger = logging.getLogger(__name__)


def execute(ctx: PipelineContext, session) -> PipelineContext:
    PipelineRunner.__new__(PipelineRunner)._drift(ctx, session)
    _publish_drift_events(ctx.drift_events, ctx)
    return ctx


def _publish_drift_events(events: list[dict], ctx: PipelineContext) -> None:
    """Publish newly detected events; polling remains the standalone fallback."""
    if not events:
        return
    try:
        from api.events.bus import get_event_bus

        for event in events:
            get_event_bus().publish(
                "drift.event",
                {
                    "scan_id": ctx.scan_id,
                    "job_id": ctx.job_id,
                    "target": ctx.target_repo,
                    "drift_type": event["drift_type"],
                    "severity": event["severity"],
                    "reason": event["reason"],
                    "algorithm": event["algorithm"],
                },
                source="drift",
            )
    except Exception as exc:  # noqa: BLE001 — standalone worker: polling covers it
        logger.warning("exception_suppressed", extra={"error_type": type(exc).__name__})
    logger.info("stage_drift_done", extra={"events": len(events)})


class StageDrift:
    def execute(self, ctx: PipelineContext, session) -> PipelineContext:
        return execute(ctx, session)
