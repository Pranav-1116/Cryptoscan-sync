"""Pipeline stage: compare the current scan to the approved baseline."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from worker.pipeline.pipeline_runner import PipelineContext

logger = logging.getLogger(__name__)


def execute(ctx: PipelineContext, session) -> PipelineContext:
    from sqlalchemy import select

    from db.models.drift_event import DriftEvent
    from db.models.evidence_record import EvidenceRecord
    from db.repositories.baseline_repository import BaselineRepository
    from drift.core.detector import DriftDetector

    baseline = BaselineRepository(session).get_active(ctx.target_repo)
    if baseline is None:
        logger.info("no_baseline_skip_drift", extra={"target": ctx.target_repo})
        return ctx

    def as_findings(scan_id: str) -> list[dict]:
        rows = list(session.execute(select(EvidenceRecord).where(EvidenceRecord.scan_id == scan_id)).scalars())
        return [
            {
                "algorithm": r.algorithm,
                "key_size": r.key_size,
                "mode": r.mode,
                "purpose": r.purpose,
                "file_path": r.file_path,
                "line_number": r.line_number,
                "compliance_status": r.compliance_status,
                "is_hardcoded_key": r.is_hardcoded_key,
            }
            for r in rows
        ]

    detection = DriftDetector().detect_drift(
        baseline_findings=as_findings(baseline.approved_scan_id),
        current_findings=as_findings(ctx.scan_id or ""),
        baseline_scan_id=baseline.approved_scan_id,
        current_scan_id=ctx.scan_id or "",
    )
    now = datetime.now(timezone.utc)
    events = []
    for change in detection.changes:
        details = {
            "change_type": change.change_type,
            "reason": change.reason,
            "algorithm": change.affected_algorithm,
        }
        session.add(
            DriftEvent(
                baseline_id=baseline.id,
                current_scan_id=ctx.scan_id or "",
                detected_at=now,
                drift_type=change.change_type,
                severity=change.severity,
                drift_details=details,
                resolution_status="OPEN",
            )
        )
        events.append(
            {
                "drift_type": change.change_type,
                "severity": change.severity,
                "reason": change.reason,
                "algorithm": change.affected_algorithm,
            }
        )
    ctx.drift_events = events
    session.flush()
    _publish_drift_events(events, ctx)

def _publish_drift_events(events: list[dict], ctx: "PipelineContext") -> None:
    """Realtime: newly detected drift goes straight to the SSE stream.

    Same guarded pattern as pipeline_runner — a standalone worker process has
    no bus, so this is a no-op there and polling covers it.
    """
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
    except Exception:  # noqa: BLE001 — standalone worker: polling covers it
        pass
    logger.info("stage_drift_done", extra={"events": len(events)})
    return ctx


class StageDrift:
    def execute(self, ctx: PipelineContext, session) -> PipelineContext:
        return execute(ctx, session)
