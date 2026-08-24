"""
Pipeline Stage 7: Drift detection.
Compares current scan findings against approved baseline.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from drift.core.comparator import DriftComparator
from database.db.repositories.baseline_repository import BaselineRepository
from database.db.repositories.drift_repository import DriftRepository
from database.db.repositories.evidence_repository import EvidenceRepository

from worker.pipeline.pipeline_runner import PipelineContext

logger = logging.getLogger(__name__)


class StageDrift:
    """Drift stage: detect changes from baseline."""

    async def execute(self, ctx: PipelineContext) -> PipelineContext:
        """
        1. Find active baseline for this system
        2. Load baseline findings
        3. Compare current findings
        4. Create drift event records
        5. Store in DB

        Returns: Updated context with drift_events.
        """
        if not ctx.scan_id:
            raise ValueError("scan_id not set")

        logger.info(
            "drift_start",
            extra={
                "job_id": ctx.job_id,
                "scan_id": ctx.scan_id,
                "repo": ctx.target_repo,
            },
        )

        try:
            from database.db.connection.session import AsyncSessionFactory

            async with AsyncSessionFactory() as db:
                baseline_repo = BaselineRepository(db)
                evidence_repo = EvidenceRepository(db)
                drift_repo = DriftRepository(db)

                # Find baseline for this system/environment
                baseline = await baseline_repo.get_active(
                    system_identifier=ctx.target_repo,
                    environment="production",
                )

                if baseline is None:
                    logger.info(
                        "no_baseline_for_drift",
                        extra={
                            "job_id": ctx.job_id,
                            "repo": ctx.target_repo,
                        },
                    )
                    return ctx.update(drift_events=[])

                # Load baseline findings
                baseline_findings, _ = await evidence_repo.list_by_scan(
                    scan_id=str(baseline.approved_scan_id),
                    offset=0,
                    limit=10000,
                )

                # Load current findings
                current_findings, _ = await evidence_repo.list_by_scan(
                    scan_id=ctx.scan_id,
                    offset=0,
                    limit=10000,
                )

                # Detect drift
                comparator = DriftComparator()
                drift_events = comparator.compare(
                    baseline_findings=baseline_findings,
                    current_findings=current_findings,
                )

                # Store drift events
                stored_events: List[Dict[str, Any]] = []
                for drift in drift_events:
                    event = await drift_repo.create(
                        baseline_id=baseline.baseline_id,
                        current_scan_id=ctx.scan_id,
                        drift_type=drift["type"],
                        severity=drift["severity"],
                        drift_details=drift["details"],
                    )
                    stored_events.append(
                        {
                            "drift_id": event.drift_id,
                            "type": event.drift_type,
                            "severity": event.severity,
                        }
                    )

                logger.info(
                    "drift_complete",
                    extra={
                        "job_id": ctx.job_id,
                        "scan_id": ctx.scan_id,
                        "drift_count": len(stored_events),
                        "critical": sum(
                            1 for e in stored_events if e["severity"] == "CRITICAL"
                        ),
                    },
                )

                return ctx.update(
                    baseline_id=str(baseline.baseline_id),
                    drift_events=stored_events,
                )

        except Exception as exc:
            logger.exception(
                "drift_failed",
                extra={
                    "job_id": ctx.job_id,
                    "scan_id": ctx.scan_id,
                    "error": str(exc),
                },
            )
            # Don't re-raise — drift detection is non-critical
            logger.warning("drift_stage_non_critical", extra={"job_id": ctx.job_id})
            return ctx.update(drift_events=[])