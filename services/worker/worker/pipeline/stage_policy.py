"""
Pipeline Stage 6: Policy evaluation.
Evaluates all findings against compliance rules.
"""
from __future__ import annotations

import logging

from policy.core.engine import PolicyEngine
from database.db.repositories.evidence_repository import EvidenceRepository

from worker.pipeline.pipeline_runner import PipelineContext

logger = logging.getLogger(__name__)


class StagePolicy:
    """Policy stage: evaluate compliance."""

    async def execute(self, ctx: PipelineContext) -> PipelineContext:
        """
        For each evidence record:
        1. Apply all active policy rules
        2. Compute compliance_status (PASS/WARN/FAIL)
        3. Store policy_evaluation JSONB

        Returns: Updated context.
        """
        if not ctx.scan_id:
            raise ValueError("scan_id not set")

        logger.info(
            "policy_start",
            extra={
                "job_id": ctx.job_id,
                "scan_id": ctx.scan_id,
            },
        )

        try:
            from database.db.connection.session import AsyncSessionFactory

            async with AsyncSessionFactory() as db:
                evidence_repo = EvidenceRepository(db)
                engine = PolicyEngine()

                # Fetch all evidence records
                evidence_records, _ = await evidence_repo.list_by_scan(
                    scan_id=ctx.scan_id,
                    offset=0,
                    limit=10000,
                )

                compliant_count = 0
                non_compliant_count = 0

                for record in evidence_records:
                    # Evaluate
                    policy_result = engine.evaluate(record)

                    # Update DB
                    await evidence_repo.update_policy_evaluation(
                        evidence_id=record.evidence_id,
                        policy_evaluation=policy_result.model_dump(),
                        compliance_status=policy_result.overall_status,
                    )

                    if policy_result.overall_status == "PASS":
                        compliant_count += 1
                    else:
                        non_compliant_count += 1

                logger.info(
                    "policy_complete",
                    extra={
                        "job_id": ctx.job_id,
                        "scan_id": ctx.scan_id,
                        "compliant": compliant_count,
                        "non_compliant": non_compliant_count,
                    },
                )

                return ctx.update()

        except Exception as exc:
            logger.exception(
                "policy_failed",
                extra={
                    "job_id": ctx.job_id,
                    "scan_id": ctx.scan_id,
                    "error": str(exc),
                },
            )
            raise