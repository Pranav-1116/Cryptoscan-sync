"""
Pipeline Stage 5: Cryptographic normalization.
Canonicalises algorithm names and enriches with standards metadata.
"""
from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from normalization.core.engine import NormalizationEngine
from database.db.repositories.evidence_repository import EvidenceRepository

from worker.pipeline.pipeline_runner import PipelineContext

logger = logging.getLogger(__name__)


class StageNormalize:
    """Normalize stage: canonicalise algorithms."""

    async def execute(self, ctx: PipelineContext) -> PipelineContext:
        """
        For each evidence record in scan:
        1. Look up raw algorithm name in normalization rules
        2. Compute normalized form with NIST/IANA/CBOM metadata
        3. Update evidence_records.normalized_crypto column

        Returns: Updated context (no output files, DB updated in-place).
        """
        if not ctx.scan_id:
            raise ValueError("scan_id not set")

        logger.info(
            "normalize_start",
            extra={
                "job_id": ctx.job_id,
                "scan_id": ctx.scan_id,
            },
        )

        try:
            from database.db.connection.session import AsyncSessionFactory

            async with AsyncSessionFactory() as db:
                evidence_repo = EvidenceRepository(db)
                engine = NormalizationEngine()

                # Fetch all evidence records for this scan
                evidence_records, _ = await evidence_repo.list_by_scan(
                    scan_id=ctx.scan_id,
                    offset=0,
                    limit=10000,
                )

                normalized_count = 0
                for record in evidence_records:
                    raw_algo = record.algorithm
                    normalized = engine.normalize(raw_algo)

                    await evidence_repo.update_normalized_crypto(
                        evidence_id=record.evidence_id,
                        normalized_crypto=normalized.model_dump(),
                    )
                    normalized_count += 1

                logger.info(
                    "normalize_complete",
                    extra={
                        "job_id": ctx.job_id,
                        "scan_id": ctx.scan_id,
                        "normalized_count": normalized_count,
                    },
                )

                return ctx

        except Exception as exc:
            logger.exception(
                "normalize_failed",
                extra={
                    "job_id": ctx.job_id,
                    "scan_id": ctx.scan_id,
                    "error": str(exc),
                },
            )
            raise