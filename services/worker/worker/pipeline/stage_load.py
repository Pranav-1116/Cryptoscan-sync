"""
Pipeline Stage 4: Database loading.
Persists evidence records and creates scan records.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from database.db.loader.evidence_loader import EvidenceLoader
from database.db.repositories.scan_repository import ScanRepository

from worker.pipeline.pipeline_runner import PipelineContext

logger = logging.getLogger(__name__)


class StageLoad:
    """Load stage: persist to database."""

    async def execute(self, ctx: PipelineContext) -> PipelineContext:
        """
        1. Create Scan record
        2. Load evidence records with integrity verification
        3. Verify counts match manifest

        Returns: Updated context with scan_id.
        """
        if not ctx.evidence_records_file:
            raise ValueError("evidence_records_file not set")

        logger.info(
            "load_start",
            extra={
                "job_id": ctx.job_id,
                "evidence_file": ctx.evidence_records_file,
            },
        )

        try:
            # Load evidence data
            with open(ctx.evidence_records_file, "r") as f:
                evidence_data = json.load(f)

            # Create DB session (would come from DI in real implementation)
            from database.db.connection.session import AsyncSessionFactory

            async with AsyncSessionFactory() as db:
                # Create Scan record
                scan_id = str(uuid4())
                scan_repo = ScanRepository(db)

                await scan_repo.create(
                    scan_id=scan_id,
                    target_type="GIT_REPOSITORY",
                    target_location=ctx.target_repo,
                    target_commit=ctx.target_commit,
                    target_branch=ctx.target_branch,
                    scanner_id="static-java-scanner-v0.1",
                    scanner_version="0.1.0",
                    operator=ctx.triggered_by,
                    statistics={
                        "files_scanned": len(evidence_data),
                        "total_findings": len(evidence_data),
                    },
                    status="LOADING",
                )

                # Load evidence records
                loader = EvidenceLoader(db)
                loaded_count = await loader.load(
                    evidence_records=evidence_data,
                    scan_id=scan_id,
                )

                # Verify counts
                if loaded_count != len(evidence_data):
                    raise ValueError(
                        f"Count mismatch: loaded {loaded_count}, expected {len(evidence_data)}"
                    )

                # Mark scan complete
                await scan_repo.update_status(scan_id, "COMPLETED")

                logger.info(
                    "load_complete",
                    extra={
                        "job_id": ctx.job_id,
                        "scan_id": scan_id,
                        "evidence_loaded": loaded_count,
                    },
                )

                return ctx.update(scan_id=scan_id)

        except Exception as exc:
            logger.exception(
                "load_failed",
                extra={
                    "job_id": ctx.job_id,
                    "error": str(exc),
                },
            )
            raise