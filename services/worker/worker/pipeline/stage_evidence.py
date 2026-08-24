"""
Pipeline Stage 3: Evidence integrity chain.
Transforms raw findings into tamper-proof evidence records.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from evidence.core.pipeline import EvidencePipeline
from evidence.models.scan_manifest import ScanManifest

from worker.pipeline.pipeline_runner import PipelineContext

logger = logging.getLogger(__name__)


class StageEvidence:
    """Evidence stage: create integrity chain."""

    async def execute(self, ctx: PipelineContext) -> PipelineContext:
        """
        Read scan-results.json, apply evidence pipeline:
        1. Canonical serialization
        2. Content hashing (SHA-256)
        3. Chain linking
        4. Manifest generation

        Output: evidence-records-{job_id}.json, manifest-{job_id}.json
        """
        if not ctx.scan_results_file:
            raise ValueError("scan_results_file not set")

        logger.info(
            "evidence_start",
            extra={
                "job_id": ctx.job_id,
                "scan_file": ctx.scan_results_file,
            },
        )

        try:
            # Load scan results
            with open(ctx.scan_results_file, "r") as f:
                scan_data = json.load(f)

            findings = scan_data.get("findings", [])

            # Apply evidence pipeline
            evidence_pipeline = EvidencePipeline()
            evidence_records, manifest = await evidence_pipeline.process(
                findings=findings,
                scan_id=None,  # Will be assigned by DB stage
                scan_timestamp=scan_data.get("scan_timestamp"),
            )

            # Write evidence records
            evidence_file = (
                Path(ctx.workspace_dir) / f"evidence-records-{ctx.job_id}.json"
            )
            with open(evidence_file, "w") as f:
                json.dump(
                    [r.model_dump(mode="json") for r in evidence_records],
                    f,
                    indent=2,
                )

            # Write manifest
            manifest_file = Path(ctx.workspace_dir) / f"manifest-{ctx.job_id}.json"
            with open(manifest_file, "w") as f:
                json.dump(manifest.model_dump(mode="json"), f, indent=2)

            logger.info(
                "evidence_complete",
                extra={
                    "job_id": ctx.job_id,
                    "evidence_count": len(evidence_records),
                    "manifest_hash": manifest.summary.manifest_hash,
                    "evidence_file": str(evidence_file),
                    "manifest_file": str(manifest_file),
                },
            )

            return ctx.update(
                evidence_records_file=str(evidence_file),
            )

        except Exception as exc:
            logger.exception(
                "evidence_failed",
                extra={
                    "job_id": ctx.job_id,
                    "error": str(exc),
                },
            )
            raise