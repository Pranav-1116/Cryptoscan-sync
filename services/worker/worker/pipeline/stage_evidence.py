"""Pipeline stage: evidence integrity chain."""

from __future__ import annotations

import logging

from worker.pipeline.pipeline_runner import PipelineContext

logger = logging.getLogger(__name__)


def execute(ctx: PipelineContext) -> PipelineContext:
    from evidence.core.pipeline import EvidencePipeline

    pipeline = EvidencePipeline(scan_session_id=ctx.scan_id)
    records, manifest = pipeline.process(findings=ctx.findings, scan_id=ctx.scan_id)
    ctx.evidence_records = [r.model_dump(mode="json") for r in records]
    ctx.manifest = manifest.model_dump(mode="json")
    logger.info("stage_evidence_done", extra={"records": len(ctx.evidence_records)})
    return ctx


class StageEvidence:
    def execute(self, ctx: PipelineContext) -> PipelineContext:
        return execute(ctx)
