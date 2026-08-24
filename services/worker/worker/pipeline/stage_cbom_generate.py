"""Optional pipeline stage: write a CycloneDX CBOM for the scan."""

from __future__ import annotations

import logging
from pathlib import Path

from worker.pipeline.pipeline_runner import PipelineContext

logger = logging.getLogger(__name__)


def execute(ctx: PipelineContext) -> PipelineContext:
    try:
        from cbom.generator import CbomGenerator
    except Exception:
        logger.debug("cbom_unavailable")
        return ctx
    records = ctx.evidence_records or ctx.findings
    if not records:
        return ctx
    bom = CbomGenerator().from_records(
        records,
        name=ctx.target_repo,
        version=ctx.target_commit or ctx.target_branch or "unknown",
        vulnerabilities=(ctx.container_result or {}).get("vulnerabilities"),
    )
    dest = Path(ctx.workspace_dir) / f"cbom-{ctx.scan_id or ctx.job_id}.json"
    dest.write_text(CbomGenerator().to_json(bom), encoding="utf-8")
    ctx.scan_meta = dict(ctx.scan_meta or {})
    ctx.scan_meta["cbom_path"] = str(dest)
    logger.info("stage_cbom_done", extra={"path": str(dest), "components": len(bom.get("components") or [])})
    return ctx


class StageCbomGenerate:
    def execute(self, ctx: PipelineContext) -> PipelineContext:
        return execute(ctx)
