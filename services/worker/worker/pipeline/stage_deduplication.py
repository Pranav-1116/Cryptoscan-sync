"""Pipeline stage: merge findings into crypto assets."""

from __future__ import annotations

import logging

from worker.pipeline.pipeline_runner import PipelineContext

logger = logging.getLogger(__name__)


def execute(ctx: PipelineContext, session, rows=None) -> PipelineContext:
    try:
        from deduplication.core.engine import DeduplicationEngine
        from db.repositories.asset_repository import AssetRepository
    except Exception:
        logger.debug("dedup_unavailable")
        return ctx
    if rows is None:
        from sqlalchemy import select

        from db.models.evidence_record import EvidenceRecord

        rows = list(session.execute(select(EvidenceRecord).where(EvidenceRecord.scan_id == ctx.scan_id)).scalars())
    findings = []
    for row in rows:
        payload = dict(row.finding_data or {})
        payload["evidence_id"] = row.id
        payload["finding_id"] = row.id
        payload["algorithm"] = row.algorithm
        payload["purpose"] = row.purpose
        payload["mode"] = row.mode
        payload["key_size"] = row.key_size
        payload["file_path"] = row.file_path
        payload["line_number"] = row.line_number
        payload["is_hardcoded_key"] = row.is_hardcoded_key
        payload["confidence"] = row.confidence
        findings.append(payload)
    assets = DeduplicationEngine().merge(findings)
    AssetRepository(session).replace_for_scan(ctx.scan_id or "", assets)
    session.flush()
    logger.info("stage_dedup_done", extra={"assets": len(assets)})
    return ctx


class StageDeduplication:
    def execute(self, ctx: PipelineContext, session, rows=None) -> PipelineContext:
        return execute(ctx, session, rows)
