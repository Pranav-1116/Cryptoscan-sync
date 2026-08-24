"""Pipeline stage: normalize algorithm names."""

from __future__ import annotations

import logging
from pathlib import Path

from worker.config.settings import get_settings
from worker.pipeline.pipeline_runner import PipelineContext

logger = logging.getLogger(__name__)


def execute(ctx: PipelineContext, session) -> PipelineContext:
    from sqlalchemy import select

    from db.models.evidence_record import EvidenceRecord
    from normalization.core.engine import NormalizationEngine

    settings = get_settings()
    rules_dir = settings.NORMALIZATION_RULES_DIR or str(
        Path(__file__).resolve().parents[3] / "normalization" / "rule_definitions"
    )
    engine = NormalizationEngine(rules_dir)
    rows = list(session.execute(select(EvidenceRecord).where(EvidenceRecord.scan_id == ctx.scan_id)).scalars())
    for row in rows:
        normalized = engine.normalize(
            row.algorithm or "UNKNOWN",
            context={
                "mode": row.mode,
                "key_size": row.key_size,
                "padding": row.padding,
                "purpose": row.purpose,
            },
        )
        row.normalized_crypto = normalized.model_dump(mode="json")
        if normalized.algorithm and normalized.algorithm != "UNKNOWN":
            row.algorithm = normalized.algorithm
        if normalized.mode:
            row.mode = normalized.mode
        if normalized.key_size:
            row.key_size = normalized.key_size
    session.flush()
    logger.info("stage_normalize_done", extra={"count": len(rows)})
    return ctx


class StageNormalize:
    def execute(self, ctx: PipelineContext, session) -> PipelineContext:
        return execute(ctx, session)
