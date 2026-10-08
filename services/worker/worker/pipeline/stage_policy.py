"""Pipeline stage: evaluate policy rules."""

from __future__ import annotations

import logging
from pathlib import Path

from worker.config.settings import get_settings
from worker.pipeline.pipeline_runner import PipelineContext

logger = logging.getLogger(__name__)


def execute(ctx: PipelineContext, session) -> PipelineContext:
    from sqlalchemy import select

    from db.models.evidence_record import EvidenceRecord
    from policy.core.engine import PolicyEngine

    settings = get_settings()
    rules_dir = settings.POLICY_RULES_DIR or str(Path(__file__).resolve().parents[3] / "policy" / "rule_definitions")
    engine = PolicyEngine(rules_dir)
    rows = list(session.execute(select(EvidenceRecord).where(EvidenceRecord.scan_id == ctx.scan_id)).scalars())
    for row in rows:
        finding_data = dict(row.finding_data or {})
        if ctx.compliance_scopes and not finding_data.get("compliance_scopes"):
            finding_data["compliance_scopes"] = list(ctx.compliance_scopes)
        payload = {
            "id": row.id,
            "evidence_id": row.id,
            "algorithm": row.algorithm,
            "key_size": row.key_size,
            "mode": row.mode,
            "purpose": row.purpose,
            "is_hardcoded_key": row.is_hardcoded_key,
            "normalized_crypto": row.normalized_crypto or {},
            "finding_data": finding_data,
            "compliance_scopes": ctx.compliance_scopes or finding_data.get("compliance_scopes") or [],
        }
        evaluation = engine.evaluate(payload)
        row.policy_evaluation = evaluation.model_dump(mode="json")
        row.compliance_status = evaluation.overall_status
    session.flush()
    logger.info("stage_policy_done", extra={"count": len(rows)})
    return ctx


class StagePolicy:
    def execute(self, ctx: PipelineContext, session) -> PipelineContext:
        return execute(ctx, session)
