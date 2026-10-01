"""Score the resolved system with the 6-factor agility + readiness engines."""

from __future__ import annotations

from db.tenancy import filtered_get

import logging

from worker.pipeline.pipeline_runner import PipelineContext

logger = logging.getLogger(__name__)


def execute(ctx: PipelineContext, session=None) -> PipelineContext:
    if session is None or not ctx.system_id:
        return ctx
    try:
        from agility.readiness import readiness_from_system
        from agility.system_score import calculate_agility_score
        from db.models.system import System
        from db.repositories.maturity_repository import MaturityRepository
        from db.repositories.system_repository import SystemRepository
    except Exception:
        logger.debug("agility_stage_unavailable", exc_info=True)
        return ctx
    try:
        system = filtered_get(session, System, ctx.system_id)
        if system is None:
            return ctx
        assets = SystemRepository(session).assets_for(ctx.system_id)
        evidence = []
        for asset in assets:
            extra = asset.extra or {}
            evidence.append(
                {
                    "algorithm": asset.algorithm,
                    "purpose": asset.purpose,
                    "file_path": asset.file_path,
                    "is_hardcoded_key": asset.is_hardcoded_key,
                    "confidence": asset.confidence,
                    "finding_data": {"metadata": {"library": (asset.libraries or [None])[0] if asset.libraries else None}},
                    "extra": extra,
                }
            )
        payload = system.to_dict()
        score = calculate_agility_score(evidence, payload)
        deps = SystemRepository(session).dependencies_for(ctx.system_id)
        ready = readiness_from_system(payload, agility_score=score["agility_score"], dependency_count=len(deps))
        score["readiness_score"] = ready["readiness_score"]
        score["readiness_category"] = ready["readiness_category"]
        score["readiness"] = ready
        MaturityRepository(session).save_agility(ctx.system_id, score)
        ctx.scan_meta["system_agility"] = {
            "score": score["agility_score"],
            "category": score["category"],
            "readiness": ready["readiness_category"],
        }
        logger.info("stage_agility_done", extra=ctx.scan_meta["system_agility"])
    except Exception:
        logger.debug("stage_agility_failed", exc_info=True)
    return ctx
