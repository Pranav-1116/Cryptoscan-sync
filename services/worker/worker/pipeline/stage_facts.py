"""Pipeline stage: maintain the materialised fact store (advanced/51, round 35).

After evidence persists, recompute the cryptographic fact rows for the
files this scan touched. The fact store is derived — if this stage fails,
nothing is lost (the live projection still answers /facts/crypto, and the
admin rebuild endpoint backfills); the stage is fail-soft by design.
"""

from __future__ import annotations

import logging

from worker.pipeline.pipeline_runner import PipelineContext

logger = logging.getLogger(__name__)


def execute(ctx: PipelineContext, session=None) -> PipelineContext:
    try:
        from db.repositories.fact_repository import FactRepository
    except Exception:
        logger.debug("facts_stage_imports_unavailable", exc_info=True)
        return ctx

    owns = False
    if session is None:
        try:
            from db.connection.session import SessionLocal

            session = SessionLocal()
            owns = True
        except Exception:
            logger.debug("facts_stage_no_session", exc_info=True)
            return ctx
    try:
        repo = FactRepository(session)
        paths = repo.files_for_scan(ctx.scan_id)
        if not paths:
            return ctx
        result = repo.rebuild(file_paths=paths)
        session.commit()
        logger.info("stage_facts_done", extra={
            "files": len(paths),
            "facts": result.get("facts_upserted"),
            "stale": result.get("facts_stale"),
        })
    except Exception:
        session.rollback()
        logger.debug("facts_stage_failed", exc_info=True)
    finally:
        if owns:
            session.close()
    return ctx


class StageFacts:
    def execute(self, ctx: PipelineContext) -> PipelineContext:
        return execute(ctx)
