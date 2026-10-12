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


def _mark_failure(ctx: PipelineContext, session) -> None:
    if isinstance(getattr(ctx, "scan_meta", None), dict):
        ctx.scan_meta["fact_store_status"] = "FAILED"
    if session is None:
        return
    try:
        from db.models.scan import Scan
        from db.tenancy import filtered_get

        scan = filtered_get(session, Scan, ctx.scan_id)
        if scan is not None:
            scan.statistics = {**(scan.statistics or {}), "fact_store_status": "FAILED"}
    except Exception:
        # Even if the DB is unusable, the warning that caused this marker is
        # emitted; a failed status write must not lose the evidence transaction.
        logger.warning("facts_stage_status_update_failed scan_id=%s", ctx.scan_id,
                       exc_info=True)


def execute(ctx: PipelineContext, session=None) -> PipelineContext:
    try:
        from db.repositories.fact_repository import FactRepository
    except Exception:
        logger.warning("facts_stage_imports_unavailable scan_id=%s", ctx.scan_id,
                       exc_info=True)
        _mark_failure(ctx, session)
        return ctx

    owns = False
    if session is None:
        try:
            from db.connection.session import SessionLocal

            session = SessionLocal()
            owns = True
        except Exception:
            logger.warning("facts_stage_no_session scan_id=%s", ctx.scan_id,
                           exc_info=True)
            _mark_failure(ctx, session)
            return ctx
    try:
        # SQLAlchemy flushes pending outer writes before a SAVEPOINT. A failed
        # projection rolls back only its own changes, never the caller's scan
        # and evidence transaction. Only a session created here is committed.
        with session.begin_nested():
            repo = FactRepository(session)
            paths = repo.files_for_scan(ctx.scan_id)
            result = repo.rebuild(file_paths=paths) if paths else None
        if owns:
            session.commit()
        if result is not None:
            logger.info("stage_facts_done", extra={
                "scan_id": ctx.scan_id,
                "files": len(paths),
                "facts": result.get("facts_upserted"),
                "stale": result.get("facts_stale"),
            })
    except Exception as exc:
        if owns:
            session.rollback()
        _mark_failure(ctx, session)
        logger.warning("facts_stage_failed scan_id=%s error_type=%s",
                       ctx.scan_id, type(exc).__name__, exc_info=True)
    finally:
        if owns:
            session.close()
    return ctx


class StageFacts:
    def execute(self, ctx: PipelineContext) -> PipelineContext:
        return execute(ctx)
