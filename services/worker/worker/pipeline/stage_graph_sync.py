"""Sync the relational inventory into Neo4j after a scan."""

from __future__ import annotations

import logging
from typing import Any

from worker.pipeline.pipeline_runner import PipelineContext

logger = logging.getLogger(__name__)


def execute(ctx: PipelineContext, session=None) -> PipelineContext:
    try:
            from api.graph_builder import sync_graph
    except Exception:
        logger.debug("graph_sync_imports_unavailable", exc_info=True)
        return ctx
    if session is None:
        try:
            from db.connection.session import SessionLocal

            owns = True
            session = SessionLocal()
        except Exception:
            logger.debug("graph_sync_no_session", exc_info=True)
            return ctx
    else:
        owns = False
    try:
        result: dict[str, Any] = sync_graph(session)
        ctx.scan_meta["graph"] = {
            "backend": result.get("backend") or (result.get("health") or {}).get("backend"),
            "synced": bool(result.get("synced")),
            "nodes": result.get("nodes"),
            "edges": result.get("edges"),
        }
        logger.info("stage_graph_sync_done", extra=ctx.scan_meta["graph"])
    except Exception:
        logger.warning("stage_graph_sync_failed", exc_info=True)
        ctx.scan_meta["graph"] = {"backend": "memory", "synced": False}
    finally:
        if owns:
            session.close()
    return ctx
