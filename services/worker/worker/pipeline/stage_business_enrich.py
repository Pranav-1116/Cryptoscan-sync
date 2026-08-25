"""Persist business_context onto crypto_assets.extra after the graph is known."""

from __future__ import annotations

import logging
from typing import Any

from worker.pipeline.pipeline_runner import PipelineContext

logger = logging.getLogger(__name__)


def execute(ctx: PipelineContext, session=None) -> PipelineContext:
    if session is None:
        return ctx
    try:
        from api.graph_builder import collect_graph_payload
        from business_context.core.enricher import enrich_assets
        from db.models.crypto_asset import CryptoAsset
    except Exception:
        logger.debug("business_enrich_imports_unavailable", exc_info=True)
        return ctx
    try:
        payload = collect_graph_payload(session)
        ranked = enrich_assets(
            payload.get("assets") or [],
            systems=payload.get("systems") or [],
            edges=payload.get("edges") or [],
            processes=payload.get("processes") or [],
            owners=payload.get("owners") or [],
        )
        updated = 0
        for item in ranked:
            row = session.get(CryptoAsset, item.get("id"))
            if row is None:
                continue
            extra = dict(row.extra or {})
            extra["business_context"] = item.get("business_context")
            row.extra = extra
            updated += 1
        session.flush()
        ctx.scan_meta["business"] = {"enriched": updated}
        logger.info("stage_business_enrich_done", extra=ctx.scan_meta["business"])
    except Exception:
        logger.debug("stage_business_enrich_failed", exc_info=True)
    return ctx
