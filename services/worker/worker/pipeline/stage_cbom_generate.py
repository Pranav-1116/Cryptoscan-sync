"""Optional pipeline stage: write a CycloneDX CBOM for the scan.

Round 45 (§4.4): the workspace file was the only artifact and the workspace
is ephemeral — the pipeline's BOM evaporated with the run. The stage now
ALSO pins a content-addressed CbomSnapshot row (generator="pipeline"), the
same store the API snapshot route uses, so the pipeline rendering survives
its run and stays traceable: snapshot → scan → evidence → hash chain.
Persistence is fail-soft like the rest of this stage.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path

from worker.pipeline.pipeline_runner import PipelineContext

logger = logging.getLogger(__name__)


def _persist_snapshot(ctx: PipelineContext, bom: dict) -> str | None:
    """Pin the pipeline rendering as a CbomSnapshot row (idempotent)."""
    from cbom.generator import CbomGenerator

    if not ctx.scan_id:
        return None
    from db.connection.session import SessionLocal
    from db.models.cbom_snapshot import CbomSnapshot, normalize_for_snapshot
    from db.models.scan import Scan

    session = SessionLocal()
    try:
        # same rule as the API route: the document's clock anchors to the
        # scan, so identical (scan, evidence) pins collapse to one row
        scan_row = session.query(Scan).filter(Scan.id == ctx.scan_id).one_or_none()
        scan_time = (scan_row.scan_end or scan_row.created_at) if scan_row else None
        pinned = normalize_for_snapshot(
            bom, scan_timestamp_iso=scan_time.isoformat() if scan_time else None)
        document = CbomGenerator().to_json(pinned)
        content_hash = hashlib.sha256(document.encode("utf-8")).hexdigest()
        existing = (
            session.query(CbomSnapshot)
            .filter(CbomSnapshot.scan_id == ctx.scan_id,
                    CbomSnapshot.content_hash == content_hash)
            .one_or_none()
        )
        if existing is not None:
            return str(existing.id)
        row = CbomSnapshot(
            scan_id=ctx.scan_id,
            content_hash=content_hash,
            format="json",
            signed="none",
            generator="pipeline",
            payload=pinned,
            component_count=len(pinned.get("components") or []),
            created_by=f"pipeline:{ctx.job_id}",
            snapshotted_at=datetime.now(timezone.utc),
        )
        session.add(row)
        session.commit()
        return str(row.id)
    finally:
        session.close()


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
    # durable half (round 45): the rendering outlives the workspace
    try:
        snapshot_id = _persist_snapshot(ctx, bom)
    except Exception:
        snapshot_id = None
        logger.warning("stage_cbom_snapshot_persist_failed", exc_info=True)
    if snapshot_id:
        ctx.scan_meta["cbom_snapshot_id"] = snapshot_id
        logger.info("stage_cbom_snapshot_pinned",
                    extra={"snapshot_id": snapshot_id,
                           "components": len(bom.get("components") or [])})
    else:
        logger.info("stage_cbom_done", extra={"path": str(dest),
                                              "components": len(bom.get("components") or [])})
    return ctx


class StageCbomGenerate:
    def execute(self, ctx: PipelineContext) -> PipelineContext:
        return execute(ctx)
