"""Cryptographic-fact query API (advanced/48 + 51 P0#1, round 31).

``GET /facts/crypto`` — the pure fact projection over live evidence:
facts grouped by (algorithm, purpose, file, parameters), each carrying
its exact evidence references. This is the read-side half of report
51's fact/risk separation: no risk scores, no asset identity, no
dedup coupling — just what was observed, where, how often, by whom.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, require_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/facts", tags=["facts"])

#: hard ceiling on rows read for one projection — a fact query must stay
#: bounded, and the truncation is reported, never silent
MAX_ROWS = 10_000


@router.get("/crypto")
def crypto_facts(
    algorithm: str | None = Query(None, description="Filter facts by exact algorithm name"),
    file_prefix: str | None = Query(None, description="Filter by file path prefix"),
    min_observations: int = Query(1, ge=1, description="Only facts observed at least this often"),
    include_deleted: bool = Query(False, description="Include soft-deleted evidence rows"),
    limit: int = Query(200, ge=1, le=1000),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    from api.facts.projection import project_facts, summarize_facts
    from db.repositories.evidence_repository import EvidenceRepository

    repo = EvidenceRepository(db)
    rows: list = []
    total = 1
    page = 1
    truncated = False
    while len(rows) < MAX_ROWS:
        batch, total = repo.list_all(
            algorithm=algorithm, page=page, page_size=500,
            include_deleted=include_deleted,
        )
        if not batch:
            break
        rows.extend(batch)
        page += 1
        if len(rows) >= total:
            break
    if len(rows) > MAX_ROWS:
        rows = rows[:MAX_ROWS]
        truncated = True

    dicts = [row.to_dict() for row in rows]
    facts = project_facts(dicts)
    if file_prefix:
        facts = [f for f in facts
                 if str(f["fact"].get("file_path") or "").startswith(file_prefix)]
    facts = [f for f in facts if f["observation_count"] >= min_observations]
    return {
        "model": "cryptographic-facts/read-projection-v1",
        "note": "facts derived live from evidence records; the fused "
                "crypto_assets write side is unchanged (advanced/51 P0#1 "
                "separation, read-side step)",
        "summary": summarize_facts(facts),
        "evidence_rows_read": len(rows),
        "evidence_rows_total": total,
        "truncated": truncated,
        "facts": facts[:limit],
        "facts_returned": min(len(facts), limit),
        "facts_matching": len(facts),
    }


@router.get("/code-graph")
def code_fact_graph(
    algorithm: str | None = Query(None, description="Filter by exact algorithm name"),
    file_prefix: str | None = Query(None, description="Filter by file path prefix"),
    min_observations: int = Query(1, ge=1, description="Only facts observed at least this often"),
    include_deleted: bool = Query(False, description="Include soft-deleted evidence rows"),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Code-level fact graph slice (advanced/48 P1#11, advanced/58, round 34).

    ``file DEFINES fact OBSERVED_BY evidence`` — a live projection over
    the same evidence rows as ``GET /facts/crypto``, shaped as nodes and
    edges. ``CALLS`` edges are absent and stated as absent: they need
    call-graph parsing the scanners do not produce, and co-location is
    not a call. Nothing persisted; the fused write side is unchanged.
    """
    from api.facts.projection import code_graph_facts, project_facts
    from db.repositories.evidence_repository import EvidenceRepository

    repo = EvidenceRepository(db)
    rows: list = []
    page = 1
    while len(rows) < MAX_ROWS:
        batch, total = repo.list_all(
            algorithm=algorithm, page=page, page_size=500,
            include_deleted=include_deleted,
        )
        if not batch:
            break
        rows.extend(batch)
        page += 1
        if len(rows) >= total:
            break
    truncated = len(rows) > MAX_ROWS
    if truncated:
        rows = rows[:MAX_ROWS]

    dicts = [row.to_dict() for row in rows]
    facts = project_facts(dicts)
    if file_prefix:
        facts = [f for f in facts
                 if str(f["fact"].get("file_path") or "").startswith(file_prefix)]
    facts = [f for f in facts if f["observation_count"] >= min_observations]
    graph = code_graph_facts(facts)
    graph["evidence_rows_read"] = len(rows)
    graph["truncated"] = truncated
    graph["fact_count"] = len(facts)
    return graph


@router.post("/rebuild")
def rebuild_fact_store(
    file_prefix: str | None = Query(None, description="Rebuild only files under this prefix"),
    user: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Rebuild the materialised fact store from evidence (51 P0#1, round 35).

    Fact rows are derived — this endpoint recomputes them from the
    evidence table (all files, or one prefix). It exists because the fact
    store is a projection, not a second truth: drop it, rebuild it, same
    answer. The scans pipeline maintains it automatically after each
    scan; this is the operator path for backfills after a migration or a
    bulk evidence import. Idempotent.
    """
    from db.models.evidence_record import EvidenceRecord
    from db.repositories.fact_repository import FactRepository

    repo = FactRepository(db)
    if file_prefix:
        paths = sorted({
            p for p in db.execute(
                select(EvidenceRecord.file_path).where(
                    EvidenceRecord.deleted_at.is_(None))
            ).scalars() if p and p.startswith(file_prefix)
        })
        result = repo.rebuild(file_paths=paths)
    else:
        result = repo.rebuild()
    db.commit()
    return {
        "model": "fact-store/rebuild-v1",
        **result,
        "note": "fact rows are derived from evidence and fully rebuildable; "
                "GET /facts/crypto keeps its live-projection contract",
    }
