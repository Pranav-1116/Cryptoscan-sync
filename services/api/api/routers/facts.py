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
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session

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
