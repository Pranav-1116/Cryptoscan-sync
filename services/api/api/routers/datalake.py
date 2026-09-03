"""Data-lake export API (P2) — append-only, hash-chained, deterministic.

* POST /datalake/export      seal a batch of records into the lake (chained)
* GET  /datalake/batches      list batches for a lake (newest first)
* GET  /datalake/batches/{id} batch manifest + chain verification status
* POST /datalake/verify/{id}  recompute hashes from stored records and verify

Every batch links to its predecessor; a tampered record or broken link is
detected on verification and surfaced. No AI — pure hashing/chaining.
"""

from __future__ import annotations

import logging

from datalake.manifest import (
    DataLakeExporter,
    verify_batch,
    verify_chain,
)
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, require_roles

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/datalake", tags=["data-lake"])

_WRITE_ROLES = ("admin", "superadmin", "auditor")


class ExportRequest(BaseModel):
    lake_id: str = Field("primary", min_length=1, max_length=128)
    kind: str = Field("findings", max_length=40)
    records: list[dict] = Field(default_factory=list, max_length=10000)
    seal_signature: str | None = None
    signer_key_id: str | None = None


def _lake_anchor(lake_id: str) -> str:
    import hashlib

    return hashlib.sha256(lake_id.encode("utf-8")).hexdigest()


def _latest_batches(db: Session, lake_id: str) -> list:
    from db.models.p2 import LakeExportBatch

    return list(db.execute(
        select(LakeExportBatch)
        .where(LakeExportBatch.lake_id == lake_id)
        .order_by(LakeExportBatch.batch_id.asc())
    ).scalars())


@router.post("/export")
def export_batch(
    body: ExportRequest,
    db: Session = Depends(get_db_session),
    user: str = Depends(require_roles("admin", "superadmin", "ciso")),
):
    from db.models.p2 import LakeExportBatch

    prior = _latest_batches(db, body.lake_id)
    ex = DataLakeExporter(body.lake_id)
    if prior:
        # resume chain at the last sealed batch
        ex._anchor = prior[0].previous_digest if prior[0].previous_digest else _lake_anchor(body.lake_id)
        ex._last_chain_digest = prior[-1].chain_digest
        ex._next_batch_id = prior[-1].batch_id + 1

    batch = ex.build_batch(body.records)
    row = LakeExportBatch(
        lake_id=batch.lake_id,
        batch_id=batch.batch_id,
        record_count=batch.record_count,
        record_hashes=batch.record_hashes,
        batch_digest=batch.batch_digest,
        previous_digest=batch.previous_digest,
        chain_digest=batch.chain_digest,
        signature=body.seal_signature,
        signer_key_id=body.signer_key_id,
        export_kind=body.kind,
        status="SEALED",
        created_by=user,
        records=body.records,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return {
        "id": row.id,
        "lake_id": row.lake_id,
        "batch_id": row.batch_id,
        "record_count": row.record_count,
        "batch_digest": row.batch_digest,
        "previous_digest": row.previous_digest,
        "chain_digest": row.chain_digest,
        "status": row.status,
    }


@router.get("/batches")
def list_batches(
    lake_id: str = "primary",
    limit: int = 100,
    db: Session = Depends(get_db_session),
    user: str = Depends(get_current_user),
):
    from db.models.p2 import LakeExportBatch

    limit = max(1, min(int(limit or 100), 500))
    rows = list(db.execute(
        select(LakeExportBatch)
        .where(LakeExportBatch.lake_id == lake_id)
        .order_by(LakeExportBatch.batch_id.desc())
        .limit(limit)
    ).scalars())
    return {
        "lake_id": lake_id,
        "head": rows[0].chain_digest if rows else None,
        "batches": [
            {
                "id": r.id,
                "batch_id": r.batch_id,
                "record_count": r.record_count,
                "batch_digest": r.batch_digest,
                "chain_digest": r.chain_digest,
                "previous_digest": r.previous_digest,
                "status": r.status,
                "export_kind": r.export_kind,
            }
            for r in rows
        ],
    }


@router.post("/verify/{batch_pk}")
def verify_stored_batch(
    batch_pk: str,
    db: Session = Depends(get_db_session),
    user: str = Depends(get_current_user),
):
    from db.models.p2 import LakeExportBatch

    row = db.get(LakeExportBatch, batch_pk)
    if not row:
        raise HTTPException(status_code=404, detail="batch not found")

    records = row.records or []
    res = verify_batch(
        _as_batch(row),
        records,
        expected_previous=row.previous_digest,
    )

    # chain integrity across the whole lake
    all_batches = _latest_batches(db, row.lake_id)
    chain = verify_chain([_as_batch(b) for b in all_batches], lake_anchor=_lake_anchor(row.lake_id))

    ok = res.ok and chain.ok
    return {
        "batch_id": row.batch_id,
        "lake_id": row.lake_id,
        "verified": ok,
        "batch_errors": res.errors,
        "chain_errors": chain.errors,
        "head_chain_digest": all_batches[-1].chain_digest if all_batches else None,
    }


def _as_batch(row):
    from datalake.manifest import LakeBatch

    return LakeBatch(
        lake_id=row.lake_id,
        batch_id=row.batch_id,
        record_count=row.record_count,
        record_hashes=list(row.record_hashes or []),
        batch_digest=row.batch_digest,
        previous_digest=row.previous_digest,
        chain_digest=row.chain_digest,
    )
