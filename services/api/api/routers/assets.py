"""Deduplicated cryptographic assets."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from db.repositories.asset_repository import AssetRepository

router = APIRouter(prefix="/assets", tags=["assets"])


def _evidence_classification(db, asset_row) -> dict:
    """Every record shows its evidence classification (gap analysis §A).

    The level is derived from the linked evidence records only — an
    unclassified record reads UNCLASSIFIED, never promoted by assumption.
    """
    from db.models.evidence_record import EvidenceRecord
    from shared_models.evidence_classification import classify_records

    ids = [link.evidence_id for link in asset_row.evidence_links]
    if not ids:
        return {"strongest_level": "UNCLASSIFIED", "evidence_ids": [],
                "counts": {}, "records": [],
                "note": "no evidence is linked to this record: its evidence "
                        "level is unknown, never assumed"}
    rows = db.query(EvidenceRecord).filter(EvidenceRecord.id.in_(ids)).all()
    provenance_rows = []
    for record in rows:
        provenance = record.provenance or {}
        provenance_rows.append({
            "id": record.id,
            "file_path": record.file_path,
            "line_number": record.line_number,
            "source": provenance.get("source"),
            "collector": provenance.get("collector"),
            "evidence_level": provenance.get("evidence_level"),
        })
    report = classify_records(provenance_rows)
    report["evidence_ids"] = ids
    return report


@router.get("")
def list_assets(
    algorithm: str | None = None,
    q: str | None = Query(None, max_length=200,
                          description="Server-side search across the whole estate: asset id, "
                                      "identity spine key, algorithm, file location"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    rows, total = AssetRepository(db).list_assets(
        algorithm=algorithm, q=q, page=page, page_size=page_size)
    return {
        "assets": [
            {**row.to_dict(),
             "evidence_classification": _evidence_classification(db, row)}
            for row in rows],
        "total_count": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/{asset_id}")
def get_asset(
    asset_id: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    row = AssetRepository(db).get_by_id(asset_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    payload = row.to_dict()
    payload["evidence_ids"] = [link.evidence_id for link in row.evidence_links]
    payload["evidence_classification"] = _evidence_classification(db, row)
    return payload


@router.get("/libraries/identity")
def library_identities(
    limit: int = Query(500, ge=1, le=2000,
                       description="How many assets' library lists to fold in"),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Canonical library identities across the estate (audit 70, round 29).

    The same library arrives as ``OpenSSL``, ``libssl.so.1.1`` and
    ``py-openssl``; this surface folds every asset's raw library entries
    into registry identities with their alias sets — the dedup view the
    asset inventory could not give. Unmatched names stay unmatched.
    """
    from normalization.library_identity import merge_library_identities

    rows, total = AssetRepository(db).list_assets(page=1, page_size=limit)
    entries: list = []
    for row in rows:
        libraries = getattr(row, "libraries", None) or []
        if isinstance(libraries, list):
            entries.extend(libraries)
    merged = merge_library_identities(entries)
    merged["assets_considered"] = len(rows)
    merged["asset_total"] = total
    merged["raw_entries"] = len(entries)
    return merged
