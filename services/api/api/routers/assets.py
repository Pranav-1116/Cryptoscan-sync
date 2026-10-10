"""Deduplicated cryptographic assets."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from db.repositories.asset_repository import AssetRepository

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("")
def list_assets(
    algorithm: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    rows, total = AssetRepository(db).list_assets(algorithm=algorithm, page=page, page_size=page_size)
    return {
        "assets": [row.to_dict() for row in rows],
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
