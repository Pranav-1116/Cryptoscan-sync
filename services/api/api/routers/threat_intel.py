"""Crypto threat-intel API (deep/30, round 31).

- ``POST /threat-intel/advisories/import`` — import advisories, either
  as a signed bundle (HMAC, the air-gap transfer convention) or as a
  plain admin-supplied list; idempotent per (source, advisory_id).
- ``GET  /threat-intel/advisories`` — query the store (by algorithm,
  type, severity, effectiveness).
- ``GET  /threat-intel/algorithms/{algorithm}`` — the advisory picture
  for one algorithm.
- ``GET  /threat-intel/assets/{asset_id}`` — annotation-only overlay:
  which advisories name this crypto asset's algorithm.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, require_admin
from db.models.crypto_asset import CryptoAsset
from db.models.threat_advisory import AlgorithmAdvisory
from vendor_intel.threat_intel import (
    AdvisoryError,
    advisory_relevance,
    build_advisory_bundle,
    sync_feeds,
    validate_advisories,
    verify_advisory_bundle,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])


class AdvisoryImport(BaseModel):
    advisories: Optional[list[dict[str, Any]]] = None
    bundle: Optional[dict[str, Any]] = None
    secret: Optional[str] = Field(None, min_length=8)


class AdvisoryBuildBundle(BaseModel):
    advisories: list[dict[str, Any]]
    secret: str = Field(..., min_length=8)
    bundle_id: str = ""


def _upsert(db: Session, entries: list[dict[str, Any]]) -> dict[str, int]:
    existing = {
        (row.source, row.advisory_id): row
        for row in db.execute(select(AlgorithmAdvisory)).scalars()
    }
    created = updated = 0
    for entry in entries:
        key = (entry["source"], entry["advisory_id"])
        row = existing.get(key)
        if row is None:
            row = AlgorithmAdvisory(**entry)
            db.add(row)
            existing[key] = row
            created += 1
        else:
            for field in ("advisory_type", "algorithm", "severity", "title",
                          "summary", "url", "published_at", "effective_date",
                          "details"):
                if field in entry:
                    setattr(row, field, entry[field])
            updated += 1
    db.flush()
    return {"created": created, "updated": updated, "total": created + updated}


def _row_dict(row: AlgorithmAdvisory) -> dict[str, Any]:
    return {
        "advisory_id": row.advisory_id,
        "source": row.source,
        "advisory_type": row.advisory_type,
        "algorithm": row.algorithm,
        "severity": row.severity,
        "title": row.title,
        "summary": row.summary,
        "url": row.url,
        "published_at": row.published_at.isoformat() if row.published_at else None,
        "effective_date": row.effective_date.isoformat() if row.effective_date else None,
        "details": row.details,
    }


@router.post("/advisories/import")
def import_advisories(
    body: AdvisoryImport,
    admin: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Signed-bundle (preferred) or admin-direct advisory import."""
    entries: list[dict[str, Any]] | None = None
    if body.bundle is not None:
        if not (body.secret or "").strip():
            raise HTTPException(status_code=422,
                                detail="bundle import requires the bundle secret")
        try:
            entries = verify_advisory_bundle(body.bundle, secret=body.secret)
        except AdvisoryError as exc:
            logger.warning("threat_intel_bundle_rejected",
                           extra={"reason": str(exc), "actor": admin})
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    elif body.advisories is not None:
        try:
            entries = validate_advisories(body.advisories)
        except AdvisoryError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    else:
        raise HTTPException(status_code=422,
                            detail="provide advisories or a signed bundle")
    counts = _upsert(db, entries)
    db.commit()
    logger.info("threat_intel_imported", extra={"entries": counts["total"], "actor": admin})
    return counts | {"accepted": True}


def _configured_feeds() -> list[dict]:
    from api.config.settings import get_settings

    raw = (get_settings().THREAT_INTEL_FEEDS or "").strip()
    feeds = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        name, _, url = part.partition("=")
        feeds.append({"name": name.strip() or url.strip(), "url": url.strip()})
    return feeds


@router.get("/feeds")
def list_feeds(user: str = Depends(get_current_user)):
    """Configured threat-intel feeds (labels + URLs; never the secret)."""
    feeds = _configured_feeds()
    return {
        "model": "threat-intel-feeds/v1",
        "feeds": feeds,
        "feed_count": len(feeds),
        "bundle_format": "zelnx-threat-intel/v1",
        "note": "feed endpoints are deployment configuration; advisories "
                "sync from the same signed-bundle format the platform exports",
    }


@router.post("/advisories/sync")
def sync_advisory_feeds(
    admin: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Sync every configured threat-intel feed now (deep/30, round 35).

    Each feed is fetched, verified (tampered/malformed bundles are
    rejected whole — nothing persists from a bad feed), and upserted.
    One failing feed never blocks the others; failures are reported
    per feed. No feeds configured -> an explicit empty result, not an
    error: the manual bundle import remains the community path.
    """
    from api.config.settings import get_settings

    feeds = _configured_feeds()
    if not feeds:
        return {"model": "threat-intel-feeds/sync-v1", "feeds_total": 0,
                "feeds_ok": 0, "results": [], "created": 0, "updated": 0,
                "note": "no feeds configured (THREAT_INTEL_FEEDS is empty)"}

    settings = get_settings()
    sync = sync_feeds(
        feeds,
        secret=settings.THREAT_INTEL_FEED_SECRET,
        timeout=float(settings.THREAT_INTEL_FEED_TIMEOUT or 15),
    )
    counts = {"created": 0, "updated": 0, "total": 0}
    if sync["entries"]:
        counts = _upsert(db, sync["entries"])
        db.commit()
    logger.info("threat_intel_feed_sync", extra={
        "entries": counts["total"], "ok": sync["feeds_ok"], "actor": admin})
    return {
        "model": "threat-intel-feeds/sync-v1",
        "feeds_total": sync["feeds_total"],
        "feeds_ok": sync["feeds_ok"],
        "results": sync["results"],
        **counts,
    }


@router.post("/advisories/bundle")
def build_bundle(body: AdvisoryBuildBundle, admin: str = Depends(require_admin)):
    """Issuer side: build a signed bundle for transfer to a disconnected site."""
    try:
        validated = validate_advisories(body.advisories)
        return build_advisory_bundle(validated, secret=body.secret,
                                      bundle_id=body.bundle_id)
    except AdvisoryError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/advisories")
def list_advisories(
    algorithm: str | None = Query(None),
    advisory_type: str | None = Query(None),
    severity: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    stmt = select(AlgorithmAdvisory).order_by(AlgorithmAdvisory.algorithm,
                                              AlgorithmAdvisory.advisory_id)
    if algorithm:
        stmt = stmt.where(AlgorithmAdvisory.algorithm == algorithm)
    if advisory_type:
        stmt = stmt.where(AlgorithmAdvisory.advisory_type == advisory_type.upper())
    if severity:
        stmt = stmt.where(AlgorithmAdvisory.severity == severity.upper())
    rows = list(db.execute(stmt.limit(limit)).scalars())
    return {"advisories": [_row_dict(r) for r in rows], "count": len(rows)}


@router.get("/algorithms/{algorithm}")
def algorithm_advisories(
    algorithm: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    rows = list(db.execute(
        select(AlgorithmAdvisory).where(AlgorithmAdvisory.algorithm == algorithm)
    ).scalars())
    return {
        "algorithm": algorithm,
        "advisory_count": len(rows),
        "annotations": [advisory_relevance(_row_dict(r), algorithm=algorithm)
                        for r in rows],
    }


@router.get("/assets/{asset_id}")
def asset_advisories(
    asset_id: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    asset = db.execute(
        select(CryptoAsset).where(CryptoAsset.id == asset_id)
    ).scalars().first()
    if asset is None:
        raise HTTPException(status_code=404, detail="Crypto asset not found")
    rows = list(db.execute(
        select(AlgorithmAdvisory).where(AlgorithmAdvisory.algorithm == asset.algorithm)
    ).scalars())
    return {
        "asset_id": str(asset.id),
        "algorithm": asset.algorithm,
        "advisory_count": len(rows),
        "annotations": [advisory_relevance(_row_dict(r), algorithm=asset.algorithm)
                        for r in rows],
        "note": "annotation only — the stored asset and its scores are unchanged",
    }
