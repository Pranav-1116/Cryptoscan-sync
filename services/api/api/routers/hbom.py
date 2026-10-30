"""Independent HBOM surface — the unified hardware BOM over the persisted
estate (§4.4, round 71).

Distinct from the two pre-existing hardware surfaces, on purpose:

* ``GET /hardware/hbom`` serves the live ENGINE's document, built from
  the controller's ephemeral in-memory state;
* the TechBOM ``hbom`` layer is a projection inside another BOM.

This router serves the INDEPENDENT document: ONE HBOM over every
persisted ``hardware_assets`` row (the 24/7 engine's DB truth), with
per-asset identity, posture (firmware / TPM / HSM / capabilities) and
evidence references (agent, first/last seen, last verified,
fingerprint, the recorded evidence IDs). The document is
deterministic — anchored to the estate's latest observation, never a
wall clock — so it can be PINNED content-addressed:

* ``GET  /hbom`` — regenerate from the current estate (live view);
* ``POST /hbom/snapshot`` — pin ONE rendering (auditor), identical
  (tenant, environment, content) pins collapse idempotently;
* ``GET  /hbom/snapshots`` — the pinned list;
* ``GET  /hbom/snapshots/{id}`` — serve the EXACT stored document
  verbatim with an integrity self-check (OK / MISMATCH);
* ``GET  /hbom/snapshots/{id}/diff?against={baseline}`` — the exact
  drift between two pins (round 72): devices added/removed, field-level
  drift on survivors, computed from the two pinned payloads.

No dependency edges are invented: no collector records
hardware→system linkage today, and the document says so.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, require_auditor
from cbom.hbom import (
    SOURCE_ESTATE_OBSERVATION,
    generate_hbom,
    hbom_hash_matches,
    to_cyclonedx,
)
from cbom.hbom_diff import diff_hbom_documents
from db.models.hardware_live import HardwareAsset
from db.models.hbom_snapshot import HbomSnapshot
from db.tenancy import filtered_get

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/hbom", tags=["hbom"])


def _estate_document(db: Session) -> dict:
    """Regenerate the unified estate HBOM from persisted rows.

    Two admitted sources, deduplicated by ``asset_id``: the live hardware inventory and
    the newest stored estate observation. The document says which of them each component
    came from, so an imported device is never mistaken for an agent-fingerprinted one.
    """
    from api.estate_bom_sources import hardware_rows
    from api.routers.techbom import _environment_of

    rows = [row.state_dict() for row in db.query(HardwareAsset).order_by(HardwareAsset.asset_id).all()]
    known = {str(row.get("asset_id") or "") for row in rows}
    observed = [row for row in hardware_rows(db) if row["asset_id"] not in known]
    sources = [SOURCE_ESTATE_OBSERVATION] if observed else []
    notes = []
    if observed:
        notes.append(
            f"{len(observed)} device(s) come from the stored estate observation, not from the "
            "live agent; each carries the observation's evidence ids and is declared, not "
            "fingerprinted."
        )
    return generate_hbom(
        [*rows, *observed],
        environment=_environment_of(db),
        sources=sources,
        notes=notes,
    )


def _snapshot_out(row: HbomSnapshot) -> dict:
    out = row.to_dict()
    out["snapshot_id"] = row.id
    out["verify_path"] = f"/api/v1/hbom/snapshots/{row.id}"
    return out


@router.get("")
def get_hbom_document(
    fmt: str = Query("native", pattern="^(native|cyclonedx)$"),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """The unified estate HBOM, regenerated from current rows.

    ``fmt=cyclonedx`` renders the SAME document as a CycloneDX 1.5
    hardware BOM (deterministic: its timestamp is the document's own
    anchor). This is the live view; pin it for an immutable copy.
    """
    document = _estate_document(db)
    if fmt == "cyclonedx":
        return to_cyclonedx(document)
    return document


@router.post("/snapshot")
def pin_hbom_snapshot(
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    """Freeze ONE deterministic rendering of the estate HBOM (§4.4, R71).

    Content-addressed by SHA-256 over the canonical serialization;
    identical (tenant, environment, content) pins collapse to one row.
    Served verbatim afterwards — never regenerated.
    """
    document = _estate_document(db)
    environment = str((document.get("metadata") or {}).get("environment") or "")
    content_hash = str(document.get("content_hash") or "")
    if not hbom_hash_matches(document, content_hash):
        # cannot happen unless the generator is broken — refuse to pin
        raise HTTPException(status_code=500, detail="HBOM self-hash mismatch; refusing to pin")
    existing = (
        db.query(HbomSnapshot)
        .filter(
            HbomSnapshot.environment == environment,
            HbomSnapshot.content_hash == content_hash,
        )
        .one_or_none()
    )
    if existing is not None:
        out = _snapshot_out(existing)
        out["created"] = False
        out["note"] = (
            "An identical estate rendering is already pinned for this "
            "environment (content-addressed); the existing snapshot is returned."
        )
        return out
    row = HbomSnapshot(
        environment=environment,
        content_hash=content_hash,
        format="json",
        generator="api",
        payload=document,
        component_count=len(document.get("components") or []),
        created_by=user,
        snapshotted_at=datetime.now(timezone.utc),
        as_of=(document.get("metadata") or {}).get("as_of"),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    out = _snapshot_out(row)
    out["created"] = True
    out["note"] = (
        "Estate HBOM pinned. GET the verify_path for the exact stored "
        "document — it is served verbatim, never regenerated."
    )
    return out


@router.get("/snapshots")
def list_hbom_snapshots(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Every pinned estate HBOM for this tenant, newest first."""
    rows = (
        db.query(HbomSnapshot)
        .order_by(HbomSnapshot.created_at.desc())
        .limit(100)
        .all()
    )
    return {
        "snapshots": [_snapshot_out(r) for r in rows],
        "count": len(rows),
        "note": (
            "Each snapshot is a pinned rendering of the whole persisted "
            "hardware estate; the live route regenerates and may differ."
        ),
    }


@router.get("/snapshots/{snapshot_id}")
def get_hbom_snapshot(
    snapshot_id: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Serve the EXACT persisted estate HBOM — verbatim, never
    regenerated — with an integrity self-check (recomputed hash over the
    stored payload must equal the pinned content_hash)."""
    row = filtered_get(db, HbomSnapshot, snapshot_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    payload = row.payload or {}
    pinned_hash = row.content_hash or ""
    embedded_hash = str(payload.get("content_hash") or "")
    integrity_ok = embedded_hash == pinned_hash and hbom_hash_matches(payload, pinned_hash)
    out = _snapshot_out(row)
    out["integrity"] = "OK" if integrity_ok else "MISMATCH"
    out["integrity_note"] = (
        "SHA-256 over the stored payload matches the pinned content hash."
        if integrity_ok else
        "Stored payload does NOT match its pinned content hash — the "
        "document was mutated after pinning. Do not trust it."
    )
    out["payload"] = payload
    return out


@router.get("/snapshots/{snapshot_id}/diff")
def diff_hbom_snapshot(
    snapshot_id: str,
    against: str = Query(..., description="snapshot_id of the baseline to diff against"),
    key_by: str = Query("asset_id", pattern="^(asset_id|bom_ref)$",
                        description="asset_id: device-keyed estate drift (observation "
                                    "churn excluded); bom_ref: exact comparison of "
                                    "everything the documents carry"),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Compare two pinned estate HBOMs (§4.4, round 72).

    ``GET /snapshots/{id}/diff?against={baseline}`` answers the
    operator's question after the estate changed: which devices were
    added, which are gone, and what drifted on the survivors (firmware,
    TPM/HSM posture, capabilities, risk, identity fingerprints). The
    diff is computed from the two content-addressed payloads on every
    call, never stored; its trustworthiness is the pins'.
    """
    target = filtered_get(db, HbomSnapshot, snapshot_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    baseline = filtered_get(db, HbomSnapshot, against)
    if baseline is None:
        raise HTTPException(status_code=404, detail="Baseline snapshot not found")
    try:
        result = diff_hbom_documents(baseline.payload, target.payload, key_by=key_by)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {
        "target": {
            "snapshot_id": target.id,
            "environment": target.environment,
            "content_hash": target.content_hash,
            "component_count": target.component_count,
            "as_of": target.as_of,
            "snapshotted_at": target.snapshotted_at.isoformat() if target.snapshotted_at else None,
            "verify_path": f"/api/v1/hbom/snapshots/{target.id}",
        },
        "baseline": {
            "snapshot_id": baseline.id,
            "environment": baseline.environment,
            "content_hash": baseline.content_hash,
            "component_count": baseline.component_count,
            "as_of": baseline.as_of,
            "snapshotted_at": baseline.snapshotted_at.isoformat() if baseline.snapshotted_at else None,
            "verify_path": f"/api/v1/hbom/snapshots/{baseline.id}",
        },
        "diff": result,
        "note": (
            "Computed from the two pinned payloads (never stored). "
            "'added' = present in the target snapshot only."
        ),
    }
