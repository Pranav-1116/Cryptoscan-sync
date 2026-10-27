"""Evidence disposition endpoints (§4.2 P0, round 40).

Controlled inventory and audited disposition for historical evidence
rows whose stored ``finding_data`` still contains fields the safe
response projection strips (raw snippets, raw transformations,
detector extras). The rules this surface enforces:

- The inventory reports counts and field NAMES — never the sensitive
  content itself.
- A disposition decision is append-only and audited. It never rewrites
  ``finding_data``, chain links, manifests or signatures: the stored
  hashes commit to the original payload.
- QUARANTINE_EXPORTS and MARK_REDACTED refuse scan exports until a
  re-issued chain exists; RETAIN records a reviewed decision to keep
  the rows as they are.
- Physical purge at rest (and backup rotation) stays an operator/DBA
  action outside the API; every response says so explicitly.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.dependencies import get_db_session, require_admin, require_auditor
from api.security.evidence_projection import project_finding
from db.models.evidence_disposition import DECISIONS, EvidenceDisposition
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan
from db.repositories.user_repository import UserRepository

router = APIRouter(prefix="/evidence/disposition", tags=["evidence-disposition"])
logger = logging.getLogger(__name__)

#: Bounded work per inventory request: records inspected, newest-first by
#: scan. A bigger estate pages through; the response says when it did.
_INVENTORY_PAGE = 2000

_EXPORT_REFUSING_DECISIONS = ("QUARANTINE_EXPORTS", "MARK_REDACTED")


def _triggering_fields(stored: dict, projected: dict) -> list[str]:
    """Field NAMES the safe projection dropped or rewrote (no content).

    Compares top-level keys and the known nested scopes; a value that the
    projection dropped or changed contributes its dotted field name.
    """
    names: set[str] = set()
    for key in set(stored) | set(projected):
        if stored.get(key) != projected.get(key):
            names.add(str(key))
    for scope in ("source", "crypto", "git_context", "inventory", "metadata"):
        s = stored.get(scope)
        p = projected.get(scope)
        if isinstance(s, dict) and isinstance(p, dict):
            for key in set(s) | set(p):
                if s.get(key) != p.get(key):
                    names.add(f"{scope}.{key}")
    return sorted(names)


def active_disposition(db: Session, scan_id: str) -> EvidenceDisposition | None:
    """Newest disposition row for a scan (append-only trail, latest wins)."""
    rows = db.execute(
        select(EvidenceDisposition)
        .where(EvidenceDisposition.scan_id == scan_id)
        .order_by(EvidenceDisposition.decided_at.desc(), EvidenceDisposition.created_at.desc())
        .limit(1)
    ).scalars().all()
    return rows[0] if rows else None


def export_refused_reason(db: Session, scan_id: str) -> str | None:
    """Honest export gate: refuse while an active decision requires it."""
    row = active_disposition(db, scan_id)
    if row is not None and row.decision in _EXPORT_REFUSING_DECISIONS:
        return (f"scan exports are quarantined by an operator disposition "
                f"({row.decision} by {row.decided_by} at "
                f"{row.decided_at.isoformat() if row.decided_at else 'unknown time'}); "
                f"re-issue a new chain before exporting")
    return None


class DispositionRequest(BaseModel):
    scan_id: str = Field(min_length=1)
    decision: str
    notes: str = Field(min_length=1)
    affected_records: int = Field(default=0, ge=0)


class DispositionResponse(BaseModel):
    id: str
    scan_id: str
    decision: str
    decided_by: str
    decided_at: str | None = None
    notes: str | None = None
    affected_records: int = 0


@router.get("/inventory")
def disposition_inventory(
    limit: int = Query(_INVENTORY_PAGE, ge=1, le=20000),
    offset: int = Query(0, ge=0),
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    """Inventory scans whose stored evidence needs the safe projection.

    A row counts as affected when the stored ``finding_data`` differs from
    its safe projection — the same deterministic comparison the read path
    applies. Counts and field names only; the sensitive content never
    leaves the database through this endpoint.
    """
    total_records = int(db.execute(select(func.count(EvidenceRecord.id))).scalar() or 0)
    rows = db.execute(
        select(EvidenceRecord)
        .order_by(EvidenceRecord.scan_id, EvidenceRecord.chain_position)
        .offset(offset)
        .limit(limit)
    ).scalars().all()

    per_scan: dict[str, dict] = {}
    for row in rows:
        entry = per_scan.setdefault(
            row.scan_id, {"affected": 0, "total": 0, "fields": set()})
        entry["total"] += 1
        try:
            projected, differs = project_finding(row.finding_data)
        except Exception:
            # An unprojectable row is affected and says so without content.
            entry["affected"] += 1
            entry["fields"].add("unprojectable_finding_data")
            continue
        if differs:
            entry["affected"] += 1
            entry["fields"].update(
                _triggering_fields(row.finding_data or {}, projected))

    scans_out = []
    for scan_id in sorted(per_scan):
        info = per_scan[scan_id]
        if info["affected"] == 0:
            continue  # clean scans are not disposition candidates
        disp = active_disposition(db, scan_id)
        scans_out.append({
            "scan_id": scan_id,
            "records_inspected": info["total"],
            "affected_records": info["affected"],
            "triggering_fields": sorted(info["fields"]),
            "disposition": disp.decision if disp else "NONE",
            "decided_by": disp.decided_by if disp else None,
            "decided_at": disp.decided_at.isoformat() if disp and disp.decided_at else None,
        })

    return {
        "model": "evidence-disposition/inventory-v1",
        "records_inspected": len(rows),
        "records_total": total_records,
        "offset": offset,
        "limit": limit,
        "truncated": offset + len(rows) < total_records,
        "affected_scans": scans_out,
        "affected_scan_count": len(scans_out),
        "notes": [
            "Affected means the stored finding_data differs from its safe "
            "projection; response views already hide the difference.",
            "This inventory reports counts and field names only — it never "
            "returns the sensitive content.",
            "Stored hashes commit to the original payload: a disposition "
            "never rewrites finding_data, chain links, manifests or "
            "signatures.",
            "Physical purge at rest and backup rotation are operator/DBA "
            "actions outside this API; record the decision here first.",
        ],
    }


@router.post("", response_model=DispositionResponse)
def record_disposition(
    body: DispositionRequest,
    user: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Record an operator disposition decision for one scan (audited)."""
    if body.decision not in DECISIONS:
        raise HTTPException(status_code=422, detail=f"decision must be one of {list(DECISIONS)}")
    scan = db.execute(select(Scan).where(Scan.id == body.scan_id)).scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    row = EvidenceDisposition(
        scan_id=body.scan_id,
        decision=body.decision,
        decided_by=user,
        decided_at=datetime.now(timezone.utc),
        notes=body.notes,
        triggering_fields=None,
        affected_records=body.affected_records,
    )
    db.add(row)
    db.flush()
    try:
        UserRepository(db).audit(
            user, "evidence.disposition",
            target_type="scan", target_id=body.scan_id,
            detail={"decision": body.decision, "notes": body.notes,
                    "affected_records": body.affected_records},
        )
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("disposition_audit_failed", extra={"scan_id": body.scan_id})
        raise HTTPException(status_code=503, detail="disposition audit failed; decision not recorded")
    db.refresh(row)
    return DispositionResponse(
        id=row.id, scan_id=row.scan_id, decision=row.decision,
        decided_by=row.decided_by,
        decided_at=row.decided_at.isoformat() if row.decided_at else None,
        notes=row.notes, affected_records=row.affected_records,
    )


@router.get("/{scan_id}", response_model=list[DispositionResponse])
def scan_dispositions(
    scan_id: str,
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    """The full append-only disposition trail for one scan, oldest first."""
    rows = db.execute(
        select(EvidenceDisposition)
        .where(EvidenceDisposition.scan_id == scan_id)
        .order_by(EvidenceDisposition.decided_at, EvidenceDisposition.created_at)
    ).scalars().all()
    return [
        DispositionResponse(
            id=r.id, scan_id=r.scan_id, decision=r.decision,
            decided_by=r.decided_by,
            decided_at=r.decided_at.isoformat() if r.decided_at else None,
            notes=r.notes, affected_records=r.affected_records,
        )
        for r in rows
    ]
