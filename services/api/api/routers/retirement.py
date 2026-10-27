"""Retired-asset registry + reintroduction detection (audit 69 / GAP-023).

Weak crypto that was deliberately retired is registered here, and every scan
can be checked against the registry. A retired algorithm reappearing is a
reintroduction — detected with a routed severity (Critical pages, High
alerts, Medium logs), never silently rediscovered as a "new" finding.

Advisory + alerting only: compliance verdicts still come solely from the
policy engine, and detection never rewrites evidence.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, require_auditor
from api.events.platform_events import emit_platform_event
from db.models.retired_asset import RetiredAsset
from db.models.scan import Scan
from db.tenancy import filtered_get

router = APIRouter(prefix="/retirements", tags=["retirement"])


class RetirementRequest(BaseModel):
    algorithm: str = Field(..., min_length=1)
    scope: str = Field("FILE", pattern="^(FILE|ASSET|ALGORITHM)$")
    file_path: str | None = None
    asset_id: str | None = None
    reason: str | None = None
    source_task_id: str | None = None


class LiftRequest(BaseModel):
    reason: str = Field(..., min_length=1)


def _out(row: RetiredAsset) -> dict:
    out = row.to_dict()
    if isinstance(out.get("retired_at"), datetime):
        out["retired_at"] = out["retired_at"].isoformat()
    return out


def _validate_scope(body: RetirementRequest) -> None:
    if body.scope == "FILE" and not body.file_path:
        raise HTTPException(status_code=400, detail="FILE-scope retirements need file_path")
    if body.scope == "ASSET" and not body.asset_id:
        raise HTTPException(status_code=400, detail="ASSET-scope retirements need asset_id")


@router.post("")
def register_retirement(
    body: RetirementRequest,
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    """Register a deliberate retirement (auditor judgment, with a reason)."""
    _validate_scope(body)
    row = RetiredAsset(
        algorithm=body.algorithm.upper().replace("_", "-"),
        scope=body.scope,
        file_path=body.file_path,
        asset_id=body.asset_id,
        reason=body.reason,
        source_task_id=body.source_task_id,
        retired_by=user,
        retired_at=datetime.now(timezone.utc),
        active=True,
    )
    db.add(row)
    db.commit()
    emit_platform_event(
        "retirement.registered",
        f"{row.algorithm} retired ({row.scope} scope) by {user}",
        {"retirement_id": row.id, "algorithm": row.algorithm, "scope": row.scope,
         "file_path": row.file_path, "asset_id": row.asset_id,
         "source_task_id": row.source_task_id},
        target_name="retirement",
    )
    return _out(row)


@router.get("")
def list_retirements(
    active: bool | None = None,
    algorithm: str | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    stmt = select(RetiredAsset)
    if active is not None:
        stmt = stmt.where(RetiredAsset.active == active)
    if algorithm:
        stmt = stmt.where(RetiredAsset.algorithm == algorithm.upper().replace("_", "-"))
    rows = db.execute(stmt.order_by(RetiredAsset.retired_at.desc())).scalars().all()
    return {"retirements": [_out(r) for r in rows], "count": len(rows)}


@router.post("/{retirement_id}/lift")
def lift_retirement(
    retirement_id: str,
    body: LiftRequest,
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    """Deactivate a retirement (e.g. an approved exception) — kept for the trail."""
    row = filtered_get(db, RetiredAsset, retirement_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Retirement not found")
    if not row.active:
        raise HTTPException(status_code=409, detail="Retirement already lifted")
    row.active = False
    row.lifted_reason = body.reason
    db.commit()
    emit_platform_event(
        "retirement.lifted",
        f"Retirement of {row.algorithm} lifted by {user}: {body.reason}",
        {"retirement_id": row.id, "algorithm": row.algorithm, "reason": body.reason},
        target_name="retirement",
    )
    return _out(row)


def _finding_view(row) -> dict:
    return {
        "algorithm": row.algorithm,
        "file_path": row.file_path,
        "line_number": row.line_number,
        "compliance_status": row.compliance_status,
        "is_hardcoded_key": bool(row.is_hardcoded_key),
    }


@router.post("/check/{scan_id}")
def check_scan(
    scan_id: str,
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    """Check one scan against the active retirement registry.

    Emits one severity-routed platform event per detection. Sites observed
    after the retirement was registered are the alarming ones; earlier
    evidence predates the promise.
    """
    from db.models.crypto_asset_evidence import CryptoAssetEvidence
    from db.repositories.evidence_repository import EvidenceRepository
    from remediation.reintroduction import detect_reintroductions

    scan = filtered_get(db, Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    retirements = [
        {**_out(r), "retired_at": r.retired_at}
        for r in db.execute(
            select(RetiredAsset).where(RetiredAsset.active == True)  # noqa: E712
        ).scalars().all()
    ]

    evidence_rows = EvidenceRepository(db).get_all_for_scan(scan_id, include_deleted=False)
    # asset linkage for ASSET-scope retirements
    asset_links: dict[str, set[str]] = {}
    if any(r["scope"] == "ASSET" for r in retirements):
        for link in db.execute(select(CryptoAssetEvidence)).scalars().all():
            asset_links.setdefault(link.evidence_id, set()).add(link.asset_id)

    findings = [
        {**_finding_view(row), "asset_ids": sorted(asset_links.get(row.id, ()))}
        for row in evidence_rows
    ]

    detections = detect_reintroductions(retirements, findings)

    for detection in detections:
        emit_platform_event(
            "retirement.reintroduced",
            f"REINTRODUCTION: {detection['algorithm']} retired "
            f"{detection.get('retired_at')} is back in scan {scan_id} "
            f"({len(detection['matched_sites'])} site(s))",
            {"scan_id": scan_id, **detection},
            target_name="retirement",
        )

    return {
        "scan_id": scan_id,
        "retirements_checked": len(retirements),
        "evidence_checked": len(findings),
        "reintroductions": detections,
        "severity_counts": {
            level: sum(1 for d in detections if d["severity"] == level)
            for level in ("CRITICAL", "HIGH", "MEDIUM")
        },
    }
