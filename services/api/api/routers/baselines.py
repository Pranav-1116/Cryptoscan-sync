"""Baseline approval."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.dependencies import (
    get_baseline_repository,
    get_current_user,
    get_db_session,
    require_auditor,
    get_scan_repository,
)
from db.repositories.baseline_repository import BaselineRepository
from db.repositories.scan_repository import ScanRepository

router = APIRouter(prefix="/baselines", tags=["baselines"])
logger = logging.getLogger(__name__)


class ApproveBody(BaseModel):
    scan_id: str
    notes: str | None = None
    environment: str = "default"


@router.post("/approve")
def approve(
    body: ApproveBody,
    user: str = Depends(require_auditor),
    baselines: BaselineRepository = Depends(get_baseline_repository),
    scans: ScanRepository = Depends(get_scan_repository),
    db=Depends(get_db_session),
):
    scan = scans.get_by_id(body.scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != "COMPLETED":
        raise HTTPException(status_code=409, detail="Only completed scans can be baselines")
    baseline = baselines.approve(
        system_identifier=scan.target_location,
        scan_id=scan.id,
        approved_by=user,
        notes=body.notes,
        environment=body.environment,
    )
    try:
        from db.repositories.user_repository import UserRepository

        UserRepository(db).audit(
            user,
            "baseline.approve",
            target_type="scan",
            target_id=str(scan.id),
            detail={"system_identifier": scan.target_location, "environment": body.environment},
        )
        db.commit()
    except Exception as audit_exc:
        # A baseline without an audit record is not an acceptable approval.
        db.rollback()
        logger.exception(
            "baseline_approval_audit_failed",
            extra={"error_type": type(audit_exc).__name__, "scan_id": str(scan.id)},
        )
        raise HTTPException(status_code=503, detail="Baseline approval audit is unavailable") from audit_exc
    return {
        "baseline_id": baseline.id,
        "system_identifier": baseline.system_identifier,
        "approved_scan_id": baseline.approved_scan_id,
        "approved_by": baseline.approved_by,
        "status": baseline.status,
    }


@router.get("")
def list_baselines(
    user: str = Depends(get_current_user),
    baselines: BaselineRepository = Depends(get_baseline_repository),
):
    rows = baselines.get_all(limit=100)
    return [
        {
            "baseline_id": b.id,
            "system_identifier": b.system_identifier,
            "approved_scan_id": b.approved_scan_id,
            "approved_by": b.approved_by,
            "status": b.status,
        }
        for b in rows
    ]


# --------------------------------------------------------------------------- #
# Clean-scan baseline proposals (report 31 §2.9, 88 GAP-011, round 23): the
# worker proposes a baseline when a system's first scan comes back clean
# (no FAIL policy evidence, no CRITICAL/HIGH drift). A proposal is NEVER
# active — activating it is an auditor decision below.
# --------------------------------------------------------------------------- #


def _proposal_out(b) -> dict:
    return {
        "baseline_id": b.id,
        "system_identifier": b.system_identifier,
        "environment": b.environment,
        "approved_scan_id": b.approved_scan_id,
        "proposed_by": b.approved_by,
        "proposed_at": b.approved_at.isoformat() if b.approved_at else None,
        "status": b.status,
        "notes": b.notes,
    }


@router.get("/proposed")
def list_proposed_baselines(
    system_identifier: str | None = None,
    user: str = Depends(require_auditor),
    baselines: BaselineRepository = Depends(get_baseline_repository),
):
    """Clean-scan proposals awaiting an auditor decision."""
    return [
        _proposal_out(b)
        for b in baselines.list_proposed(system_identifier)
    ]


class ApproveProposedBody(BaseModel):
    notes: str | None = None


@router.post("/{baseline_id}/approve-proposed")
def approve_proposed_baseline(
    baseline_id: str,
    body: ApproveProposedBody | None = None,
    user: str = Depends(require_auditor),
    baselines: BaselineRepository = Depends(get_baseline_repository),
    db=Depends(get_db_session),
):
    """Activate a proposed baseline (auditor approval). The previously active
    baseline for the same system is superseded; the decision is audited."""
    row = baselines.approve_proposed(
        baseline_id, user, notes=(body.notes if body else None)
    )
    if row is None:
        raise HTTPException(
            status_code=404, detail="No such PROPOSED baseline"
        )
    try:
        from db.repositories.user_repository import UserRepository

        UserRepository(db).audit(
            user,
            "baseline.approve_proposed",
            target_type="baseline",
            target_id=str(baseline_id),
            detail={"system_identifier": row.system_identifier,
                    "scan_id": row.approved_scan_id},
        )
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=503, detail="Audit is unavailable")
    return {
        "baseline_id": row.id,
        "system_identifier": row.system_identifier,
        "status": row.status,
        "approved_by": row.approved_by,
    }


@router.delete("/{baseline_id}/proposal")
def dismiss_proposed_baseline(
    baseline_id: str,
    user: str = Depends(require_auditor),
    baselines: BaselineRepository = Depends(get_baseline_repository),
    db=Depends(get_db_session),
):
    """Dismiss a proposal the auditor rejects (audited — it is a decision
    about the trust anchor, same as approving it)."""
    # `get` does not exist on the repository — this line raised AttributeError,
    # so the endpoint answered 500 on every call, including for a real id. The
    # proposal could be listed and approved but never dismissed.
    row = baselines.get_by_id(baseline_id)
    if row is None or row.status != "PROPOSED":
        raise HTTPException(status_code=404, detail="No such PROPOSED baseline")
    row.status = "REJECTED"
    row.notes = (row.notes or "") + " | dismissed by auditor"
    try:
        from db.repositories.user_repository import UserRepository

        UserRepository(db).audit(
            user,
            "baseline.reject_proposed",
            target_type="baseline",
            target_id=str(baseline_id),
            detail={"system_identifier": row.system_identifier},
        )
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=503, detail="Audit is unavailable")
    return {"baseline_id": baseline_id, "status": "REJECTED"}
