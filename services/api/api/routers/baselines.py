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
