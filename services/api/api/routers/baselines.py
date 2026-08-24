"""Baseline approval."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.dependencies import get_baseline_repository, get_current_user, get_scan_repository
from db.repositories.baseline_repository import BaselineRepository
from db.repositories.scan_repository import ScanRepository

router = APIRouter(prefix="/baselines", tags=["baselines"])


class ApproveBody(BaseModel):
    scan_id: str
    notes: str | None = None
    environment: str = "default"


@router.post("/approve")
def approve(
    body: ApproveBody,
    user: str = Depends(get_current_user),
    baselines: BaselineRepository = Depends(get_baseline_repository),
    scans: ScanRepository = Depends(get_scan_repository),
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
