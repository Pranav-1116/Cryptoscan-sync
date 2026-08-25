"""Cloud-scan job listing and trigger aliases."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from cloud_scanner.core.scanner import CloudScanner
from db.repositories.intelligence_repository import IntelligenceRepository

router = APIRouter(prefix="/cloud-scans", tags=["cloud-scans"])


class CloudScanRequest(BaseModel):
    path: str
    live: bool = False


@router.post("")
@router.post("/")
def trigger_cloud_scan(body: CloudScanRequest, user: str = Depends(get_current_user)):
    if not body.path:
        raise HTTPException(status_code=400, detail="path required")
    return CloudScanner(live=body.live).scan_filesystem(body.path)


@router.get("")
@router.get("/")
def list_cloud_scans(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows = IntelligenceRepository(db).list_cloud_accounts()
    return {"accounts": [row.to_dict() for row in rows], "total_count": len(rows)}
