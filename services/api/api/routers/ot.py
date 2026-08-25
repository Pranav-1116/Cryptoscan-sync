"""OT/ICS passive scan and inventory."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from db.repositories.maturity_repository import MaturityRepository
from ot_scanner.core.scanner import OtPassiveScanner

router = APIRouter(prefix="/ot", tags=["ot"])


class OtScanRequest(BaseModel):
    path: str


@router.post("/scan")
def scan_ot(body: OtScanRequest, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    if not body.path:
        raise HTTPException(status_code=400, detail="path required")
    result = OtPassiveScanner().scan_filesystem(body.path)
    try:
        repo = MaturityRepository(db)
        id_by_ip = {}
        for device in result.get("devices") or []:
            row = repo.upsert_ot_device(device)
            id_by_ip[device.get("ip_address")] = row.id
        for finding in result.get("findings") or []:
            ip = (finding.get("device") or {}).get("ip_address")
            repo.add_ot_finding(id_by_ip.get(ip), finding)
    except Exception:
        result = dict(result)
        result["persisted"] = False
    return result


@router.get("/devices")
def list_devices(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows = MaturityRepository(db).list_ot_devices()
    return {"devices": [row.to_dict() for row in rows], "total_count": len(rows)}


@router.get("/findings")
def list_findings(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows = MaturityRepository(db).list_ot_findings()
    return {"findings": [row.to_dict() for row in rows], "total_count": len(rows)}
