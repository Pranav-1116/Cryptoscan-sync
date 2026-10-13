"""OT/ICS passive scan and inventory."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from api.security.scan_admission import admit_scan
from api.security.target_validation import (
    TargetValidationError,
    validate_source_target,
)
from db.repositories.maturity_repository import MaturityRepository
from ot_scanner.core.scanner import OtPassiveScanner

router = APIRouter(prefix="/ot", tags=["ot"])


class OtScanRequest(BaseModel):
    path: str


@router.post("/scan")
def scan_ot(body: OtScanRequest, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Passive OT/ICS observation over a bounded path.

    Product vision §4.1 (P0): the OT collector passes the same central
    admission as queued jobs — emergency stop, queue depth, safe-scan
    policy. ``is_ot_trusted=True`` because this endpoint IS the OT
    collector (server-side knowledge; request bodies never set trust),
    and the walk is passive, so no maintenance window is required. The
    path must resolve inside the declared source roots; a refused
    target launches no scan.
    """
    if not body.path:
        raise HTTPException(status_code=400, detail="path required")
    try:
        target = validate_source_target(body.path, label="ot_scan.path")
    except TargetValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    decision = admit_scan(is_ot_trusted=True, active_probing_requested=False)
    result = OtPassiveScanner().scan_filesystem(target)
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
    if isinstance(result, dict):
        result["admission"] = decision
    return result


class OtMetricsRequest(BaseModel):
    report: dict  # an OT scan result


@router.post("/metrics")
def render_ot_metrics(body: OtMetricsRequest, user: str = Depends(get_current_user)):
    """Render an OT scan result as Prometheus text (format 0.0.4)."""
    from fastapi.responses import Response

    from ot_scanner.reports.metrics import CONTENT_TYPE, render_prometheus

    return Response(content=render_prometheus(body.report), media_type=CONTENT_TYPE)


@router.get("/devices")
def list_devices(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows = MaturityRepository(db).list_ot_devices()
    return {"devices": [row.to_dict() for row in rows], "total_count": len(rows)}


@router.get("/findings")
def list_findings(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows = MaturityRepository(db).list_ot_findings()
    return {"findings": [row.to_dict() for row in rows], "total_count": len(rows)}
