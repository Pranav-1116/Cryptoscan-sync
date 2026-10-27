"""Cloud-scan job listing and trigger aliases."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.dependencies import TenantContext, get_current_user, get_db_session, get_tenant_context
from api.security.scan_admission import admit_scan
from api.security.scan_runs import DurableScanRun, coverage_from_result
from api.security.target_validation import (
    TargetValidationError,
    validate_source_target,
)
from cloud_scanner.core.scanner import CloudScanner
from db.repositories.intelligence_repository import IntelligenceRepository

router = APIRouter(prefix="/cloud-scans", tags=["cloud-scans"])


class CloudScanRequest(BaseModel):
    path: str
    live: bool = False


@router.post("")
@router.post("/")
def trigger_cloud_scan(
    body: CloudScanRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db_session),
):
    """Synchronous IaC-tree / live cloud scan with a durable run record.

    Product vision §4.1 (P0): direct scanner routes share the SAME
    admission and target containment as queued jobs — emergency stop,
    queue depth, safe-scan policy, active-probing authorization for live
    provider reads (a live cloud scan touches real accounts; it is an
    active collector, not a passive file walk), and the path must
    resolve inside the declared source roots. A refused target must
    launch no scan.

    §4.8/§5 (round 44): the run leaves a tenant-bound ScanJob row
    (status, admission decision, bounded coverage) readable at
    ``GET /jobs/{id}`` — a shared latest-cycle listing is no longer the
    only trace this scan ever existed.
    """
    if not body.path:
        raise HTTPException(status_code=400, detail="path required")
    try:
        target = validate_source_target(body.path, label="cloud_scan.path")
    except TargetValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    decision = admit_scan(active_probing_requested=body.live)
    with DurableScanRun(db, job_type="CLOUD_SCAN", target=body.path,
                        user=ctx.username, admission=decision,
                        tenant_id=ctx.tenant_id,
                        metadata={"live": body.live}) as run:
        result = CloudScanner(live=body.live).scan_filesystem(target)
        run.succeed(coverage=coverage_from_result(result))
    if isinstance(result, dict):
        result = dict(result)
        result["admission"] = decision
        result["job_id"] = run.job_id
    return result


@router.get("")
@router.get("/")
def list_cloud_scans(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows = IntelligenceRepository(db).list_cloud_accounts()
    return {"accounts": [row.to_dict() for row in rows], "total_count": len(rows)}
