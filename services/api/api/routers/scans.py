"""Scan list and detail."""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query

from api.dependencies import (
    get_current_user,
    get_job_repository,
    get_scan_repository,
    require_auditor,
)
from api.schemas.job_schemas import TriggerScanResponse
from api.schemas.scan_schemas import ScanListResponse, ScanResponse
from db.repositories.job_repository import JobRepository
from db.repositories.scan_repository import ScanRepository

router = APIRouter(prefix="/scans", tags=["scans"])


def _to_response(scan) -> ScanResponse:
    return ScanResponse(
        scan_id=scan.id,
        status=scan.status,
        target_location=scan.target_location,
        target_type=scan.target_type,
        target_branch=scan.target_branch,
        target_commit=scan.target_commit,
        scanner_id=scan.scanner_id,
        scanner_version=scan.scanner_version,
        operator=scan.operator,
        scan_start=scan.scan_start.isoformat() if scan.scan_start else None,
        scan_end=scan.scan_end.isoformat() if scan.scan_end else None,
        duration_seconds=scan.duration_seconds,
        statistics=scan.statistics,
        manifest_hash=scan.manifest_hash,
        error_message=scan.error_message,
    )


@router.get("", response_model=ScanListResponse)
def list_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    status: str | None = None,
    user: str = Depends(get_current_user),
    repo: ScanRepository = Depends(get_scan_repository),
):
    scans, total = repo.list_scans(status=status, page=page, page_size=page_size)
    return ScanListResponse(
        scans=[_to_response(s) for s in scans],
        total_count=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: str,
    user: str = Depends(get_current_user),
    repo: ScanRepository = Depends(get_scan_repository),
):
    scan = repo.get_by_id(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _to_response(scan)


@router.post("/{scan_id}/retry", response_model=TriggerScanResponse)
def retry_scan(
    scan_id: str,
    background_tasks: BackgroundTasks,
    user: str = Depends(require_auditor),
    scans: ScanRepository = Depends(get_scan_repository),
    jobs: JobRepository = Depends(get_job_repository),
):
    scan = scans.get_by_id(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    from api.routers.trigger import enqueue_scan_job

    return enqueue_scan_job(
        jobs,
        background_tasks,
        repo_url=scan.target_location,
        branch=scan.target_branch or "main",
        commit=scan.target_commit,
        triggered_by=user,
        job_type="RETRY",
    )
