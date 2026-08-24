"""
Scan jobs router.
Provides endpoints for querying job status and logs.
"""
from __future__ import annotations

import logging
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.dependencies import get_current_user, get_job_repository
from api.schemas.job_schemas import (
    JobListResponse,
    JobLogsResponse,
    JobStatusResponse,
    JobProgressDetail,
)
from db.models.scan_job import JobStatus
from db.repositories.job_repository import JobRepository

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/jobs", tags=["jobs"])

# Ordered pipeline stage names for progress reporting
PIPELINE_STAGES = [
    "clone",
    "scan",
    "evidence",
    "load",
    "normalize",
    "policy",
    "drift",
    "alert",
]


def _build_progress(job) -> Optional[JobProgressDetail]:
    """Build progress detail from job metadata JSONB field."""
    if job.status not in (JobStatus.RUNNING.value, "RUNNING"):
        return None

    meta = job.metadata or {}
    current_stage = meta.get("current_stage", "initializing")
    stages_complete = meta.get("stages_complete", 0)
    findings_count = meta.get("findings_count")

    return JobProgressDetail(
        current_stage=current_stage,
        stages_complete=stages_complete,
        findings_count=findings_count,
    )


def _job_to_response(job) -> JobStatusResponse:
    return JobStatusResponse(
        job_id=str(job.job_id),
        status=job.status,
        job_type=job.job_type,
        target_repo=job.target_repo,
        target_branch=job.target_branch,
        target_commit=job.target_commit,
        triggered_by=job.triggered_by,
        created_at=job.created_at.isoformat() if job.created_at else None,
        started_at=job.started_at.isoformat() if job.started_at else None,
        completed_at=job.completed_at.isoformat() if job.completed_at else None,
        scan_id=str(job.scan_id) if job.scan_id else None,
        error_message=job.error_message,
        progress=_build_progress(job),
    )


@router.get(
    "",
    response_model=JobListResponse,
    summary="List scan jobs",
)
async def list_jobs(
    current_user: Annotated[str, Depends(get_current_user)],
    job_repo: JobRepository = Depends(get_job_repository),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    status_filter: Optional[str] = Query(default=None, alias="status"),
) -> JobListResponse:
    """List scan jobs with optional status filtering."""
    offset = (page - 1) * page_size
    jobs, total = await job_repo.list_jobs(
        offset=offset,
        limit=page_size,
        status_filter=status_filter,
    )

    return JobListResponse(
        items=[_job_to_response(j) for j in jobs],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/{job_id}",
    response_model=JobStatusResponse,
    summary="Get job status",
)
async def get_job_status(
    job_id: str,
    current_user: Annotated[str, Depends(get_current_user)],
    job_repo: JobRepository = Depends(get_job_repository),
) -> JobStatusResponse:
    """
    Get the current status of a scan job.
    Poll this endpoint every 5 seconds during active scans.
    """
    job = await job_repo.get_by_id(job_id)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job {job_id} not found",
        )

    return _job_to_response(job)


@router.get(
    "/{job_id}/logs",
    response_model=JobLogsResponse,
    summary="Get job execution logs",
)
async def get_job_logs(
    job_id: str,
    current_user: Annotated[str, Depends(get_current_user)],
    job_repo: JobRepository = Depends(get_job_repository),
    tail: int = Query(default=100, ge=1, le=1000, description="Number of log lines to return"),
) -> JobLogsResponse:
    """
    Retrieve structured log lines for a scan job.
    Logs are stored in job.metadata['logs'] by the worker.
    """
    job = await job_repo.get_by_id(job_id)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job {job_id} not found",
        )

    meta = job.metadata or {}
    all_logs: list[str] = meta.get("logs", [])
    return JobLogsResponse(
        job_id=job_id,
        logs=all_logs[-tail:],
    )