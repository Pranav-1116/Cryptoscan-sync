"""Job status."""

from __future__ import annotations

import inspect

from fastapi import APIRouter, Depends, HTTPException

from api.dependencies import get_current_user, get_job_repository
from api.schemas.job_schemas import JobStatusResponse
from db.repositories.job_repository import JobRepository

router = APIRouter(prefix="/jobs", tags=["jobs"])


@router.get("/{job_id}", response_model=JobStatusResponse)
async def get_job(
    job_id: str,
    user: str = Depends(get_current_user),
    repo: JobRepository = Depends(get_job_repository),
):
    job = repo.get_by_id(job_id)
    if inspect.isawaitable(job):
        job = await job
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    job_pk = getattr(job, "job_id", None) or getattr(job, "id", job_id)
    created_at = getattr(job, "created_at", None)
    started_at = getattr(job, "started_at", None)
    completed_at = getattr(job, "completed_at", None)
    progress = getattr(job, "progress", None) or getattr(job, "metadata", None)
    return JobStatusResponse(
        job_id=str(job_pk),
        status=job.status,
        job_type=getattr(job, "job_type", None),
        target_repo=getattr(job, "target_repo", None),
        target_branch=getattr(job, "target_branch", None),
        target_commit=getattr(job, "target_commit", None),
        scan_id=getattr(job, "scan_id", None),
        error_message=getattr(job, "error_message", None),
        created_at=created_at.isoformat() if hasattr(created_at, "isoformat") else created_at,
        started_at=started_at.isoformat() if hasattr(started_at, "isoformat") else started_at,
        completed_at=completed_at.isoformat() if hasattr(completed_at, "isoformat") else completed_at,
        progress=progress,
    )
