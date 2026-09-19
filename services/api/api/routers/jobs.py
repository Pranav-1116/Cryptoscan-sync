"""Job status, listing, and logs."""

from __future__ import annotations

import inspect

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query

from api.dependencies import get_current_user, get_job_repository
from api.schemas.job_schemas import JobLogsResponse, JobStatusResponse
from db.repositories.job_repository import JobRepository

router = APIRouter(prefix="/jobs", tags=["jobs"])


def _to_status(job, job_id: str | None = None) -> JobStatusResponse:
    job_pk = getattr(job, "job_id", None) or getattr(job, "id", job_id)
    created_at = getattr(job, "created_at", None)
    started_at = getattr(job, "started_at", None)
    completed_at = getattr(job, "completed_at", None)
    progress = getattr(job, "progress", None)
    if not isinstance(progress, dict):
        progress = getattr(job, "metadata", None)
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
        progress=progress if isinstance(progress, dict) else None,
    )


@router.get("")
def list_jobs(
    limit: int = Query(20, ge=1, le=100),
    user: str = Depends(get_current_user),
    repo: JobRepository = Depends(get_job_repository),
):
    rows = repo.list_recent(limit)
    return {"jobs": [_to_status(row).model_dump() for row in rows], "total_count": len(rows)}


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
    return _to_status(job, job_id)


@router.post("/{job_id}/retry")
async def retry_job(
    job_id: str,
    background_tasks=None,
    user: str = Depends(get_current_user),
    repo: JobRepository = Depends(get_job_repository),
):

    job = repo.get_by_id(job_id)
    if inspect.isawaitable(job):
        job = await job
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    from api.routers.trigger import enqueue_scan_job

    # FastAPI injects BackgroundTasks when annotated; keep a local fallback for tests.
    tasks = background_tasks if isinstance(background_tasks, BackgroundTasks) else BackgroundTasks()
    return enqueue_scan_job(
        repo,
        tasks,
        repo_url=getattr(job, "target_repo", None) or "",
        branch=getattr(job, "target_branch", None) or "main",
        commit=getattr(job, "target_commit", None),
        triggered_by=user,
        job_type="RETRY",
    )


@router.get("/{job_id}/logs", response_model=JobLogsResponse)
async def get_job_logs(
    job_id: str,
    user: str = Depends(get_current_user),
    repo: JobRepository = Depends(get_job_repository),
):
    job = repo.get_by_id(job_id)
    if inspect.isawaitable(job):
        job = await job
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    progress = getattr(job, "progress", None) or {}
    logs = progress.get("logs") if isinstance(progress, dict) else []
    return JobLogsResponse(
        job_id=str(getattr(job, "job_id", None) or getattr(job, "id", job_id)),
        status=job.status,
        logs=list(logs or []),
        progress=progress if isinstance(progress, dict) else None,
    )
