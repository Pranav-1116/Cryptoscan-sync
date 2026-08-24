"""
Manual scan trigger router.
Allows authenticated users to trigger on-demand scans.
"""
from __future__ import annotations

import json
import logging
from typing import Annotated

import redis.asyncio as aioredis
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.config.settings import get_settings
from api.dependencies import get_current_user, get_db_session, get_job_repository
from api.schemas.job_schemas import (
    JobStatusResponse,
    TriggerScanRequest,
    TriggerScanResponse,
)
from db.models.scan_job import JobStatus, JobType
from db.repositories.job_repository import JobRepository

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/scans", tags=["scan-trigger"])
settings = get_settings()


@router.post(
    "/trigger",
    response_model=TriggerScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger a manual scan",
)
async def trigger_manual_scan(
    request_body: TriggerScanRequest,
    background_tasks: BackgroundTasks,
    current_user: Annotated[str, Depends(get_current_user)],
    job_repo: JobRepository = Depends(get_job_repository),
) -> TriggerScanResponse:
    """
    Trigger an on-demand scan for a Git repository.

    The scan runs asynchronously. Poll /api/jobs/{job_id} for status.

    Authentication: Required (Bearer token or session cookie)
    """
    # Validate repo URL format
    if not request_body.repo_url.startswith(("https://", "http://", "git@")):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="repo_url must be a valid Git repository URL",
        )

    job = await job_repo.create(
        job_type=JobType.MANUAL,
        target_repo=str(request_body.repo_url),
        target_branch=request_body.branch or "main",
        target_commit=request_body.commit,
        triggered_by=current_user,
    )

    logger.info(
        "manual_scan_triggered",
        extra={
            "job_id": str(job.job_id),
            "repo": str(request_body.repo_url),
            "triggered_by": current_user,
        },
    )

    # Publish to Redis queue
    background_tasks.add_task(
        _publish_to_queue,
        job_id=str(job.job_id),
        job_type=JobType.MANUAL.value,
        target_repo=str(request_body.repo_url),
        target_branch=request_body.branch or "main",
        target_commit=request_body.commit,
        triggered_by=current_user,
    )

    return TriggerScanResponse(
        job_id=str(job.job_id),
        status=JobStatus.QUEUED.value,
        created_at=job.created_at.isoformat(),
        message=f"Scan queued. Poll /api/jobs/{job.job_id} for status.",
    )


@router.get(
    "/trigger/{job_id}/cancel",
    status_code=status.HTTP_200_OK,
    summary="Cancel a queued scan job",
)
async def cancel_scan_job(
    job_id: str,
    current_user: Annotated[str, Depends(get_current_user)],
    job_repo: JobRepository = Depends(get_job_repository),
) -> dict:
    """
    Cancel a queued (not yet running) scan job.
    Running jobs cannot be cancelled.
    """
    job = await job_repo.get_by_id(job_id)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job {job_id} not found",
        )

    if job.status != JobStatus.QUEUED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Job {job_id} cannot be cancelled (status: {job.status})",
        )

    await job_repo.update_status(
        job_id=job_id,
        status=JobStatus.CANCELLED,
        error_message=f"Cancelled by {current_user}",
    )

    return {"job_id": job_id, "cancelled": True}


async def _publish_to_queue(
    job_id: str,
    job_type: str,
    target_repo: str,
    target_branch: str,
    target_commit: str | None,
    triggered_by: str,
) -> None:
    """Publish scan job to Redis queue."""
    try:
        redis_client = aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
        )
        async with redis_client as r:
            await r.lpush(
                settings.SCAN_JOB_QUEUE_KEY,
                json.dumps({
                    "job_id": job_id,
                    "job_type": job_type,
                    "target_repo": target_repo,
                    "target_branch": target_branch,
                    "target_commit": target_commit,
                    "triggered_by": triggered_by,
                }),
            )
        logger.info("job_published_to_queue", extra={"job_id": job_id})
    except Exception as exc:
        logger.exception("queue_publish_failed", extra={"job_id": job_id, "error": str(exc)})