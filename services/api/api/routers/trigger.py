"""Manual scan trigger."""

from __future__ import annotations

import inspect
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, status

from api.config.settings import get_settings
from api.dependencies import get_current_user, get_job_repository
from api.schemas.job_schemas import TriggerScanRequest, TriggerScanResponse
from db.repositories.job_repository import JobRepository

logger = logging.getLogger(__name__)
router = APIRouter(tags=["trigger"])


def _publish_job(payload: dict) -> None:
    try:
        from worker.core.job_consumer import enqueue_job

        settings = get_settings()
        enqueue_job(payload, redis_url=settings.REDIS_URL, queue_name=settings.SCAN_JOB_QUEUE_KEY)
    except Exception:
        logger.exception("queue_publish_failed")


def _run_inline(payload: dict) -> None:
    from worker.pipeline.pipeline_runner import PipelineRunner

    PipelineRunner().run(
        job_id=payload["job_id"],
        target_repo=payload["target_repo"],
        target_branch=payload["target_branch"],
        target_commit=payload.get("target_commit"),
        triggered_by=payload["triggered_by"],
    )


def enqueue_scan_job(
    job_repo: JobRepository,
    background_tasks: BackgroundTasks,
    *,
    repo_url: str,
    branch: str = "main",
    commit: str | None = None,
    triggered_by: str = "system",
    job_type: str = "MANUAL",
) -> TriggerScanResponse:
    created = job_repo.create(
        job_type=job_type,
        target_repo=repo_url,
        target_branch=branch or "main",
        target_commit=commit,
        triggered_by=triggered_by,
    )
    job_id = getattr(created, "job_id", None) or getattr(created, "id", None)
    created_at = getattr(created, "created_at", None)
    payload = {
        "job_id": job_id,
        "job_type": job_type,
        "target_repo": repo_url,
        "target_branch": branch or "main",
        "target_commit": commit,
        "triggered_by": triggered_by,
        "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else datetime.now(timezone.utc).isoformat(),
    }
    settings = get_settings()
    if settings.REDIS_URL:
        background_tasks.add_task(_publish_job, payload)
    else:
        background_tasks.add_task(_run_inline, payload)
    return TriggerScanResponse(
        job_id=str(job_id),
        status=getattr(created, "status", None) or "QUEUED",
        created_at=created_at.isoformat() if hasattr(created_at, "isoformat") else datetime.now(timezone.utc).isoformat(),
        message=f"Scan queued. Poll /api/v1/jobs/{job_id} for status.",
    )


@router.post("/scans/trigger", response_model=TriggerScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def trigger_manual_scan(
    request_body: TriggerScanRequest,
    background_tasks: BackgroundTasks,
    current_user: str = Depends(get_current_user),
    job_repo: JobRepository = Depends(get_job_repository),
):
    created = job_repo.create(
        job_type="MANUAL",
        target_repo=request_body.repo_url,
        target_branch=request_body.branch or "main",
        target_commit=request_body.commit,
        triggered_by=current_user,
    )
    if inspect.isawaitable(created):
        created = await created

    job_id = getattr(created, "job_id", None) or getattr(created, "id", None)
    created_at = getattr(created, "created_at", None)
    payload = {
        "job_id": job_id,
        "job_type": "MANUAL",
        "target_repo": request_body.repo_url,
        "target_branch": request_body.branch or "main",
        "target_commit": request_body.commit,
        "triggered_by": current_user,
        "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else datetime.now(timezone.utc).isoformat(),
    }
    settings = get_settings()
    if settings.REDIS_URL:
        background_tasks.add_task(_publish_job, payload)
    else:
        background_tasks.add_task(_run_inline, payload)

    return TriggerScanResponse(
        job_id=str(job_id),
        status=getattr(created, "status", None) or "QUEUED",
        created_at=created_at.isoformat() if hasattr(created_at, "isoformat") else datetime.now(timezone.utc).isoformat(),
        message=f"Scan queued. Poll /api/v1/jobs/{job_id} for status.",
    )
