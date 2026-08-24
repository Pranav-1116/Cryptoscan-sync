"""GitHub webhook receiver."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Request

from api.config.settings import get_settings
from api.dependencies import get_job_repository, get_repo_config_repository
from api.github.payload_parser import parse_push_event
from api.security.hmac_verifier import HMACVerifier
from db.repositories.job_repository import JobRepository
from db.repositories.repo_config_repository import RepoConfigRepository

router = APIRouter(prefix="/webhooks", tags=["webhooks"])
settings = get_settings()


@router.post("/github")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: str | None = Header(default=None),
    x_github_event: str | None = Header(default=None),
    job_repo: JobRepository = Depends(get_job_repository),
    configs: RepoConfigRepository = Depends(get_repo_config_repository),
):
    body = await request.body()
    if settings.ENVIRONMENT == "production":
        if not HMACVerifier(settings.GITHUB_WEBHOOK_SECRET).verify(body, x_hub_signature_256):
            raise HTTPException(status_code=401, detail="Invalid webhook signature")
    if x_github_event and x_github_event != "push":
        return {"accepted": True, "message": f"ignored event {x_github_event}"}

    try:
        payload = parse_push_event(await request.json() if False else __import__("json").loads(body.decode() or "{}"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid webhook payload")

    repo_url = payload.get("repo_url")
    if not repo_url:
        return {"accepted": True, "message": "no repository in payload"}
    if not configs.is_allowed(repo_url):
        return {"accepted": True, "message": "repository not configured"}

    job = job_repo.create_job(
        job_type="GITHUB_WEBHOOK",
        target_repo=repo_url,
        target_branch=payload.get("branch") or "main",
        target_commit=payload.get("commit"),
        triggered_by=payload.get("author") or "github",
    )
    job_payload = {
        "job_id": job.id,
        "job_type": "GITHUB_WEBHOOK",
        "target_repo": repo_url,
        "target_branch": payload.get("branch") or "main",
        "target_commit": payload.get("commit"),
        "triggered_by": payload.get("author") or "github",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    if settings.REDIS_URL:
        from worker.core.job_consumer import enqueue_job

        background_tasks.add_task(enqueue_job, job_payload, settings.REDIS_URL, settings.SCAN_JOB_QUEUE_KEY)
    else:
        from worker.pipeline.pipeline_runner import PipelineRunner

        background_tasks.add_task(
            PipelineRunner().run,
            job.id,
            repo_url,
            payload.get("branch") or "main",
            payload.get("author") or "github",
            payload.get("commit"),
        )
    return {"accepted": True, "job_id": job.id, "message": "scan queued"}
