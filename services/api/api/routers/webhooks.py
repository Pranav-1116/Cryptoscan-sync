"""
GitHub webhook receiver router.
Handles inbound push/PR events and queues scan jobs.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.config.settings import get_settings
from api.dependencies import get_db_session, get_job_repository, get_repo_config_repository
from api.github.payload_parser import GitHubPayloadParser
from api.github.webhook_handler import GitHubWebhookHandler
from api.schemas.webhook_schemas import WebhookAcknowledgement
from api.security.hmac_verifier import HMACVerifier
from db.repositories.job_repository import JobRepository
from db.repositories.repo_config_repository import RepoConfigRepository

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/webhooks", tags=["webhooks"])
settings = get_settings()


async def _queue_scan_job(
    job_data: Dict[str, Any],
    job_repo: JobRepository,
) -> None:
    """Background task: persist job record and publish to Redis queue."""
    import redis.asyncio as aioredis

    try:
        job = await job_repo.create_from_webhook(job_data)
        logger.info("scan_job_created", extra={"job_id": str(job.job_id)})

        redis_client = aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
        )
        async with redis_client as r:
            await r.lpush(
                settings.SCAN_JOB_QUEUE_KEY,
                json.dumps(
                    {
                        "job_id": str(job.job_id),
                        "job_type": job.job_type,
                        "target_repo": job.target_repo,
                        "target_commit": job.target_commit,
                        "target_branch": job.target_branch,
                        "triggered_by": job.triggered_by,
                    }
                ),
            )
        logger.info("scan_job_queued", extra={"job_id": str(job.job_id)})
    except Exception as exc:
        logger.exception("failed_to_queue_scan_job", extra={"error": str(exc)})


@router.post(
    "/github",
    response_model=WebhookAcknowledgement,
    status_code=status.HTTP_200_OK,
    summary="Receive GitHub webhook events",
)
async def receive_github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: str | None = Header(default=None, alias="X-Hub-Signature-256"),
    x_github_event: str | None = Header(default=None, alias="X-GitHub-Event"),
    x_github_delivery: str | None = Header(default=None, alias="X-GitHub-Delivery"),
    db: AsyncSession = Depends(get_db_session),
    job_repo: JobRepository = Depends(get_job_repository),
    repo_config_repo: RepoConfigRepository = Depends(get_repo_config_repository),
) -> WebhookAcknowledgement:
    """
    Receive and process GitHub push/pull_request webhook events.

    Security:
    - HMAC-SHA256 signature verification via X-Hub-Signature-256
    - Repo allowlist check (only configured repos are scanned)
    - Responds 200 immediately; scanning happens asynchronously

    Returns 200 OK regardless (GitHub requires fast response < 10s).
    """
    raw_body = await request.body()

    # --- Step 1: HMAC verification ---
    if not x_hub_signature_256:
        logger.warning(
            "webhook_missing_signature",
            extra={"delivery": x_github_delivery},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Hub-Signature-256 header",
        )

    verifier = HMACVerifier(secret=settings.GITHUB_WEBHOOK_SECRET)
    if not verifier.verify(payload=raw_body, signature_header=x_hub_signature_256):
        logger.warning(
            "webhook_invalid_signature",
            extra={"delivery": x_github_delivery},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature",
        )

    # --- Step 2: Parse payload ---
    try:
        payload: Dict[str, Any] = json.loads(raw_body)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid JSON payload: {exc}",
        )

    logger.info(
        "webhook_received",
        extra={
            "event": x_github_event,
            "delivery": x_github_delivery,
        },
    )

    # --- Step 3: Only handle push events ---
    if x_github_event not in ("push",):
        logger.debug("webhook_event_ignored", extra={"event": x_github_event})
        return WebhookAcknowledgement(
            acknowledged=True,
            queued=False,
            message=f"Event '{x_github_event}' not processed",
        )

    handler = GitHubWebhookHandler()
    parsed = GitHubPayloadParser().parse_push(payload)

    if parsed is None:
        return WebhookAcknowledgement(
            acknowledged=True,
            queued=False,
            message="Push event skipped (no head commit or deleted branch)",
        )

    # --- Step 4: Check repo allowlist ---
    repo_config = await repo_config_repo.get_by_url(parsed.repo_url)
    if repo_config is None or not repo_config.enabled or not repo_config.scan_on_push:
        logger.info(
            "webhook_repo_not_configured",
            extra={"repo_url": parsed.repo_url},
        )
        return WebhookAcknowledgement(
            acknowledged=True,
            queued=False,
            message="Repository not configured for scanning",
        )

    # --- Step 5: Queue scan job (async — respond fast) ---
    job_data = {
        "job_type": "GITHUB_WEBHOOK",
        "target_repo": parsed.repo_url,
        "target_commit": parsed.commit_hash,
        "target_branch": parsed.branch,
        "triggered_by": parsed.pusher_name,
        "github_delivery_id": x_github_delivery,
    }

    background_tasks.add_task(_queue_scan_job, job_data, job_repo)

    logger.info(
        "webhook_scan_queued",
        extra={
            "repo": parsed.repo_url,
            "commit": parsed.commit_hash,
            "branch": parsed.branch,
        },
    )

    return WebhookAcknowledgement(
        acknowledged=True,
        queued=True,
        message=f"Scan queued for {parsed.repo_url}@{parsed.branch}",
    )