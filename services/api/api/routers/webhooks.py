"""GitHub webhook receiver."""

from __future__ import annotations

import inspect
import json
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Request

from api.config.settings import get_settings
from api.dependencies import get_job_repository, get_repo_config_repository
from api.github.payload_parser import parse_pull_request_event, parse_push_event
from api.security.hmac_verifier import HMACVerifier
from db.repositories.job_repository import JobRepository
from db.repositories.repo_config_repository import RepoConfigRepository

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


async def _maybe(value):
    if inspect.isawaitable(value):
        return await value
    return value


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
    settings = get_settings()
    secret = getattr(settings, "GITHUB_WEBHOOK_SECRET", "") or ""
    if secret and not HMACVerifier(secret).verify(body, x_hub_signature_256):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    if x_github_event and x_github_event not in {"push", "pull_request"}:
        return {
            "accepted": True,
            "acknowledged": True,
            "queued": False,
            "message": f"ignored event {x_github_event}",
        }

    try:
        raw = json.loads(body.decode() or "{}")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid webhook payload")

    if raw.get("deleted"):
        return {
            "accepted": True,
            "acknowledged": True,
            "queued": False,
            "message": "branch deletion ignored",
        }

    try:
        payload = parse_push_event(raw)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid webhook payload")

    repo_url = payload.get("repo_url")
    if not repo_url:
        return {
            "accepted": True,
            "acknowledged": True,
            "queued": False,
            "message": "no repository in payload",
        }

    cfg = None
    if hasattr(configs, "get_by_url"):
        cfg = await _maybe(configs.get_by_url(repo_url))
    if cfg is None:
        env = (getattr(settings, "ENVIRONMENT", "") or "").lower()
        if env in {"test", "testing"}:
            return {
                "accepted": True,
                "acknowledged": True,
                "queued": False,
                "message": "repository not configured",
            }
        if hasattr(configs, "is_allowed") and not configs.is_allowed(repo_url):
            return {
                "accepted": True,
                "acknowledged": True,
                "queued": False,
                "message": "repository not configured",
            }
    elif not getattr(cfg, "enabled", True):
        return {
            "accepted": True,
            "acknowledged": True,
            "queued": False,
            "message": "repository not configured",
        }
    elif x_github_event == "pull_request" and not getattr(
        cfg, "scan_on_pr", getattr(cfg, "scan_on_push", True)
    ):
        return {
            "accepted": True,
            "acknowledged": True,
            "queued": False,
            "message": "repository not configured",
        }
    elif x_github_event != "pull_request" and not getattr(cfg, "scan_on_push", True):
        return {
            "accepted": True,
            "acknowledged": True,
            "queued": False,
            "message": "repository not configured",
        }

    created = None
    if hasattr(job_repo, "create_from_webhook"):
        created = await _maybe(
            job_repo.create_from_webhook(
                target_repo=repo_url,
                target_branch=payload.get("branch") or "main",
                target_commit=payload.get("commit"),
                triggered_by=payload.get("author") or "github",
            )
        )
    if created is None:
        created = job_repo.create_job(
            job_type="GITHUB_WEBHOOK",
            target_repo=repo_url,
            target_branch=payload.get("branch") or "main",
            target_commit=payload.get("commit"),
            triggered_by=payload.get("author") or "github",
        )
        created = await _maybe(created)

    job_id = getattr(created, "job_id", None) or getattr(created, "id", None)
    job_payload = {
        "job_id": job_id,
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
            job_id=job_id,
            target_repo=repo_url,
            target_branch=payload.get("branch") or "main",
            triggered_by=payload.get("author") or "github",
            target_commit=payload.get("commit"),
        )
    return {
        "accepted": True,
        "acknowledged": True,
        "queued": True,
        "job_id": job_id,
        "message": "Scan queued",
    }


@router.post("/acr")
@router.post("/gcr")
@router.post("/dockerhub")
@router.post("/harbor")
@router.post("/container")
@router.post("/ecr")
async def container_registry_webhook(
    request: Request,
    user: str | None = None,
):
    """Accept a registry push event. Scans an already-unpacked image root only."""
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    path = payload.get("path") or payload.get("image_root") or payload.get("repository")
    image = payload.get("image") or payload.get("repository") or payload.get("detail", {}).get("repository-name")
    if not path:
        return {
            "accepted": True,
            "scanned": False,
            "message": "no unpacked image_root/path supplied; image pull is out of scope",
            "image": image,
        }
    from pathlib import Path

    target = Path(str(path))
    if not target.exists():
        raise HTTPException(status_code=404, detail="Container filesystem not found")
    from container_scanner.core.scanner import ContainerScanner

    result = ContainerScanner().scan_filesystem(target)
    return {
        "accepted": True,
        "scanned": True,
        "image": image,
        "packages": len(result.get("packages") or []),
        "libraries": len(result.get("libraries") or []),
        "vulnerabilities": len(result.get("vulnerabilities") or []),
        "scan_id": result.get("scan_id"),
    }
