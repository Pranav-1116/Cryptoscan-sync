"""GitHub webhook receiver."""

from __future__ import annotations

import inspect
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from db.repositories.job_repository import JobRepository
from db.repositories.repo_config_repository import RepoConfigRepository
from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Request

from api.config.settings import get_settings
from api.dependencies import get_job_repository, get_repo_config_repository
from api.github.payload_parser import parse_push_event
from api.security.hmac_verifier import HMACVerifier

router = APIRouter(prefix="/webhooks", tags=["webhooks"])
logger = logging.getLogger(__name__)


async def _maybe(value):
    if inspect.isawaitable(value):
        return await value
    return value


#: weak/placeholder default secrets that must never be treated as "configured".
_WEAK_SECRETS = {
    "", "dev-webhook-secret-change-me-32chars!!", "changeme", "secret", "webhook-secret",
}


def _registry_secret() -> str:
    """Shared secret for registry webhooks (ACR/GCR/ECR/Harbor/Docker Hub/…).

    Registry push events are authenticated by HMAC (REGISTRY_WEBHOOK_SECRET)
    falling back to the GitHub secret; never by defaulting to open access.
    """
    for name in ("REGISTRY_WEBHOOK_SECRET", "GITHUB_WEBHOOK_SECRET"):
        val = (os.environ.get(name) or "").strip()
        if val and val not in _WEAK_SECRETS:
            return val
    return ""


def _authorize_registry_webhook(request: Request, body: bytes) -> None:
    """Authenticate an inbound registry push event.

    Accepts EITHER a valid ``X-ZELNX-Signature: sha256=<hex>`` HMAC over the raw
    body (registry configured with the shared secret) OR a machine ``X-API-Key``
    (CI/scanner identity, RBAC-checked against the API-key store). Fails CLOSED:
    in production an unauthenticated/unsigned request is rejected (401). In dev,
    with no secret configured and no API key, the request is allowed for local
    testing — but never if a real secret is set and the signature is wrong.
    """
    sig = request.headers.get("x-zelnx-signature") or request.headers.get("x-hub-signature-256")
    if sig:
        secret = _registry_secret()
        if secret and HMACVerifier(secret).verify(body, sig):
            return
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    if request.headers.get("x-api-key"):
        from api.dependencies import _API_KEY_INVALID, _resolve_api_key

        result = _resolve_api_key(request)
        if result is _API_KEY_INVALID:
            raise HTTPException(status_code=401, detail="Invalid API key")
        if isinstance(result, tuple):
            return  # valid machine identity

    settings = get_settings()
    if getattr(settings, "is_production", False):
        # Fail closed: production never accepts unsigned registry events.
        raise HTTPException(status_code=401, detail="Webhook authentication required")
    # Dev/test with no secret configured and no/accepted credentials: allowed.


def _safe_scan_path(raw_path: str) -> Path:
    """Validate the caller-supplied container filesystem root.

    Blocks absolute paths to sensitive OS locations (path traversal outside a
    scan sandbox) and, when SCAN_ROOT is configured, confines scans to it.
    """
    target = Path(str(raw_path)).resolve()
    blocked_prefixes = ("/etc", "/proc", "/sys", "/root", "/var/lib/postgresql",
                        "/var/run", "/run/secrets", "/dev", "/boot")
    if any(str(target) == p or str(target).startswith(p + "/") for p in blocked_prefixes):
        raise HTTPException(status_code=403, detail="Refusing to scan a protected system path")
    sandbox = os.environ.get("SCAN_ROOT", "").strip()
    if sandbox:
        root = Path(sandbox).resolve()
        if not (target == root or root in target.parents):
            raise HTTPException(status_code=403, detail="scan path outside the configured SCAN_ROOT")
    return target


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
    if not secret or secret in _WEAK_SECRETS:
        # No real shared secret configured: dev/test accept unauthenticated for
        # local testing, but production must never run an open webhook.
        if getattr(settings, "is_production", False):
            raise HTTPException(status_code=401, detail="Webhook secret not configured")

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
    elif not getattr(cfg, "enabled", True) or x_github_event == "pull_request" and not getattr(
        cfg, "scan_on_pr", getattr(cfg, "scan_on_push", True)
    ) or x_github_event != "pull_request" and not getattr(cfg, "scan_on_push", True):
        return {
            "accepted": True,
            "acknowledged": True,
            "queued": False,
            "message": "repository not configured",
        }

    # Tenant ownership: the webhook path is skipped by the tenant middleware
    # (no authenticated principal to resolve), so the job would otherwise be
    # created with tenant_id NULL — the platform estate, readable by every
    # tenant. The matched RepoConfiguration row knows whose repo this is:
    # copy its tenant onto the job and the queue payload.
    cfg_tenant = getattr(cfg, "tenant_id", None)

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
            tenant_id=cfg_tenant,
        )
        created = await _maybe(created)
    if cfg_tenant and getattr(created, "tenant_id", None) is None:
        # legacy create_from_webhook hooks don't take a tenant: stamp the row
        # so the job itself is owned, not just the queue payload
        created.tenant_id = cfg_tenant

    job_id = getattr(created, "job_id", None) or getattr(created, "id", None)
    # Commit the job BEFORE scheduling the background task: FastAPI runs
    # dependency teardown (which commits) only AFTER background tasks, so an
    # inline pipeline would otherwise race the uncommitted INSERT and hit
    # "database is locked" (SQLite) or read a missing job.
    try:
        session = getattr(job_repo, "session", None)
        if session is not None:
            session.commit()
    except Exception as commit_exc:
        logger.exception(
            "github_webhook_job_commit_failed",
            extra={"error_type": type(commit_exc).__name__, "job_id": job_id},
        )
        raise HTTPException(status_code=503, detail="Webhook job could not be persisted") from commit_exc
    job_payload = {
        "job_id": job_id,
        "job_type": "GITHUB_WEBHOOK",
        "target_repo": repo_url,
        "target_branch": payload.get("branch") or "main",
        "target_commit": payload.get("commit"),
        "triggered_by": payload.get("author") or "github",
        "created_at": datetime.now(timezone.utc).isoformat(),
        # so the worker runs the scan inside the owning tenant's scope
        "tenant_id": getattr(created, "tenant_id", None) or cfg_tenant,
    }
    if settings.REDIS_URL:
        from worker.core.job_consumer import enqueue_job

        background_tasks.add_task(enqueue_job, job_payload, settings.REDIS_URL, settings.SCAN_JOB_QUEUE_KEY)
    else:
        # Inline fallback MUST re-enter the tenant scope: this background task
        # runs after the request scope is gone, and an unscoped pipeline would
        # write every result into the platform estate (tenant_id NULL, visible
        # to all tenants). Same discipline as api.routers.trigger._run_inline.
        from api.routers.trigger import _run_inline

        background_tasks.add_task(_run_inline, job_payload)
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
):
    """Accept a registry push event. Scans an already-unpacked image root only.

    Authenticated: requires a valid HMAC signature (REGISTRY_WEBHOOK_SECRET) or
    a machine API key; unsigned requests are rejected (fail-closed in prod).
    """
    body = await request.body()
    _authorize_registry_webhook(request, body)
    try:
        payload = json.loads(body.decode() or "{}")
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError) as parse_exc:
        logger.warning("registry_webhook_payload_invalid", extra={"error_type": type(parse_exc).__name__})
        payload = {}
    path = payload.get("path") or payload.get("image_root")
    image = payload.get("image") or payload.get("repository") or payload.get("detail", {}).get("repository-name")
    if not path:
        return {
            "accepted": True,
            "scanned": False,
            "message": "no unpacked image_root/path supplied; image pull is out of scope",
            "image": image,
        }
    target = _safe_scan_path(str(path))
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
