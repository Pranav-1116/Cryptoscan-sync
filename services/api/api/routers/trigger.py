"""Manual scan trigger."""

from __future__ import annotations

import inspect
import logging
from datetime import datetime, timezone

from db.repositories.job_repository import JobRepository
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status

from api.config.settings import get_settings
from api.dependencies import get_job_repository
from api.schemas.job_schemas import TriggerScanRequest, TriggerScanResponse
from api.security.rbac import require_permission

logger = logging.getLogger(__name__)
router = APIRouter(tags=["trigger"])
# Exposed as a named dependency so applications and tests can override the
# scan-trigger capability without bypassing the central permission matrix.
require_scan_trigger = require_permission("scan.trigger")


def _resolve_sector(explicit: str | None, job_repo: JobRepository) -> str:
    """Effective sector for a scan: explicit override else org setting else generic."""
    if explicit:
        try:
            from sector_profiles import normalize_sector

            return normalize_sector(explicit)
        except Exception:
            return "generic"
    try:
        from db.connection.session import SessionLocal
        from db.repositories.settings_repository import (
            SECTOR_SETTING_KEY,
            SettingsRepository,
        )

        session = SessionLocal()
        try:
            stored = SettingsRepository(session).get(SECTOR_SETTING_KEY)
            if isinstance(stored, dict) and stored.get("sector"):
                return str(stored["sector"])
        finally:
            session.close()
    except Exception as _handler_exc:
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        pass
    return "generic"


def _annotate_sector(job, sector: str, scan_mode: str | None) -> None:
    """Stamp sector/scan_mode onto the job's progress JSON so the pipeline and
    reports see the sector context (no schema change required)."""
    try:
        progress = dict(getattr(job, "progress", None) or {})
        progress["sector"] = sector
        if scan_mode:
            progress["scan_mode"] = scan_mode
        job.progress = progress
    except Exception:
        logger.debug("sector_annotation_skipped", exc_info=True)


def _publish_job(payload: dict) -> None:
    try:
        from worker.core.job_consumer import enqueue_job

        settings = get_settings()
        enqueue_job(payload, redis_url=settings.REDIS_URL, queue_name=settings.SCAN_JOB_QUEUE_KEY)
    except Exception:
        logger.exception("queue_publish_failed")


def _run_inline(payload: dict) -> None:
    """Run the pipeline in-process when no queue is configured.

    Scoped for the same reason the worker is: this runs as a background task,
    after the request has returned and its tenant scope has been torn down, so
    without re-entering it the results would be written unscoped and land in
    the platform estate where every tenant can read them.
    """
    from db.tenancy import tenant_scope

    with tenant_scope(payload.get("tenant_id")):
        _run_inline_in_scope(payload)


def _run_inline_in_scope(payload: dict) -> None:
    try:
        from worker.core.job_consumer import ScanJob
        from worker.pipeline.binary_job import is_binary_target, run_binary_job

        if is_binary_target(payload.get("target_repo")):
            run_binary_job(
                ScanJob(
                    job_id=payload["job_id"],
                    target_repo=payload["target_repo"],
                    target_branch=payload.get("target_branch") or "main",
                    triggered_by=payload.get("triggered_by") or "system",
                    target_commit=payload.get("target_commit"),
                    job_type=payload.get("job_type") or "BINARY",
                    system_id=payload.get("system_id"),
                    tenant_id=payload.get("tenant_id"),
                    progress=payload.get("progress"),
                )
            )
            return
        from cloud_scanner.estate import should_run_cloud_job

        if should_run_cloud_job(payload):
            from worker.core.job_consumer import ScanJob
            from worker.pipeline.cloud_job import run_cloud_job

            run_cloud_job(
                ScanJob(
                    job_id=payload["job_id"],
                    target_repo=payload["target_repo"],
                    target_branch=payload.get("target_branch") or "main",
                    triggered_by=payload.get("triggered_by") or "system",
                    target_commit=payload.get("target_commit"),
                    job_type=payload.get("job_type") or "CLOUD",
                    system_id=payload.get("system_id"),
                    tenant_id=payload.get("tenant_id"),
                )
            )
            return
        from worker.pipeline.pipeline_runner import PipelineRunner

        PipelineRunner().run(
            job_id=payload["job_id"],
            target_repo=payload["target_repo"],
            target_branch=payload["target_branch"],
            target_commit=payload.get("target_commit"),
            triggered_by=payload["triggered_by"],
            system_id=payload.get("system_id"),
        )
    except Exception:
        logger.exception("inline_pipeline_failed", extra={"job_id": payload.get("job_id")})


def enqueue_scan_job(
    job_repo: JobRepository,
    background_tasks: BackgroundTasks,
    *,
    repo_url: str,
    branch: str = "main",
    commit: str | None = None,
    triggered_by: str = "system",
    job_type: str = "MANUAL",
    system_id: str | None = None,
    sector: str | None = None,
    scan_mode: str | None = None,
    scan_options: dict | None = None,
) -> TriggerScanResponse:
    from cloud_scanner.estate import is_cloud_target

    # ONE fail-closed admission decision at the common queue boundary: every
    # route that enqueues a scan goes through this helper, so emergency stop,
    # safe-scan policy and the OT/passive boundary are enforced once, here,
    # instead of per-route (the manual route historically gated itself while
    # this helper — used by cbom/estate/scans/devsecops/systems/jobs/cloud —
    # had no gate at all). Lookup failures raise 503; nothing is accepted
    # when the decision cannot be made.
    from api.security.scan_admission import admit_scan

    admit_scan(scan_mode=scan_mode, asset=repo_url)

    if is_cloud_target(repo_url) and str(job_type).upper() != "CLOUD":
        job_type = "CLOUD"

    # Confine local scan targets to the configured source roots.
    #
    # This endpoint had no containment at all, while the SBOM route next door
    # has always called the same validator. Triggering a scan of /etc was
    # accepted with 202 and the worker walked it, surfacing
    # /etc/NetworkManager/system-connections/<ssid> -- a plaintext WiFi
    # credentials file -- in the job's error message. The scan failed, but
    # only after reading host paths it had no business reaching, and a
    # directory it *could* parse would have put snippets from arbitrary host
    # files into evidence_records.
    #
    # Cloud and remote-git targets are passed through by the validator
    # itself; only local filesystem paths are resolved and root-checked.
    if not is_cloud_target(repo_url):
        from api.security.target_validation import (
            TargetValidationError,
            validate_source_target,
        )

        try:
            validate_source_target(repo_url, label="repo_url")
        except TargetValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    effective_sector = _resolve_sector(sector, job_repo)
    # non-git targets (a binary scan) need their options to survive a restart and a
    # retry, so they are stored on the job row, not held in this process
    progress = {"scan_options": scan_options} if scan_options else None
    created = job_repo.create(
        job_type=job_type,
        target_repo=repo_url,
        target_branch=branch or "main",
        target_commit=commit,
        triggered_by=triggered_by,
        system_id=system_id,
        progress=progress,
    )
    _annotate_sector(created, effective_sector, scan_mode)
    try:
        job_repo.session.commit()
    except Exception as exc:
        # A job that was not committed must never be reported as accepted:
        # otherwise the caller receives an id that a worker can never claim.
        try:
            job_repo.session.rollback()
        except Exception:
            logger.exception("job_commit_rollback_failed")
        logger.exception("job_commit_failed")
        from api.observability.operational_counters import incr

        # The caller is told the queue is unavailable; this is how an
        # operator sees how often that happens without grepping logs.
        incr("persistence_failure")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan queue is temporarily unavailable; no job was accepted",
        ) from exc
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
        "system_id": system_id,
        # Captured here, from the row the ORM guard just stamped, because the
        # publish runs as a background task after the request has finished and
        # the tenant ContextVar is gone by then. Without this the worker has
        # no way to know whose scan it is running.
        "tenant_id": getattr(created, "tenant_id", None),
        "sector": effective_sector,
        "scan_mode": scan_mode,
        "progress": progress,
    }
    settings = get_settings()
    if settings.REDIS_URL:
        background_tasks.add_task(_publish_job, payload)
    else:
        background_tasks.add_task(_run_inline, payload)
    try:  # real-time stream: announce the queued scan the moment it is accepted
        from api.events.bus import get_event_bus

        get_event_bus().publish(
            "scan.queued",
            {"job_id": str(job_id), "repo": repo_url, "branch": branch or "main",
             "triggered_by": triggered_by},
            source="api",
        )
    except Exception as _handler_exc:
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        pass
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
    current_user: str = Depends(require_scan_trigger),
    job_repo: JobRepository = Depends(get_job_repository),
):
    from cloud_scanner.estate import is_cloud_target

    # Fail-closed admission (emergency stop / safe-scan policy / OT passive
    # boundary) before queuing. OT is DERIVED from trusted declarations by
    # the gate itself — the old code read an ``is_ot`` request field that
    # does not exist on TriggerScanRequest, so OT policy was never applied
    # here and a client could not have been trusted to declare it anyway.
    from api.security.scan_admission import admit_scan

    admit_scan(scan_mode=getattr(request_body, "scan_mode", None),
               asset=request_body.repo_url)

    # Same containment as _queue_scan_job below and as the SBOM route: a
    # local target must resolve inside CRYPTOSCAN_SOURCE_ROOTS. Without it
    # this endpoint accepted /etc with 202 and the worker walked it.
    if not is_cloud_target(request_body.repo_url):
        from api.security.target_validation import (
            TargetValidationError,
            validate_source_target,
        )

        try:
            validate_source_target(request_body.repo_url, label="repo_url")
        except TargetValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    job_type = "CLOUD" if is_cloud_target(request_body.repo_url) else "MANUAL"
    effective_sector = _resolve_sector(getattr(request_body, "sector", None), job_repo)
    created = job_repo.create(
        job_type=job_type,
        target_repo=request_body.repo_url,
        target_branch=request_body.branch or "main",
        target_commit=request_body.commit,
        triggered_by=current_user,
    )
    if inspect.isawaitable(created):
        created = await created
    _annotate_sector(created, effective_sector, getattr(request_body, "scan_mode", None))
    try:
        job_repo.session.commit()
    except Exception as exc:
        try:
            job_repo.session.rollback()
        except Exception:
            logger.exception("job_commit_rollback_failed")
        logger.exception("job_commit_failed")
        from api.observability.operational_counters import incr

        # The caller is told the queue is unavailable; this is how an
        # operator sees how often that happens without grepping logs.
        incr("persistence_failure")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan queue is temporarily unavailable; no job was accepted",
        ) from exc

    job_id = getattr(created, "job_id", None) or getattr(created, "id", None)
    created_at = getattr(created, "created_at", None)
    payload = {
        "job_id": job_id,
        "job_type": job_type,
        "target_repo": request_body.repo_url,
        "target_branch": request_body.branch or "main",
        "target_commit": request_body.commit,
        "triggered_by": current_user,
        "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else datetime.now(timezone.utc).isoformat(),
        # See the note on the other payload: the background publish runs after
        # the request scope is gone, so the tenant is captured now.
        "tenant_id": getattr(created, "tenant_id", None),
        "sector": effective_sector,
        "scan_mode": getattr(request_body, "scan_mode", None),
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
