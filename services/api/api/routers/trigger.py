"""Manual scan trigger."""

from __future__ import annotations

import inspect
import logging
from datetime import datetime, timezone

from db.repositories.job_repository import JobRepository
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status

from api.config.settings import get_settings
from api.dependencies import get_job_repository, require_auditor
from api.schemas.job_schemas import TriggerScanRequest, TriggerScanResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["trigger"])


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
    except Exception:
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


def _safe_scan_gate(*, region: str | None = None, environment: str | None = None,
                    is_ot: bool = False, asset: str | None = None) -> None:
    """Fail-closed: refuse to queue a scan when the safe-scan layer blocks it
    (global/scope emergency stop, or an OT/policy prohibition). Reads the
    Control Plane policies; any lookup failure fails closed for safety."""
    try:
        from control_plane.orchestrator import emergency_engaged
        from control_plane.safety import evaluate_scan
        from db.connection.session import SessionLocal
        from db.repositories.control_plane_repository import ControlPlaneRepository

        session = SessionLocal()
        try:
            cp = ControlPlaneRepository(session)
            if emergency_engaged([e.to_dict() for e in cp.list_events(None, limit=500)]):
                raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                    detail="Scan rejected: emergency stop is engaged")
            policy_row = cp.matching_policy(region=region, environment=environment)
            decision = evaluate_scan(policy_row.to_dict() if policy_row else None,
                                     asset=asset, is_ot=is_ot)
            if not decision.permitted:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                    detail=f"Scan rejected by safe-scan policy: {decision.reason}")
        finally:
            session.close()
    except HTTPException:
        raise
    except Exception:
        logger.debug("safe_scan_gate_unavailable", exc_info=True)


def _publish_job(payload: dict) -> None:
    try:
        from worker.core.job_consumer import enqueue_job

        settings = get_settings()
        enqueue_job(payload, redis_url=settings.REDIS_URL, queue_name=settings.SCAN_JOB_QUEUE_KEY)
    except Exception:
        logger.exception("queue_publish_failed")


def _run_inline(payload: dict) -> None:
    try:
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
) -> TriggerScanResponse:
    from cloud_scanner.estate import is_cloud_target

    if is_cloud_target(repo_url) and str(job_type).upper() != "CLOUD":
        job_type = "CLOUD"
    effective_sector = _resolve_sector(sector, job_repo)
    created = job_repo.create(
        job_type=job_type,
        target_repo=repo_url,
        target_branch=branch or "main",
        target_commit=commit,
        triggered_by=triggered_by,
        system_id=system_id,
    )
    _annotate_sector(created, effective_sector, scan_mode)
    try:
        job_repo.session.commit()
    except Exception:
        logger.debug("job_commit_skipped", exc_info=True)
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
        "sector": effective_sector,
        "scan_mode": scan_mode,
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
    except Exception:
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
    current_user: str = Depends(require_auditor),
    job_repo: JobRepository = Depends(get_job_repository),
):
    from cloud_scanner.estate import is_cloud_target

    # fail-closed safe-scan gate (emergency stop / OT policy) before queuing
    _safe_scan_gate(is_ot=bool(getattr(request_body, "is_ot", False)))

    job_type = "CLOUD" if is_cloud_target(request_body.repo_url) else "MANUAL"
    effective_sector = _resolve_sector(getattr(request_body, "sector", None), job_repo)
    created = job_repo.create(
        job_type=job_type,
        target_repo=request_body.repo_url,
        target_branch=request_body.branch or "main",
        target_commit=request_body.commit,
        triggered_by=current_user,
    )
    _annotate_sector(created, effective_sector, getattr(request_body, "scan_mode", None))
    if inspect.isawaitable(created):
        created = await created
    try:
        job_repo.session.commit()
    except Exception:
        logger.debug("job_commit_skipped", exc_info=True)

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
