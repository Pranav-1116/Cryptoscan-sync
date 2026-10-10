"""Estate coverage campaigns. One CLOUD job per account, not per resource."""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, require_auditor, get_job_repository
from cloud_scanner.estate import CAMPAIGN_LOOKAHEAD, plan_campaign
from db.repositories.job_repository import JobRepository
from db.repositories.system_repository import SystemRepository

router = APIRouter(prefix="/estate", tags=["estate"])


class CampaignRequest(BaseModel):
    limit: int = Field(25, ge=1, le=100)
    coverage: str = "SCANNABLE"
    business_unit: str | None = None
    providers: list[str] | None = None
    include_cloud: bool = True
    include_git: bool = True
    dry_run: bool = False


def _plan(db: Session, body: CampaignRequest) -> list[dict]:
    lookahead = min(max(int(body.limit) * 40, 200), CAMPAIGN_LOOKAHEAD)
    provider = None
    if body.providers and len(body.providers) == 1:
        provider = body.providers[0]
    uncovered = SystemRepository(db).list_uncovered(
        limit=lookahead,
        business_unit=body.business_unit,
        cloud_provider=provider,
    )
    return plan_campaign(
        uncovered,
        limit=body.limit,
        include_git=body.include_git,
        include_cloud=body.include_cloud,
        providers=body.providers,
    )


@router.get("/scans/due")
def preview_due_scans(
    interval_days: int = Query(7, ge=1, le=365),
    limit: int = Query(25, ge=1, le=100),
    include_cloud: bool = True,
    include_git: bool = True,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Continuous monitoring: which systems are due for a re-scan right now."""
    from cloud_scanner.estate import plan_due_scans

    systems, _trunc = SystemRepository(db).list_all_bounded()
    return {
        "dry_run": True,
        "systems_truncated": _trunc,
        **plan_due_scans(
            systems, interval_days=interval_days, limit=limit,
            include_cloud=include_cloud, include_git=include_git,
        ),
    }


@router.post("/scans/run-due")
def run_due_scans(
    background_tasks: BackgroundTasks,
    interval_days: int = Query(7, ge=1, le=365),
    limit: int = Query(25, ge=1, le=100),
    dry_run: bool = False,
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
    jobs: JobRepository = Depends(get_job_repository),
):
    """Enqueue the overdue re-scans (cron entrypoint). Role: auditor+."""
    from api.routers.trigger import enqueue_scan_job
    from cloud_scanner.estate import plan_due_scans

    systems, _trunc = SystemRepository(db).list_all_bounded()
    plan = plan_due_scans(systems, interval_days=interval_days, limit=limit)
    if dry_run:
        return {"dry_run": True, "queued": 0, "systems_truncated": _trunc, **plan}
    queued = []
    for item in plan["jobs"]:
        result = enqueue_scan_job(
            jobs,
            background_tasks,
            repo_url=item["target"],
            branch=item.get("branch") or "main",
            triggered_by=f"scheduler:{user}",
            job_type=item["job_type"],
            system_id=item.get("system_id"),
        )
        queued.append({**item, "job_id": result.job_id})
    return {
        "dry_run": False,
        "queued": len(queued),
        "triggered_by": f"scheduler:{user}",
        "jobs": queued,
        "due": plan["due"],
        "fresh": plan["fresh"],
        "interval_days": plan["interval_days"],
        "message": (
            f"Queued {len(queued)} overdue re-scans ({plan['fresh']} systems fresh, skipped). "
            "Call from cron for continuous monitoring."
        ),
    }


@router.get("/campaigns")
def preview_campaign(
    limit: int = Query(25, ge=1, le=100),
    business_unit: str | None = None,
    include_cloud: bool = True,
    include_git: bool = True,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    body = CampaignRequest(
        limit=limit,
        business_unit=business_unit,
        include_cloud=include_cloud,
        include_git=include_git,
        dry_run=True,
    )
    planned = _plan(db, body)
    return {
        "dry_run": True,
        "planned": len(planned),
        "jobs": planned,
        "message": "One CLOUD job per cloud account. Git systems stay one job each.",
    }


@router.post("/campaigns")
def start_campaign(
    background_tasks: BackgroundTasks,
    body: CampaignRequest | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
    jobs: JobRepository = Depends(get_job_repository),
):
    from api.routers.trigger import enqueue_scan_job

    request = body or CampaignRequest()
    planned = _plan(db, request)
    if request.dry_run:
        return {
            "dry_run": True,
            "queued": 0,
            "planned": len(planned),
            "jobs": planned,
            "message": "Dry run. No jobs queued.",
        }
    queued = []
    for item in planned:
        result = enqueue_scan_job(
            jobs,
            background_tasks,
            repo_url=item["target"],
            branch=item.get("branch") or "main",
            triggered_by=user,
            job_type=item["job_type"],
            system_id=item.get("system_id"),
        )
        queued.append({**item, "job_id": result.job_id})
    git_n = sum(1 for item in queued if item["job_type"] != "CLOUD")
    cloud_n = sum(1 for item in queued if item["job_type"] == "CLOUD")
    return {
        "dry_run": False,
        "queued": len(queued),
        "git_jobs": git_n,
        "cloud_jobs": cloud_n,
        "jobs": queued,
        "message": (
            f"Queued {git_n} git scans and {cloud_n} cloud account inventories. "
            "Cloud jobs do not clone git. Algorithms stay unknown until each job finishes."
        ),
    }
