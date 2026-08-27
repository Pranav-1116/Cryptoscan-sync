"""Cloud / IaC crypto scan and estate inventory."""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, get_job_repository
from cloud_scanner.core.scanner import CloudScanner
from db.repositories.intelligence_repository import IntelligenceRepository
from db.repositories.job_repository import JobRepository

router = APIRouter(prefix="/cloud", tags=["cloud"])


class CloudScanRequest(BaseModel):
    path: str
    live: bool = False


class CloudInventoryRequest(BaseModel):
    path: str | None = None
    live: bool = False
    persist: bool = True
    enqueue: bool = True
    account_id: str | None = None
    providers: list[str] | None = None
    regions: list[str] | None = None


class CloudAccountCreate(BaseModel):
    cloud_provider: str
    account_identifier: str
    role_arn: str | None = None
    regions: list[str] | None = None
    enabled: bool = True


def _queued_payload(queued):
    if queued is None:
        return None
    if hasattr(queued, "model_dump"):
        return queued.model_dump()
    if hasattr(queued, "dict"):
        return queued.dict()
    return queued


def _account_target(account) -> str:
    provider = str(getattr(account, "cloud_provider", "aws") or "aws").lower()
    ident = str(getattr(account, "account_identifier", "") or "").strip()
    return f"cloud://{provider}/{ident}" if ident else f"cloud://{provider}"


@router.post("/scan")
def scan_cloud(body: CloudScanRequest, user: str = Depends(get_current_user)):
    if not body.path:
        raise HTTPException(status_code=400, detail="path required")
    return CloudScanner(live=body.live).scan_filesystem(body.path)


@router.get("/accounts")
def list_accounts(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows = IntelligenceRepository(db).list_cloud_accounts()
    return {"accounts": [row.to_dict() for row in rows]}


@router.post("/accounts")
def create_account(body: CloudAccountCreate, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    row = IntelligenceRepository(db).create_cloud_account(
        cloud_provider=body.cloud_provider.upper(),
        account_identifier=body.account_identifier,
        role_arn=body.role_arn,
        regions=body.regions,
        enabled=body.enabled,
    )
    return row.to_dict()


@router.post("/inventory")
def inventory_cloud(
    body: CloudInventoryRequest,
    background_tasks: BackgroundTasks,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
    jobs: JobRepository = Depends(get_job_repository),
):
    return _inventory(body, background_tasks, user, db, jobs)


@router.post("/accounts/{account_id}/inventory")
def inventory_account(
    account_id: str,
    background_tasks: BackgroundTasks,
    live: bool = False,
    enqueue: bool = True,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
    jobs: JobRepository = Depends(get_job_repository),
):
    return _inventory(
        CloudInventoryRequest(live=live, enqueue=enqueue, persist=True, account_id=account_id),
        background_tasks,
        user,
        db,
        jobs,
    )


def _inventory(
    body: CloudInventoryRequest,
    background_tasks: BackgroundTasks,
    user: str,
    db: Session,
    jobs: JobRepository,
) -> dict:
    from api.routers.trigger import enqueue_scan_job
    from cloud_scanner.estate import ingest_findings

    intel = IntelligenceRepository(db)
    account = intel.get_cloud_account(body.account_id) if body.account_id else None
    if body.account_id and account is None:
        raise HTTPException(status_code=404, detail="Cloud account not found")
    if not body.path and not body.live:
        raise HTTPException(status_code=422, detail="Provide an IaC path or set live=true to inventory a cloud account")

    findings: list[dict] = []
    iac = None
    queued = None
    live_result = None
    if body.path:
        iac = CloudScanner(live=False).scan_filesystem(body.path)
        findings.extend(iac.get("findings") or [])
    if body.live:
        if body.enqueue:
            if account:
                target = _account_target(account)
            elif body.providers:
                target = f"cloud://{body.providers[0].lower()}"
            else:
                target = "cloud://aws"
            queued = enqueue_scan_job(
                jobs,
                background_tasks,
                repo_url=target,
                triggered_by=user,
                job_type="CLOUD",
            )
        else:
            live_result = CloudScanner(live=True).scan_live(
                providers=body.providers,
                regions=body.regions or (getattr(account, "regions", None) if account else None),
                role_arn=getattr(account, "role_arn", None) if account else None,
                azure_subscription=(
                    account.account_identifier
                    if account and str(account.cloud_provider).upper() == "AZURE"
                    else None
                ),
                gcp_project=(
                    account.account_identifier
                    if account and str(account.cloud_provider).upper() == "GCP"
                    else None
                ),
            )
            findings.extend(live_result.get("findings") or [])

    ingested = None
    if body.persist and findings:
        ingested = ingest_findings(
            db,
            findings,
            account=getattr(account, "account_identifier", None) if account else None,
            stamp=True,
        )
    return {
        "live": body.live,
        "resources": len(findings),
        "issues": sum(1 for row in findings if row.get("compliance_issue")),
        "iac": {"resources": iac.get("resources"), "issues": iac.get("issues")} if iac else None,
        "queued": _queued_payload(queued),
        "ingested": ingested,
        "live_errors": (live_result or {}).get("errors") if live_result else None,
        "live_scan": (live_result or {}).get("live_scan") if live_result else None,
        "message": (
            "IaC findings persist as systems when persist=true. "
            "Live APIs never run unless live=true, and default to one queued CLOUD job per account."
        ),
    }
