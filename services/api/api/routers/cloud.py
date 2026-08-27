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


class CloudOrgDiscoverRequest(BaseModel):
    provider: str  # aws | azure | gcp
    role_name: str | None = None  # AWS cross-account role installed per member
    management_account_id: str | None = None  # informational label for the org
    gcp_folder: str | None = None
    gcp_organization: str | None = None
    regions: list[str] | None = None
    max_accounts: int | None = None
    enqueue: bool = True  # enqueue one CLOUD job per discovered account
    register: bool = True  # persist accounts in the cloud account inventory


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


@router.post("/orgs/discover")
def discover_org(
    body: CloudOrgDiscoverRequest,
    background_tasks: BackgroundTasks,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
    jobs: JobRepository = Depends(get_job_repository),
):
    """Enumerate an entire org (AWS Organizations / Azure tenant / GCP folder)
    and register + enqueue every discovered account. Requires org-level
    credentials in the API host environment (partner mode)."""
    from cloud_scanner.org.enumerators import enumerate_org

    provider = str(body.provider or "").lower().strip()
    if provider not in {"aws", "azure", "gcp"}:
        raise HTTPException(status_code=400, detail="provider must be aws, azure or gcp")

    kwargs: dict = {"max_accounts": body.max_accounts} if body.max_accounts else {}
    if provider == "aws" and body.role_name:
        kwargs["role_name"] = body.role_name
    if provider == "gcp":
        if body.gcp_folder:
            kwargs["folder"] = body.gcp_folder
        if body.gcp_organization:
            kwargs["organization"] = body.gcp_organization
    discovery = enumerate_org(provider, **kwargs)
    if discovery.get("errors") and not discovery.get("accounts"):
        raise HTTPException(status_code=502, detail={"message": "org enumeration failed", "errors": discovery["errors"][:5]})

    intel = IntelligenceRepository(db)
    registered, existing_rows = 0, 0
    queued = []
    for account in discovery.get("accounts") or []:
        account_id = str(account.get("account_id") or "").strip()
        if not account_id:
            continue
        if intel.find_cloud_account(provider, account_id) is None:
            intel.create_cloud_account(
                cloud_provider=provider.upper(),
                account_identifier=account_id,
                role_arn=account.get("role_arn"),
                regions=body.regions,
                enabled=True,
            )
            registered += 1
        else:
            existing_rows += 1
        if body.enqueue:
            from api.routers.trigger import enqueue_scan_job as _enqueue

            queued.append(
                _enqueue(
                    jobs,
                    background_tasks,
                    repo_url=f"cloud://{provider}/{account_id}",
                    triggered_by=user,
                    job_type="CLOUD",
                )
            )
    db.commit()
    return {
        "provider": provider,
        "discovered": len(discovery.get("accounts") or []),
        "truncated": bool(discovery.get("truncated")),
        "registered": registered,
        "already_registered": existing_rows,
        "jobs_enqueued": len(queued),
        "errors": discovery.get("errors") or [],
        "accounts": [
            {"account_id": a.get("account_id"), "name": a.get("name"), "status": a.get("status"), "role_arn": a.get("role_arn")}
            for a in (discovery.get("accounts") or [])[:100]
        ],
        "message": (
            "Org enumerated. Accounts registered and one CLOUD job enqueued each. "
            "Use /cloud/orgs/scan for a single fan-out job instead."
        ),
    }


@router.post("/orgs/scan")
def scan_org_endpoint(
    body: CloudOrgDiscoverRequest,
    background_tasks: BackgroundTasks,
    user: str = Depends(get_current_user),
    jobs: JobRepository = Depends(get_job_repository),
):
    """Enqueue ONE org-level job (cloud://<provider>-org/<id>) — the worker
    enumerates and scans all accounts in parallel with a rate budget."""
    from api.routers.trigger import enqueue_scan_job

    provider = str(body.provider or "").lower().strip()
    if provider not in {"aws", "azure", "gcp"}:
        raise HTTPException(status_code=400, detail="provider must be aws, azure or gcp")
    ident = (
        (body.gcp_folder or body.gcp_organization or body.management_account_id)
        if provider == "gcp"
        else body.management_account_id
    )
    target = f"cloud://{provider}-org/{ident}" if ident else f"cloud://{provider}-org"
    queued = enqueue_scan_job(
        jobs,
        background_tasks,
        repo_url=target,
        triggered_by=user,
        job_type="CLOUD",
    )
    return {"queued": _queued_payload(queued), "target": target}


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
