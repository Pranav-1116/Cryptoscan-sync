"""Network-scan job listing and trigger aliases."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import (
    TenantContext,
    get_current_user,
    get_db_session,
    get_tenant_context,
)
from api.security.target_validation import (
    TargetValidationError,
    validate_probe_targets,
)
from db.repositories.certificate_repository import CertificateRepository
from db.repositories.intelligence_repository import IntelligenceRepository
from db.repositories.maturity_repository import MaturityRepository
from network_scanner.core.scanner import NetworkTlsScanner

router = APIRouter(prefix="/network-scans", tags=["network-scans"])


class HostScanRequest(BaseModel):
    hosts: list[str] = Field(default_factory=list)
    live: bool = True
    timeout: float = 5.0
    sni: str | None = None
    starttls: str | None = None
    workers: int | None = None
    scan_versions: bool = False
    scan_ciphers: bool = False
    check_renegotiation: bool = False
    check_chain_sent: bool = False
    live_revocation: bool = False


@router.post("")
@router.post("/")
def trigger_network_scan(
    body: HostScanRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db_session),
):
    """Live TLS scan of operator-supplied hosts.

    The host list passes the platform's SSRF choke point (loopback, cloud
    metadata, URL schemes refused — found by round-28 review, same class as
    the round-26 monitor finding). Tenant contexts also spend one
    scan_run unit against the plan's monthly quota (402 when exhausted);
    metering happens here so manual scans count exactly like daemon passes.
    """
    if not body.hosts:
        raise HTTPException(status_code=400, detail="hosts required")
    try:
        validate_probe_targets(body.hosts, label="network_scan.hosts")
    except TargetValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if ctx.tenant_id:
        from db.repositories.tenant_repository import TenantRepository

        t_repo = TenantRepository(db)
        tenant = t_repo.get(ctx.tenant_id)
        from api.security.tenancy import quota_check

        allowed, reason = quota_check(
            tenant.plan if tenant else "FREE", "scan_run",
            t_repo.month_usage(ctx.tenant_id, "scan_run"))
        if not allowed:
            raise HTTPException(status_code=402, detail=f"quota_exceeded: {reason}")
        t_repo.record_usage(ctx.tenant_id, "scan_run", len(body.hosts),
                            detail="manual network scan")
    result = NetworkTlsScanner(live=True, timeout=body.timeout, workers=body.workers).scan_hosts(
        body.hosts,
        sni=body.sni,
        starttls=body.starttls,
        scan_versions=body.scan_versions,
        scan_ciphers=body.scan_ciphers,
        check_renegotiation=body.check_renegotiation,
        check_chain_sent=body.check_chain_sent,
        live_revocation=body.live_revocation,
    )
    repo = CertificateRepository(db)
    usages = MaturityRepository(db)
    for cert in result.get("certificates") or []:
        if cert.get("fingerprint_sha256"):
            repo.upsert(cert)
    for usage in result.get("usages") or []:
        if usage.get("fingerprint_sha256") and usage.get("location"):
            usages.upsert_usage(usage["fingerprint_sha256"], usage["location"], usage.get("usage_type") or "UNKNOWN")
    return result


@router.get("")
@router.get("/")
def list_network_scans(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows = IntelligenceRepository(db).list_targets()
    return {"targets": [row.to_dict() for row in rows], "total_count": len(rows)}
