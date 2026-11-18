"""Network-scan job listing and trigger aliases."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.dependencies import (
    TenantContext,
    get_current_user,
    get_db_session,
)
from api.security.network_collection import (NetworkHostRequest, admit_network, checked_hosts, meter_network, network_run, persist_network, network_coverage, network_context)
from db.repositories.intelligence_repository import IntelligenceRepository
from db.tenancy import current_tenant
from network_scanner.core.scanner import NetworkTlsScanner

router = APIRouter(prefix="/network-scans", tags=["network-scans"])


class HostScanRequest(NetworkHostRequest):
    pass

@router.post("")
@router.post("/")
def trigger_network_scan(
    body: HostScanRequest,
    ctx: TenantContext = Depends(network_context),
    db: Session = Depends(get_db_session),
):
    """Live TLS scan of operator-supplied hosts.

    The host list passes the platform's SSRF choke point (loopback, cloud
    metadata, URL schemes refused — found by round-28 review, same class as
    the round-26 monitor finding). Tenant contexts also spend one
    scan_run unit against the plan's monthly quota (402 when exhausted);
    metering happens here so manual scans count exactly like daemon passes.
    """
    hosts = checked_hosts(body.hosts)
    admission = admit_network(hosts)
    meter_network(db, hosts)
    with network_run(db, user=ctx.username, target=",".join(hosts)[:2000], admission=admission, profile={**body.model_dump(exclude={"hosts"}), "workers": body.workers or 8}) as run:
        result = NetworkTlsScanner(live=True, timeout=body.timeout, workers=body.workers or 8).scan_hosts(
            hosts, sni=body.sni, starttls=body.starttls,
            scan_versions=body.scan_versions, scan_ciphers=body.scan_ciphers,
            check_renegotiation=body.check_renegotiation, check_chain_sent=body.check_chain_sent,
            live_revocation=body.live_revocation,
        )
        result = persist_network(db, result, run)
        run.succeed(coverage=network_coverage(result))
    # project the observation into the live-inventory snapshot so the Network
    # and Certificate dashboards reflect this scan, not only full scan cycles
    from api.live_scan.runner import get_live_scan_runner

    get_live_scan_runner().record_network_result(result, tenant_id=current_tenant())
    return result


@router.get("")
@router.get("/")
def list_network_scans(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows = IntelligenceRepository(db).list_targets()
    return {"targets": [row.to_dict() for row in rows], "total_count": len(rows)}
