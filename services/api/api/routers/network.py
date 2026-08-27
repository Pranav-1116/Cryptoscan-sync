"""TLS probe, certificate inventory, and scan targets."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from datetime import datetime, timezone

from api.dependencies import get_current_user, get_db_session
from db.repositories.certificate_repository import CertificateRepository
from db.repositories.intelligence_repository import IntelligenceRepository
from db.repositories.maturity_repository import MaturityRepository
from network_scanner.certificates.crl_checker import check_crl
from network_scanner.certificates.ocsp_checker import check_ocsp
from network_scanner.core.scanner import NetworkTlsScanner
from network_scanner.core.scheduler import due_targets, next_scan_time

router = APIRouter(tags=["network"])


class HostScanRequest(BaseModel):
    hosts: list[str] = Field(default_factory=list)
    live: bool = True
    timeout: float = 5.0
    sni: str | None = None
    starttls: str | None = None  # auto | smtp | imap | pop3 | ftp | ldap | postgresql | off
    workers: int | None = None
    scan_versions: bool = False
    scan_ciphers: bool = False
    check_renegotiation: bool = False
    check_chain_sent: bool = False
    live_revocation: bool = False


class TargetCreate(BaseModel):
    endpoint: str
    system_id: str | None = None
    scan_frequency: str = "daily"
    enabled: bool = True


class FilesystemTlsRequest(BaseModel):
    path: str
    live: bool = False


@router.get("/certificates")
def list_certificates(
    expiring_days: int | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    rows = CertificateRepository(db).list_all(expiring_days=expiring_days)
    return {"certificates": [row.to_dict() for row in rows], "total_count": len(rows)}


@router.get("/certificates/{cert_id}")
def get_certificate(cert_id: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    row = CertificateRepository(db).get_by_id(cert_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return row.to_dict()


@router.get("/network/targets")
def list_targets(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows = IntelligenceRepository(db).list_targets()
    return {"targets": [row.to_dict() for row in rows]}


@router.post("/network/targets")
def create_target(body: TargetCreate, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    row = IntelligenceRepository(db).upsert_target(
        body.endpoint,
        system_id=body.system_id,
        scan_frequency=body.scan_frequency,
        enabled=body.enabled,
        next_scan_time=next_scan_time(None, body.scan_frequency),
    )
    return row.to_dict()


@router.get("/network/due")
def list_due(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows = IntelligenceRepository(db).list_targets()
    due = due_targets([row.to_dict() for row in rows])
    return {"targets": due, "total_count": len(due)}


@router.post("/network/run-due")
def run_due(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    intel = IntelligenceRepository(db)
    rows = intel.list_targets()
    due = due_targets([row.to_dict() for row in rows])
    if not due:
        return {"scanned": 0, "findings": []}
    hosts = [item["endpoint"] for item in due if item.get("endpoint")]
    result = NetworkTlsScanner(live=True).scan_hosts(hosts)
    repo = CertificateRepository(db)
    usages = MaturityRepository(db)
    now = datetime.now(timezone.utc)
    for cert in result.get("certificates") or []:
        if cert.get("fingerprint_sha256"):
            repo.upsert(cert)
    for usage in result.get("usages") or []:
        if usage.get("fingerprint_sha256") and usage.get("location"):
            usages.upsert_usage(usage["fingerprint_sha256"], usage["location"], usage.get("usage_type") or "UNKNOWN")
    for item in due:
        intel.upsert_target(
            item["endpoint"],
            last_scan_time=now,
            next_scan_time=next_scan_time(now, item.get("scan_frequency")),
        )
    result["scanned"] = len(hosts)
    return result


class SubnetDiscoverRequest(BaseModel):
    cidr: str
    ports: list[int] = Field(default_factory=lambda: [443, 8443])
    timeout: float = 1.5
    scan: bool = True
    register: bool = False  # upsert discovered endpoints into the due-scan rotation
    scan_frequency: str = "daily"  # hourly | daily | weekly | monthly
    scan_versions: bool = False
    scan_ciphers: bool = False
    check_renegotiation: bool = False
    check_chain_sent: bool = False
    live_revocation: bool = False
    workers: int | None = None


@router.post("/network/discover")
def discover_subnet_endpoints(
    body: SubnetDiscoverRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Sweep a CIDR for open TLS ports and optionally scan each endpoint."""
    from network_scanner.discovery.subnet_discoverer import discover_subnet

    result = discover_subnet(body.cidr, body.ports or [443, 8443], timeout=body.timeout)
    if body.register:
        from network_scanner.discovery.registration import register_targets

        intel = IntelligenceRepository(db)
        existing = {row.endpoint for row in intel.list_targets()}
        result["registration"] = register_targets(
            intel,
            result.get("endpoints") or [],
            scan_frequency=body.scan_frequency,
            existing=existing,
        )
    if body.scan and result.get("endpoints"):
        scanned = NetworkTlsScanner(live=True, workers=body.workers).scan_hosts(
            result["endpoints"],
            scan_versions=body.scan_versions,
            scan_ciphers=body.scan_ciphers,
            check_renegotiation=body.check_renegotiation,
            check_chain_sent=body.check_chain_sent,
            live_revocation=body.live_revocation,
        )
        result["scan"] = {
            "probe_telemetry": scanned.get("probe_telemetry"),
            "certificates": scanned.get("certificates"),
            "alerts": scanned.get("alerts"),
        }
        repo = CertificateRepository(db)
        for cert in scanned.get("certificates") or []:
            if cert.get("fingerprint_sha256"):
                repo.upsert(cert)
    return result


@router.get("/certificates/{cert_id}/usages")
def certificate_usages(cert_id: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    row = CertificateRepository(db).get_by_id(cert_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Certificate not found")
    usages = MaturityRepository(db).usages_for(row.fingerprint_sha256)
    return {"usages": [item.to_dict() for item in usages], "certificate": row.to_dict()}


@router.post("/certificates/{cert_id}/revocation")
def check_revocation(cert_id: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    repo = CertificateRepository(db)
    row = repo.get_by_id(cert_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Certificate not found")
    payload = row.to_dict()
    ocsp = check_ocsp(payload, live=False)
    crl = check_crl(payload, live=False)
    chosen = ocsp if ocsp.get("urls") else crl
    repo.upsert(
        {
            "fingerprint_sha256": row.fingerprint_sha256,
            "revocation_status": chosen.get("status"),
            "revocation_method": chosen.get("method"),
            "ocsp_url": (ocsp.get("urls") or [None])[0],
            "crl_url": (crl.get("urls") or [None])[0],
            "revocation": {"ocsp": ocsp, "crl": crl},
        }
    )
    return {"ocsp": ocsp, "crl": crl}


@router.post("/network/scan")
def scan_network(body: HostScanRequest, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    if not body.hosts:
        raise HTTPException(status_code=400, detail="hosts required")
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


@router.post("/network/scan-path")
def scan_path(body: FilesystemTlsRequest, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    result = NetworkTlsScanner(live=body.live).scan_filesystem(body.path)
    repo = CertificateRepository(db)
    usages = MaturityRepository(db)
    for cert in result.get("certificates") or []:
        if cert.get("fingerprint_sha256"):
            repo.upsert(cert)
    for usage in result.get("usages") or []:
        if usage.get("fingerprint_sha256") and usage.get("location"):
            usages.upsert_usage(usage["fingerprint_sha256"], usage["location"], usage.get("usage_type") or "UNKNOWN")
    return result
