"""TLS probe, certificate inventory, and scan targets."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from db.repositories.certificate_repository import CertificateRepository
from db.repositories.intelligence_repository import IntelligenceRepository
from network_scanner.core.scanner import NetworkTlsScanner

router = APIRouter(tags=["network"])


class HostScanRequest(BaseModel):
    hosts: list[str] = Field(default_factory=list)
    live: bool = True
    timeout: float = 5.0


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
        body.endpoint, system_id=body.system_id, scan_frequency=body.scan_frequency, enabled=body.enabled
    )
    return row.to_dict()


@router.post("/network/scan")
def scan_network(body: HostScanRequest, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    if not body.hosts:
        raise HTTPException(status_code=400, detail="hosts required")
    result = NetworkTlsScanner(live=True, timeout=body.timeout).scan_hosts(body.hosts)
    repo = CertificateRepository(db)
    for cert in result.get("certificates") or []:
        if cert.get("fingerprint_sha256"):
            repo.upsert(cert)
    return result


@router.post("/network/scan-path")
def scan_path(body: FilesystemTlsRequest, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    result = NetworkTlsScanner(live=body.live).scan_filesystem(body.path)
    repo = CertificateRepository(db)
    for cert in result.get("certificates") or []:
        if cert.get("fingerprint_sha256"):
            repo.upsert(cert)
    return result
