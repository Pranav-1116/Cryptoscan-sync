"""Network-scan job listing and trigger aliases."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from db.repositories.certificate_repository import CertificateRepository
from db.repositories.intelligence_repository import IntelligenceRepository
from db.repositories.maturity_repository import MaturityRepository
from network_scanner.core.scanner import NetworkTlsScanner

router = APIRouter(prefix="/network-scans", tags=["network-scans"])


class HostScanRequest(BaseModel):
    hosts: list[str] = Field(default_factory=list)
    live: bool = True
    timeout: float = 5.0


@router.post("")
@router.post("/")
def trigger_network_scan(
    body: HostScanRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    if not body.hosts:
        raise HTTPException(status_code=400, detail="hosts required")
    result = NetworkTlsScanner(live=True, timeout=body.timeout).scan_hosts(body.hosts)
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
