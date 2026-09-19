"""Workload identity API (SPIFFE-style SVID issuance + verification).

The trust domain CA is generated once and held in settings/secret at boot
(or provided via env WORKLOAD_CA_CERT / WORKLOAD_CA_KEY for a stable CA).
Scanners/workers call POST /workload/svid to fetch a short-lived client SVID
for mTLS to the API; the API's mTLS listener (or an edge proxy) validates
peers with verify_peer. The verify endpoint lets an operator confirm a
presented cert chain deterministically.

Issuance requires an admin-scoped principal (the CA is a root of trust);
verification only requires authentication.
"""

from __future__ import annotations

import functools

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_db_session, require_roles
from db.repositories.user_repository import UserRepository

router = APIRouter(prefix="/workload", tags=["workload-identity"])


@functools.lru_cache(maxsize=1)
def _ca():
    """Lazily build/load the trust-domain CA.

    Production should set WORKLOAD_CA_CERT_PEM / WORKLOAD_CA_KEY_PEM so the CA
    is stable across restarts; otherwise a CA is generated for the process
    (development). The domain comes from WORKLOAD_TRUST_DOMAIN.
    """
    import os

    from identity.workload import CaBundle, generate_ca

    cert = os.environ.get("WORKLOAD_CA_CERT_PEM", "")
    key = os.environ.get("WORKLOAD_CA_KEY_PEM", "")
    domain = os.environ.get("WORKLOAD_TRUST_DOMAIN", "cryptoscan.internal")
    if cert and key:
        return CaBundle(trust_domain=domain, cert_pem=cert, private_key_pem=key)
    return generate_ca(trust_domain=domain)


class SvidRequest(BaseModel):
    workload: str = Field(..., min_length=1, max_length=200,
                          description="Workload path, e.g. 'scanner/edge-1'")
    ttl_minutes: int = Field(60, ge=5, le=1440)


class SvidResponse(BaseModel):
    spiffe_id: str
    cert_pem: str
    key_pem: str
    ca_cert_pem: str
    not_after: str


@router.post("/svid", response_model=SvidResponse, status_code=201)
def issue_svid(
    body: SvidRequest,
    user: str = Depends(require_roles("admin", "superadmin", "scanner")),
    db: Session = Depends(get_db_session),
):
    from identity.workload import WorkloadIdentityError, issue_svid as _issue

    # workload names must be safe path segments
    if any(c in body.workload for c in ("..", " ", "\n", "\r")) or body.workload.startswith("/"):
        raise HTTPException(status_code=422, detail="invalid workload identifier")
    try:
        svid = _issue(_ca(), body.workload, ttl_minutes=body.ttl_minutes)
    except WorkloadIdentityError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    UserRepository(db).audit(user, "workload.svid_issue", target_type="workload",
                             target_id=svid["spiffe_id"], detail={"ttl_minutes": body.ttl_minutes})
    db.commit()
    return SvidResponse(**svid)


class VerifyRequest(BaseModel):
    cert_pem: str
    allowed_workloads: list[str] | None = None


@router.post("/verify")
def verify_svid(
    body: VerifyRequest,
    user: str = Depends(require_roles("admin", "superadmin", "scanner", "auditor")),
):
    from identity.workload import WorkloadIdentityError, verify_peer

    try:
        result = verify_peer(body.cert_pem, _ca(),
                             allowed_workloads=body.allowed_workloads)
    except WorkloadIdentityError as exc:
        raise HTTPException(status_code=401, detail=f"SVID verification failed: {exc}")
    return {"valid": True, **result}


@router.get("/ca")
def ca_bundle(user: str = Depends(require_roles("admin", "superadmin", "scanner"))):
    """Return the trust-domain CA certificate (public) for mTLS clients."""
    ca = _ca()
    return {"trust_domain": ca.trust_domain, "ca_cert_pem": ca.cert_pem}
