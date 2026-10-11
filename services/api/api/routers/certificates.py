"""Certificate lifecycle endpoints (spec-named router).

Inventory endpoints live in api.routers.network (re-exported here for
backwards compatibility). The lifecycle automation — CSR generation,
issuance (self-signed or internal CA), renewal with optional key rotation,
revocation with local CRL, and the renewal-queue — is defined here.

Honest constraints:

- Private keys are generated locally and returned to the caller **once**;
  the platform never stores key material.
- Renewal of a CA-issued certificate requires the CA key to be configured
  (env CRYPTOSCAN_CA_CERT / CRYPTOSCAN_CA_KEY). Without it, renewals are
  refused with 503 — never guessed, never silently self-signed.
- Revocation without a CA key records MANUAL revocation (operator must
  distribute the CRL / update OCSP themselves); with a CA key a local CRL
  is produced and returned.
"""

from __future__ import annotations

import logging
import os
import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api.dependencies import get_current_user, get_db_session
from api.security.audit_diff import audit_detail_with_changes, field_diff
from api.security.rbac import require_permission
from sqlalchemy.orm import Session

from db.repositories.certificate_repository import CertificateRepository

from api.routers.network import (
    certificate_usages,
    check_revocation,
    get_certificate,
    list_certificates,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/certificates", tags=["certificates"])

_CERT_FIELDS = {
    "fingerprint_sha256",
    "subject",
    "issuer",
    "serial_number",
    "not_before",
    "not_after",
    "public_key_algorithm",
    "public_key_size",
    "expiry_status",
    "days_until_expiry",
    "is_self_signed",
    "san",
    "usages",
    "revocation_status",
    "revocation_method",
    "revocation_checked_at",
    "ocsp_url",
    "crl_url",
    "extra",
}


class CsrRequest(BaseModel):
    subject: dict[str, str] = Field(default_factory=lambda: {"CN": "cryptoscan-host"})
    san: list[str] | None = None
    key_size: int = 2048


class IssueRequest(BaseModel):
    subject: dict[str, str] = Field(default_factory=lambda: {"CN": "cryptoscan-leaf"})
    san: list[str] | None = None
    csr_pem: str | None = None
    key_size: int = 2048
    validity_days: int = 825
    signed_by_ca: bool = False


class RenewRequest(BaseModel):
    validity_days: int = 825
    rotate_key: bool = False


class CertificateOwnershipRequest(BaseModel):
    """Direct ownership on a certificate (audit 55 P0#4)."""
    owner: str | None = Field(None, max_length=200)
    technical_contact: str | None = Field(None, max_length=200)
    reason: str = Field(..., min_length=1)


class RevokeRequest(BaseModel):
    reason: str = "unspecified"


def _subject_cn(subject: str | None) -> str:
    """CN from a stored subject (may be the x509 Name repr or a plain CN)."""
    if not subject:
        return ""
    match = re.search(r"CN=([^,)]+)", subject)
    return match.group(1) if match else subject


def _days_until(iso: str | None) -> int | None:
    """Whole days from now until the ISO timestamp (None when unparsable)."""
    if not iso:
        return None
    try:
        from datetime import datetime, timezone

        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return max(0, (dt - datetime.now(timezone.utc)).days)
    except (TypeError, ValueError, OverflowError):
        return None


def _ca_credentials() -> tuple[str, str] | None:
    cert = os.environ.get("CRYPTOSCAN_CA_CERT", "")
    key = os.environ.get("CRYPTOSCAN_CA_KEY", "")
    if cert and key:
        return cert, key
    return None


@router.post("/lifecycle/csr")
def lifecycle_csr(
    body: CsrRequest,
    user: str = Depends(require_permission("certificates.manage")),
):
    from network_scanner.certificates.lifecycle import generate_csr

    result = generate_csr(subject=body.subject, san=body.san, key_size=body.key_size)
    return {
        "csr_pem": result.csr_pem,
        "private_key_pem": result.private_key_pem,  # returned exactly once
        "subject": result.subject,
    }


@router.post("/lifecycle/issue")
def lifecycle_issue(
    body: IssueRequest,
    user: str = Depends(require_permission("certificates.manage")),
    db: Session = Depends(get_db_session),
):
    from network_scanner.certificates.lifecycle import issue_from_ca, issue_self_signed

    if body.signed_by_ca:
        creds = _ca_credentials()
        if creds is None:
            raise HTTPException(
                status_code=503,
                detail="CA issuance requested but CRYPTOSCAN_CA_CERT/CRYPTOSCAN_CA_KEY "
                "are not configured",
            )
        result = issue_from_ca(
            ca_cert_pem=creds[0],
            ca_key_pem=creds[1],
            subject=body.subject,
            san=body.san,
            csr_pem=body.csr_pem,
            key_size=body.key_size,
            validity_days=body.validity_days,
        )
    else:
        result = issue_self_signed(
            subject=body.subject,
            san=body.san,
            csr_pem=body.csr_pem,
            key_size=body.key_size,
            validity_days=body.validity_days,
        )
    repo = CertificateRepository(db)
    payload = result.to_inventory_payload()
    payload["expiry_status"] = "VALID"
    payload["days_until_expiry"] = _days_until(result.not_after)
    extra = dict(payload.get("extra") or {})
    extra["certificate_pem"] = result.certificate_pem
    payload["extra"] = extra
    row = repo.upsert(payload)
    db.commit()
    return {
        "certificate_pem": result.certificate_pem,
        "private_key_pem": result.private_key_pem,  # returned exactly once
        "fingerprint_sha256": result.fingerprint_sha256,
        "serial_number": result.serial_number,
        "subject": result.subject,
        "issuer": result.issuer,
        "not_before": result.not_before,
        "not_after": result.not_after,
        "inventory_id": row.id,
    }


@router.post("/{fingerprint}/ownership")
def assign_certificate_ownership(
    fingerprint: str,
    body: CertificateOwnershipRequest,
    user: str = Depends(require_permission("certificates.manage")),
    db: Session = Depends(get_db_session),
):
    """Assign a direct owner + technical contact to a certificate (audit 55 P0#4).

    Certificate ownership used to be inferable only through the systems the
    certificate protects — a cert with no usage links had nobody to notify
    at expiry. Only supplied fields change; omitting one clears nothing.
    """
    repo = CertificateRepository(db)
    row = repo.get_by_fingerprint(fingerprint)
    if row is None:
        raise HTTPException(status_code=404, detail="certificate not found")
    before = {"owner": row.owner, "technical_contact": row.technical_contact}
    if body.owner is not None:
        row.owner = body.owner
    if body.technical_contact is not None:
        row.technical_contact = body.technical_contact
    db.commit()
    from db.repositories.user_repository import UserRepository

    UserRepository(db).audit(
        user, "certificate.ownership.assign", target_type="certificate",
        target_id=row.fingerprint_sha256,
        detail=audit_detail_with_changes(field_diff(
            before, {"owner": row.owner, "technical_contact": row.technical_contact}),
            reason=body.reason),
    )
    db.commit()
    return {
        "fingerprint_sha256": row.fingerprint_sha256,
        "owner": row.owner,
        "technical_contact": row.technical_contact,
        "reason": body.reason,
    }


@router.post("/{fingerprint}/renew")
def lifecycle_renew(
    fingerprint: str,
    body: RenewRequest,
    user: str = Depends(require_permission("certificates.manage")),
    db: Session = Depends(get_db_session),
):
    from network_scanner.certificates.lifecycle import renew_certificate

    repo = CertificateRepository(db)
    row = repo.get_by_fingerprint(fingerprint)
    if row is None:
        raise HTTPException(status_code=404, detail="certificate not found")
    cert_pem = (row.extra or {}).get("certificate_pem")
    if not cert_pem:
        raise HTTPException(
            status_code=409,
            detail="certificate PEM not stored in inventory; renewal needs the current "
            "certificate body (supply it via POST /certificates/lifecycle/issue)",
        )
    creds = _ca_credentials() if row.is_self_signed is False else None
    try:
        result = renew_certificate(
            cert_pem,
            ca_cert_pem=creds[0] if creds else None,
            ca_key_pem=creds[1] if creds else None,
            validity_days=body.validity_days,
            rotate_key=body.rotate_key,
        )
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    payload = result.to_inventory_payload()
    payload["expiry_status"] = "VALID"
    extra = dict(payload.get("extra") or {})
    extra["certificate_pem"] = result.certificate_pem
    payload["extra"] = extra
    row2 = repo.upsert(payload)
    repo.update_renewal(
        result.fingerprint_sha256,
        "DONE",
        note=f"renewed from {fingerprint[:12]} (rotate_key={body.rotate_key})",
    )
    db.commit()
    return {
        "certificate_pem": result.certificate_pem,
        "private_key_pem": result.private_key_pem,  # returned exactly once
        "fingerprint_sha256": result.fingerprint_sha256,
        "serial_number": result.serial_number,
        "not_before": result.not_before,
        "not_after": result.not_after,
        "inventory_id": row2.id,
    }


@router.post("/{fingerprint}/revoke")
def lifecycle_revoke(
    fingerprint: str,
    body: RevokeRequest,
    user: str = Depends(require_permission("certificates.manage")),
    db: Session = Depends(get_db_session),
):
    from network_scanner.certificates.lifecycle import revoke_result

    repo = CertificateRepository(db)
    row = repo.get_by_fingerprint(fingerprint)
    if row is None:
        raise HTTPException(status_code=404, detail="certificate not found")
    cert_pem = (row.extra or {}).get("certificate_pem")
    if not cert_pem:
        raise HTTPException(
            status_code=409,
            detail="certificate PEM not stored; cannot build a CRL entry without it",
        )
    creds = _ca_credentials()
    record = revoke_result(
        cert_pem,
        ca_cert_pem=creds[0] if creds else None,
        ca_key_pem=creds[1] if creds else None,
        reason=body.reason,
    )
    row2 = repo.upsert(record)
    db.commit()
    return {
        "fingerprint_sha256": record["fingerprint_sha256"],
        "revocation_status": "REVOKED",
        "revocation_method": record["revocation_method"],
        "crl_pem": (record.get("extra") or {}).get("revocation", {}).get("crl_pem"),
        "inventory_id": row2.id,
    }


class CtEntryIngest(BaseModel):
    """One CT log entry — the get-entries shape (leaf_input b64, index)."""
    leaf_input: str = Field(..., min_length=1)
    index: int | None = None


class CtIngestRequest(BaseModel):
    log_url: str | None = Field(None, max_length=500)
    entries: list[CtEntryIngest] = Field(..., min_length=1, max_length=500)


@router.post("/ct-entries")
def ingest_ct_log_entries(
    body: CtIngestRequest,
    user: str = Depends(require_permission("certificates.manage")),
    db: Session = Depends(get_db_session),
):
    """Ingest Certificate-Transparency log entries into cert inventory (audit 63).

    Accepts ``get-entries`` shaped batches (``leaf_input`` base64, optional
    index, log URL for provenance) — the deterministic layer a CT poller
    or a log-monitor export feeds. Live log streaming itself stays
    deployment-scoped (a real log/monitor endpoint is configuration, not
    code). Precertificate leaves are skipped with an explicit reason
    rather than half-parsed; every rejected entry is reported, never
    silently dropped. Composite/hybrid detection rides along on ingest.
    """
    from network_scanner.certificates.ct_entries import ingest_ct_entries

    batch = ingest_ct_entries(
        [e.model_dump() for e in body.entries], log_url=body.log_url)
    repo = CertificateRepository(db)
    imported: list[str] = []
    composite = 0
    for payload in batch["payloads"]:
        row = repo.upsert(payload)
        db.commit()
        imported.append(row.fingerprint_sha256)
        if (row.extra or {}).get("composite"):
            composite += 1
    return {
        "model": "ct-entries/ingest-v1",
        "imported": len(imported),
        "skipped": len(batch["skipped"]),
        "skip_detail": batch["skipped"],
        "composite_detected": composite,
        "fingerprints": imported,
        "note": "deterministic ingestion layer; live CT log streaming is "
                "deployment-scoped",
    }


@router.get("/lifecycle/renewal-queue")
def renewal_queue(
    lead_days: int = 30,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Certificates due for renewal within `lead_days`."""
    from network_scanner.certificates.lifecycle import renewal_due

    repo = CertificateRepository(db)
    rows = repo.list_all()
    due = []
    for row in rows:
        if row.revocation_status == "REVOKED":
            continue
        if renewal_due(row.not_after, lead_days=lead_days):
            due.append(
                {
                    "fingerprint_sha256": row.fingerprint_sha256,
                    "subject": _subject_cn(row.subject),
                    "not_after": row.not_after.isoformat() if row.not_after else None,
                    "renewal_status": row.renewal_status,
                    "is_self_signed": row.is_self_signed,
                    # where the record came from: TLS probe (default) or a key/certificate export scan
                    "source": (row.extra or {}).get("source") or "TLS_SCAN",
                    "key_label": (row.extra or {}).get("key_label"),
                    "key_store": (row.extra or {}).get("key_store"),
                    "usages": list(row.usages or [])[:5],
                }
            )
    return {"lead_days": lead_days, "due": sorted(due, key=lambda d: d["not_after"] or "")}


__all__ = [
    "certificate_usages",
    "check_revocation",
    "get_certificate",
    "list_certificates",
    "lifecycle_csr",
    "lifecycle_issue",
    "lifecycle_renew",
    "lifecycle_revoke",
    "renewal_queue",
    "router",
]
