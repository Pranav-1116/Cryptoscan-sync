"""Governance / resilience API: signed compliance PDF reports (21), encrypted
backup + restore + retention (22), audit hash-chain attestation (25), air-gapped
mode + signed feed bundles (26), and passive OT protocol decode (27).

Everything is deterministic (no AI). Signing keys are read from settings/env
(vault references in production); if absent, an ephemeral key is generated per
process so the endpoint remains demonstrable without leaking a default secret.
"""

from __future__ import annotations

import base64
import datetime as dt
import os
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_db_session, require_roles
from db.models.user import AuditLog
from db.repositories.user_repository import UserRepository

router = APIRouter(prefix="/resilience", tags=["resilience"])


def _signing_secret() -> str:
    return os.environ.get("GOVERNANCE_SIGNING_SECRET") or _ephemeral["secret"]


def _fernet_key() -> bytes:
    from cryptography.fernet import Fernet

    env = os.environ.get("BACKUP_ENCRYPTION_KEY")
    if env:
        return env.encode()
    # process-ephemeral but stable across calls within this process, so a
    # backup created here can be verified/restored here; production sets the env
    # vault reference so the key persists across restarts.
    global _EPHEMERAL_FERNET
    if _EPHEMERAL_FERNET is None:
        _EPHEMERAL_FERNET = Fernet.generate_key()
    return _EPHEMERAL_FERNET


_EPHEMERAL_FERNET: bytes | None = None


class _Ephemeral:
    def __init__(self):
        self.secret = base64.urlsafe_b64encode(os.urandom(32)).decode()


_ephemeral = _Ephemeral()


# ================================================================ 21 report = #
class ReportRequest(BaseModel):
    framework: str = Field(..., description="NIST_SP_800_53 | PCI_DSS_4 | DORA | UAE_PDPL")
    org: str = "CryptoScan Tenant"
    evidence: dict[str, list[dict]] = Field(default_factory=dict)
    format: str = "pdf"  # pdf | json


@router.post("/compliance-report")
def compliance_report(body: ReportRequest,
                      user: str = Depends(require_roles("admin", "auditor", "security_analyst", "superadmin"))):
    from governance import compliance_pdf

    if body.framework not in compliance_pdf.FRAMEWORKS:
        raise HTTPException(400, f"unknown framework {body.framework!r}; "
                                 f"choose from {sorted(compliance_pdf.FRAMEWORKS)}")
    mapping = compliance_pdf.map_evidence(body.framework, body.evidence)
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    canonical = compliance_pdf.canonical_summary(body.framework, mapping, org=body.org, generated_at=now)
    signature = compliance_pdf.sign_summary(canonical, _signing_secret())
    if body.format == "json":
        return {"mapping": mapping, "generated_at": now, "signature": signature,
                "canonical": canonical.decode()}
    pdf = compliance_pdf.render_pdf(framework=body.framework, org=body.org,
                                    generated_at=now, mapping=mapping, signature=signature)
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition":
                             f'attachment; filename="compliance-{body.framework}.pdf"',
                             "X-Report-Signature": signature})


# ================================================================ 22 backup = #
class RetentionRequest(BaseModel):
    backups: list[dict]
    policy: dict[str, int] | None = None


@router.post("/backup/retention-plan")
def retention_plan(body: RetentionRequest,
                   user: str = Depends(require_roles("admin", "auditor", "superadmin"))):
    from governance import backup as bk

    return bk.apply_retention(body.backups, policy=body.policy)


class BackupCreateRequest(BaseModel):
    database_id: str
    engine: str = "reference"
    dump_b64: str = Field("", description="raw pg_dump/neo4j-admin output (b64)")
    wal_tail_b64: str | None = None
    sequence: int = 1


class _CreateBackend:
    def __init__(self, name: str, dump_bytes: bytes):
        self.name = name
        self._dump = dump_bytes

    def dump(self, database_id: str) -> bytes:
        return self._dump or f"REFERENCE-DUMP:{database_id}".encode()


@router.post("/backup/create")
def backup_create(body: BackupCreateRequest,
                  user: str = Depends(require_roles("admin", "superadmin"))):
    """Create an encrypted, signed backup artifact (reference dump; production
    wires pg_dump / neo4j-admin). Returns ciphertext + manifest for restore."""
    from governance import backup as bk

    raw = base64.b64decode(body.dump_b64) if body.dump_b64 else b""
    backend = _CreateBackend(body.engine, raw)
    wal = base64.b64decode(body.wal_tail_b64) if body.wal_tail_b64 else None
    res = bk.create_backup(backend=backend, database_id=body.database_id,
                           encryption_key=_fernet_key(), signing_secret=_signing_secret(),
                           sequence=body.sequence, wal_tail=wal)
    return {"manifest": res["manifest"],
            "ciphertext_b64": base64.b64encode(res["ciphertext"]).decode(),
            "plaintext_sha256": res["plaintext_preview_sha"]}


class BackupRestoreRequest(BaseModel):
    ciphertext_b64: str
    manifest: dict
    database_id: str
    target_point_in_time: str | None = None


class _RestoreBackend:
    """Reference restore backend: records intent without touching a real DB in
    the reference surface; production wires pg_dump/neo4j-admin here."""

    name = "reference"

    def restore(self, database_id: str, payload: bytes) -> dict:
        return {"database_id": database_id, "bytes": len(payload), "mode": "reference-noop"}

    def replay_wal(self, database_id, wal, pit):
        return {"database_id": database_id, "wal_bytes": len(wal), "point_in_time": pit}


@router.post("/backup/restore")
def backup_restore(body: BackupRestoreRequest,
                   user: str = Depends(require_roles("admin", "superadmin"))):
    from governance import backup as bk

    try:
        ciphertext = base64.b64decode(body.ciphertext_b64)
        out = bk.restore_backup(backend=_RestoreBackend(), database_id=body.database_id,
                                ciphertext=ciphertext, manifest=body.manifest,
                                encryption_key=_fernet_key(), signing_secret=_signing_secret(),
                                target_point_in_time=body.target_point_in_time)
    except bk.BackupError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(400, f"restore rejected: {exc}")
    return out


@router.get("/backup/encryption-key-info")
def backup_key_info(user: str = Depends(require_roles("admin", "superadmin"))):
    """Reports whether a persistent backup key is configured (never returns it)."""
    return {"persistent_key_configured": bool(os.environ.get("BACKUP_ENCRYPTION_KEY")),
            "algorithm": "Fernet (AES-128-CBC + HMAC-SHA256)",
            "manifest_signature": "HMAC-SHA256"}


# ============================================================== 25 attest == #
@router.get("/audit/attestation")
def audit_attestation(db: Session = Depends(get_db_session),
                      user: str = Depends(require_roles("admin", "auditor", "superadmin"))):
    """Verify the hash-chained audit log end to end and return a signed
    attestation report (tamper evidence + HMAC signature)."""
    from governance import audit_attest as aa
    from db.repositories.user_repository import verify_audit_chain

    base = verify_audit_chain(db)
    rows = list(db.execute(
        select(AuditLog).where(AuditLog.chain_sequence.is_not(None))
        .order_by(AuditLog.chain_sequence)).scalars())
    entries = [{"actor": r.actor, "action": r.action, "target_type": r.target_type,
                "target_id": r.target_id, "detail": r.detail, "ip_address": r.ip_address,
                "outcome": r.outcome, "created_at": r.created_at,
                "chain_sequence": r.chain_sequence, "previous_hash": r.previous_hash,
                "entry_hash": r.entry_hash} for r in rows]
    report = aa.build_attestation(entries, org=os.environ.get("ORG_NAME", "CryptoScan Tenant"),
                                  signer=user, secret=_signing_secret())
    report["chain_verification"] = base
    return report


@router.post("/audit/attestation/verify")
def audit_attestation_verify(payload: dict,
                             user: str = Depends(require_roles("admin", "auditor", "superadmin"))):
    from governance import audit_attest as aa

    return {"valid": aa.verify_attestation(payload, secret=_signing_secret())}


# ============================================================== 26 airgap == #
class AirgapDecisionRequest(BaseModel):
    url: str


@router.get("/airgap/status")
def airgap_status(user: str = Depends(require_roles("admin", "auditor", "security_analyst", "superadmin"))):
    from governance import airgap

    on = os.environ.get("AIRGAP_MODE", "false").lower() in ("1", "true", "yes", "on")
    allowlist = tuple(a.strip() for a in os.environ.get("AIRGAP_ALLOWLIST", "").split(",") if a.strip())
    return {"airgap": on, "allowlist": list(allowlist),
            "external_feed_hosts_blocked": list(airgap.EXTERNAL_FEED_HOSTS) if on else []}


@router.post("/airgap/network-decision")
def airgap_decision(body: AirgapDecisionRequest,
                    user: str = Depends(require_roles("admin", "auditor", "security_analyst", "superadmin"))):
    from governance import airgap

    on = os.environ.get("AIRGAP_MODE", "false").lower() in ("1", "true", "yes", "on")
    allowlist = tuple(a.strip() for a in os.environ.get("AIRGAP_ALLOWLIST", "").split(",") if a.strip())
    policy = airgap.AirgapPolicy(airgap=on, allowlist=allowlist)
    return airgap.network_decision(body.url, policy)


class FeedBundleRequest(BaseModel):
    bundle: dict


@router.post("/airgap/import-feed")
def airgap_import(body: FeedBundleRequest,
                  user: str = Depends(require_roles("admin", "superadmin"))):
    from governance import airgap

    sink = airgap.InMemoryFeedSink()
    try:
        result = airgap.import_bundle(body.bundle, secret=_signing_secret(), sink=sink)
    except airgap.AirgapError as exc:
        raise HTTPException(400, str(exc))
    result["staged_feeds"] = {k: len(v) for k, v in sink.feeds.items()}
    return result


# ============================================================== 27 OT ====== #
class OtDecodeRequest(BaseModel):
    frames: list[dict] = Field(..., description="Observed frames: {tcp_payload_hex|udp_payload_hex, dport}")


@router.post("/ot/decode")
def ot_decode(body: OtDecodeRequest,
              user: str = Depends(require_roles("admin", "auditor", "security_analyst", "ot_engineer", "superadmin"))):
    """Passively decode observed OT frames. Never sends probes (active=0)."""
    from network_scanner.passive import ot_protocols as ot

    frames = []
    for fr in body.frames:
        parsed: dict[str, Any] = {"dport": fr.get("dport")}
        if fr.get("tcp_payload_hex"):
            parsed["tcp_payload"] = bytes.fromhex(fr["tcp_payload_hex"])
        if fr.get("udp_payload_hex"):
            parsed["udp_payload"] = bytes.fromhex(fr["udp_payload_hex"])
        frames.append(parsed)
    return ot.analyze_capture(frames)
