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
from db.repositories.settings_repository import SettingsRepository

router = APIRouter(prefix="/resilience", tags=["resilience"])


def _signing_secret(db: Session | None = None) -> str:
    """Vault-ref > persisted settings key > HKDF-derived from platform master.
    Falls back to the dev ephemeral only when no platform SECRET_KEY exists."""
    from governance import keys
    try:
        repo = SettingsRepository(db) if db is not None else None
        return keys.signing_secret(settings_repo=repo)
    except Exception:
        return _ephemeral["secret"]


def _fernet_key(db: Session | None = None) -> bytes:
    """Vault-ref > persisted key > HKDF-derived Fernet key (stable restarts)."""
    from governance import keys
    try:
        repo = SettingsRepository(db) if db is not None else None
        return keys.backup_fernet_key(settings_repo=repo)
    except Exception:
        env = os.environ.get("BACKUP_ENCRYPTION_KEY")
        if env:
            return env.encode()
        global _EPHEMERAL_FERNET
        if _EPHEMERAL_FERNET is None:
            _EPHEMERAL_FERNET = Fernet.generate_key()
        return _EPHEMERAL_FERNET


def _airgap_policy():
    from governance import airgap

    on = os.environ.get("AIRGAP_MODE", "false").lower() in ("1", "true", "yes", "on")
    allowlist = tuple(a.strip() for a in os.environ.get("AIRGAP_ALLOWLIST", "").split(",") if a.strip())
    return airgap.AirgapPolicy(airgap=on, allowlist=allowlist)


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
                           encryption_key=_fernet_key(db), signing_secret=_signing_secret(db),
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
                                encryption_key=_fernet_key(db), signing_secret=_signing_secret(db),
                                target_point_in_time=body.target_point_in_time)
    except bk.BackupError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(400, f"restore rejected: {exc}")
    return out


class BackupRunRequest(BaseModel):
    databases: list[dict] = Field(..., description="[{database_id, engine, interval_hours}]")
    apply_retention: bool = True


@router.post("/backup/run-scheduled")
def backup_run_scheduled(body: BackupRunRequest,
                         user: str = Depends(require_roles("admin", "superadmin"))):
    """Run due backups across Postgres/Neo4j via injected command runners,
    persist encrypted artifacts to the reference store, then apply retention.

    In the reference surface the command runner is a deterministic stub that
    returns synthetic dumps (no real DB server required); production injects a
    subprocess runner wrapping pg_dump / neo4j-admin."""
    from governance import backup as bk
    from governance import backup_jobs as bj

    storage = _backup_storage()
    key = _fernet_key(db)
    secret = _signing_secret(db)

    def fake_runner_factory(engine: str):
        def runner(argv, stdin: bytes | None = None):
            tool = argv[0].split("/")[-1]
            if "dump" in tool or "backup" in tool:
                return bj.CommandResult(0, f"{engine.upper()}-DUMP:{':'.join(argv[-1:])}".encode())
            return bj.CommandResult(0, b"")
        return runner

    def backend_for(engine: str):
        runner = fake_runner_factory(engine)
        if engine == "neo4j":
            return bj.Neo4jBackend(runner=runner)
        return bj.PgDumpBackend(runner=runner)

    configs = [bj.BackupConfig(database_id=c["database_id"], engine=c.get("engine", "postgres"),
                               interval_hours=c.get("interval_hours", 24.0))
               for c in body.databases]
    results = bj.run_due_backups(configs=configs, backend_for=backend_for, storage=storage,
                                 encryption_key=key, signing_secret=secret)
    retention = None
    if body.apply_retention:
        retention = bj.execute_retention(storage=storage, signing_secret=secret)
    return {"ran": len([r for r in results if not r.get("skipped")]),
            "skipped": len([r for r in results if r.get("skipped")]),
            "results": results,
            "retention": ({"kept": retention["plan"]["kept"], "purged": retention["plan"]["purged"],
                           "deleted_keys": retention["deleted_keys"]} if retention else None),
            "stored_backups": len(storage.list_manifests())}


_BACKUP_STORE = None


def _backup_storage():
    global _BACKUP_STORE
    if _BACKUP_STORE is None:
        from governance.backup_jobs import InMemoryBackupStorage
        _BACKUP_STORE = InMemoryBackupStorage()
    return _BACKUP_STORE


@router.get("/backup/list")
def backup_list(user: str = Depends(require_roles("admin", "auditor", "superadmin"))):
    return {"backups": _backup_storage().list_manifests()}


class BackupSweepRequest(BaseModel):
    apply_retention: bool = True


@router.post("/backup/sweep")
def backup_sweep(body: BackupSweepRequest, db: Session = Depends(get_db_session),
                 user: str = Depends(require_roles("admin", "superadmin"))):
    """Run the scheduled-backup sweep (called by the worker tick or manually).

    Reads backup configs persisted in app_settings, runs due Postgres/Neo4j
    backups via the injected dump runner, applies retention, and persists the
    schedule state. In the reference surface the dump runner is deterministic;
    production injects a subprocess runner for pg_dump/neo4j-admin."""
    from governance import backup_jobs as bj
    from governance import backup_schedule as bsched

    storage = _backup_storage()
    repo = SettingsRepository(db)

    def fake_runner(argv, stdin: bytes | None = None):
        engine = "neo4j" if "neo4j" in argv[0] else "postgres"
        tool = argv[0].split("/")[-1]
        if "dump" in tool or "backup" in argv:
            return bj.CommandResult(0, f"{engine.upper()}-DUMP".encode(), b"")
        return bj.CommandResult(0, b"", b"")

    def backend_for(engine: str):
        if engine == "neo4j":
            return bj.Neo4jBackend(runner=fake_runner)
        return bj.PgDumpBackend(runner=fake_runner)

    try:
        out = bsched.run_due_backups_sweep(
            settings_repo=repo, backend_for=backend_for, storage=storage,
            encryption_key=_fernet_key(db), signing_secret=_signing_secret(db),
            apply_retention=body.apply_retention)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(400, f"backup sweep failed: {exc}")
    UserRepository(db).audit(user, "governance.backup_sweep", target_type="backup_schedule",
                             target_id="sweep", detail={"backed_up": out["backed_up"],
                                                       "failed": out["failed"],
                                                       "stored": out["stored_backups"]})
    db.commit()
    return out


class BackupConfigRequest(BaseModel):
    databases: list[dict] = Field(..., description="[{database_id, engine, interval_hours}]")


@router.post("/backup/config")
def backup_config(body: BackupConfigRequest, db: Session = Depends(get_db_session),
                  user: str = Depends(require_roles("admin", "superadmin"))):
    """Persist the scheduled-backup configuration in app_settings."""
    from governance import backup_schedule as bsched
    from governance import backup_jobs as bj

    repo = SettingsRepository(db)
    configs = [bj.BackupConfig(database_id=c["database_id"], engine=c.get("engine", "postgres"),
                               interval_hours=float(c.get("interval_hours", 24.0)))
               for c in body.databases]
    bsched.save_configs(repo, configs, by=user)
    db.commit()
    return {"ok": True, "configured": len(configs),
            "databases": [c.database_id for c in configs]}


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
                                  signer=user, secret=_signing_secret(db))
    report["chain_verification"] = base
    return report


@router.post("/audit/attestation/verify")
def audit_attestation_verify(payload: dict,
                             user: str = Depends(require_roles("admin", "auditor", "superadmin"))):
    from governance import audit_attest as aa

    return {"valid": aa.verify_attestation(payload, secret=_signing_secret())}


# ============================================================== 26 airgap == #
class AirgapDecisionRequest(BaseModel):
    url: str | None = None
    operation: str | None = None


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

    policy = _airgap_policy()
    if body.operation:
        try:
            return airgap.enforce_operation(body.operation, policy)
        except airgap.AirgapReadOnlyError as exc:
            return {"operation": body.operation, "airgap": True, "allowed": False,
                    "action": "BLOCK", "reason": str(exc)}
    if not body.url:
        raise HTTPException(400, "provide url or operation")
    return airgap.network_decision(body.url, policy)


class FeedBundleRequest(BaseModel):
    bundle: dict


@router.post("/airgap/import-feed")
def airgap_import(body: FeedBundleRequest, db: Session = Depends(get_db_session),
                  user: str = Depends(require_roles("admin", "superadmin"))):
    """Verify a signed offline feed bundle and ingest entries into the LIVE
    vulnerability store used by the scanners (idempotent merge)."""
    from governance import airgap, feed_store

    sink = feed_store.SqlVulnerabilityFeedSink(db)
    try:
        result = airgap.import_bundle(body.bundle, secret=_signing_secret(db), sink=sink)
    except airgap.AirgapError as exc:
        raise HTTPException(400, str(exc))
    UserRepository(db).audit(user, "airgap.feed_import", target_type="feed_bundle",
                             target_id=body.bundle.get("manifest", {}).get("bundle_sha256", "")[:16],
                             detail={"imported": result["imported"], "inserted": sink.inserted,
                                     "updated": sink.updated, "by_feed": result["by_feed"]})
    db.commit()
    result["rows_inserted"] = sink.inserted
    result["rows_updated"] = sink.updated
    return result


class FeedBuildRequest(BaseModel):
    entries: list[dict]
    created_by: str = "online-updater"


@router.post("/airgap/build-bundle")
def airgap_build(body: FeedBuildRequest,
                 user: str = Depends(require_roles("admin", "superadmin"))):
    """Build a signed offline feed bundle (run on an ONLINE host, then carry the
    artifact into the air-gapped network for import)."""
    from governance import airgap

    return airgap.build_bundle(body.entries, secret=_signing_secret(db), created_by=body.created_by)


# ============================================================== 27 OT ====== #
class OtDecodeRequest(BaseModel):
    frames: list[dict] = Field(..., description="Observed frames: {tcp_payload_hex|udp_payload_hex, dport}")


class OtPcapRequest(BaseModel):
    pcap_b64: str = Field(..., description="base64-encoded classic libpcap capture")


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


@router.post("/ot/ingest-pcap")
def ot_ingest_pcap(body: OtPcapRequest, db: Session = Depends(get_db_session),
                   user: str = Depends(require_roles("admin", "auditor", "security_analyst", "ot_engineer", "superadmin"))):
    """Parse an uploaded libpcap capture (passive), decode OT protocols, and
    PERSIST cleartext-engineering findings as audit-verifiable records. Never
    sends a packet — active_probes_sent is always 0."""
    from network_scanner.passive import ot_capture

    try:
        blob = base64.b64decode(body.pcap_b64)
        result = ot_capture.analyze_pcap(blob)
    except ot_capture.PcapError as exc:
        raise HTTPException(400, f"pcap parse failed: {exc}")
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(400, f"pcap ingest rejected: {exc}")

    # Persist each finding to the audit chain (deterministic record). Findings
    # surface to analysts via the audit trail + response; no false positives are
    # generated because a flag only exists when a decoded frame proved it.
    for f in result["findings"]:
        UserRepository(db).audit(
            user, "ot.cleartext_engineering", target_type="ot_finding",
            target_id=f"{f['protocol']}:{f['port']}",
            detail={"rule_id": f["rule_id"], "severity": f["severity"],
                    "service": f.get("service"), "flags": f["flags"],
                    "active_probes_sent": 0},
            outcome="DETECTED")
    db.commit()
    return result
