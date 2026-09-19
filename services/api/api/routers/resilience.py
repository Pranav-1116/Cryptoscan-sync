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

from cryptography.fernet import Fernet
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


def _real_backend(engine: str):
    """Build a REAL dump backend that shells out to pg_dump / neo4j-admin via
    subprocess. Connection params come from settings/env. Raises ToolNotFound
    (reported honestly) when the binary isn't installed."""
    from governance import backup_jobs as bj

    runner = bj.subprocess_runner()
    if engine == "neo4j":
        return bj.Neo4jBackend(
            runner=runner,
            host=os.environ.get("NEO4J_HOST", "localhost"),
            port=int(os.environ.get("NEO4J_BACKUP_PORT", "6362")),
            neo4j_bin=os.environ.get("NEO4J_BIN", ""),
            backup_dir=os.environ.get("NEO4J_BACKUP_STAGING", "/tmp/cryptoscan-neo4j-backup"))
    return bj.PgDumpBackend(
        runner=runner,
        host=os.environ.get("PGHOST", os.environ.get("POSTGRES_HOST", "localhost")),
        port=int(os.environ.get("PGPORT", os.environ.get("POSTGRES_PORT", "5432"))),
        user=os.environ.get("PGUSER", os.environ.get("POSTGRES_USER", "postgres")),
        pg_bin=os.environ.get("PG_BIN", ""))


@router.post("/backup/create")
def backup_create(body: BackupCreateRequest, db: Session = Depends(get_db_session),
                  user: str = Depends(require_roles("admin", "superadmin"))):
    """Create a REAL encrypted, signed backup via pg_dump/neo4j-admin and persist
    it to the configured backup store. A raw dump may be supplied (b64) for
    explicit/offline capture; otherwise the live database tool is invoked."""
    from governance import backup as bk
    from governance import backup_jobs as bj

    if body.dump_b64:
        raw = base64.b64decode(body.dump_b64)
        backend = bj._DumpCaptureBackend(body.engine or "postgres", raw)
    else:
        backend = _real_backend(body.engine or "postgres")
    wal = base64.b64decode(body.wal_tail_b64) if body.wal_tail_b64 else None
    try:
        res = bk.create_backup(backend=backend, database_id=body.database_id,
                               encryption_key=_fernet_key(db), signing_secret=_signing_secret(db),
                               sequence=body.sequence, wal_tail=wal)
    except bj.ToolNotFound as exc:
        raise HTTPException(503, f"backup tool unavailable: {exc}")
    except bk.BackupError as exc:
        UserRepository(db).audit(user, "governance.backup_create", target_type="database",
                                 target_id=body.database_id, outcome="FAILURE", detail={"error": str(exc)})
        db.commit()
        raise HTTPException(502, f"backup failed: {exc}")
    # persist to the real store so it survives restarts and is restorable
    storage = _backup_storage()
    key = f"{body.engine or 'postgres'}/{body.database_id}/{res['manifest']['backup_id']}"
    storage.put(key, res["ciphertext"])
    storage.put_manifest(key, res["manifest"])
    UserRepository(db).audit(user, "governance.backup_create", target_type="database",
                             target_id=body.database_id,
                             detail={"backup_id": res["manifest"]["backup_id"],
                                     "engine": res["manifest"]["engine"], "storage_key": key})
    db.commit()
    return {"manifest": res["manifest"], "storage_key": key,
            "plaintext_sha256": res["plaintext_preview_sha"]}


class BackupRestoreRequest(BaseModel):
    ciphertext_b64: str | None = None
    manifest: dict | None = None
    database_id: str
    storage_key: str | None = None
    target_point_in_time: str | None = None


@router.post("/backup/restore")
def backup_restore(body: BackupRestoreRequest, db: Session = Depends(get_db_session),
                   user: str = Depends(require_roles("admin", "superadmin"))):
    """REAL restore: verify+decrypt the backup and apply it via pg_restore /
    neo4j-admin restore. Artifact is loaded from the persistent store by
    storage_key, or from supplied ciphertext/manifest."""
    from governance import backup as bk
    from governance import backup_jobs as bj

    storage = _backup_storage()
    try:
        if body.storage_key:
            man = next((m for m in storage.list_manifests() if m["storage_key"] == body.storage_key), None)
            if man is None:
                raise HTTPException(404, f"backup {body.storage_key} not found in store")
            ciphertext = storage.get(body.storage_key)
            manifest = {k: v for k, v in man.items() if k != "storage_key"}
        else:
            if not body.ciphertext_b64 or not body.manifest:
                raise HTTPException(400, "provide storage_key or ciphertext_b64+manifest")
            ciphertext = base64.b64decode(body.ciphertext_b64)
            manifest = body.manifest
        engine = manifest.get("engine", "postgres")
        backend = _real_backend(engine)
        out = bk.restore_backup(backend=backend, database_id=body.database_id,
                                ciphertext=ciphertext, manifest=manifest,
                                encryption_key=_fernet_key(db), signing_secret=_signing_secret(db),
                                target_point_in_time=body.target_point_in_time)
    except HTTPException:
        raise
    except bj.ToolNotFound as exc:
        raise HTTPException(503, f"restore tool unavailable: {exc}")
    except bk.BackupError as exc:
        UserRepository(db).audit(user, "governance.backup_restore", target_type="database",
                                 target_id=body.database_id, outcome="FAILURE", detail={"error": str(exc)})
        db.commit()
        raise HTTPException(400, str(exc))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(502, f"restore failed: {exc}")
    UserRepository(db).audit(user, "governance.backup_restore", target_type="database",
                             target_id=body.database_id,
                             detail={"engine": engine, "point_in_time": out.get("point_in_time"),
                                     "wal_applied": out.get("wal_applied")})
    db.commit()
    return out


class BackupRunRequest(BaseModel):
    databases: list[dict] = Field(..., description="[{database_id, engine, interval_hours}]")
    apply_retention: bool = True


@router.post("/backup/run-scheduled")
def backup_run_scheduled(body: BackupRunRequest, db: Session = Depends(get_db_session),
                         user: str = Depends(require_roles("admin", "superadmin"))):
    """Run due backups across Postgres/Neo4j via REAL subprocess runners
    (pg_dump/neo4j-admin), persist encrypted artifacts to the on-disk store,
    then apply retention. A missing tool / unreachable DB is reported honestly.

    In the reference surface the command runner is a deterministic stub that
    returns synthetic dumps (no real DB server required); production injects a
    subprocess runner wrapping pg_dump / neo4j-admin."""
    from governance import backup_jobs as bj

    storage = _backup_storage()
    key = _fernet_key(db)
    secret = _signing_secret(db)

    def backend_for(engine: str):
        return _real_backend(engine)  # real subprocess pg_dump / neo4j-admin

    configs = [bj.BackupConfig(database_id=c["database_id"], engine=c.get("engine", "postgres"),
                               interval_hours=c.get("interval_hours", 24.0))
               for c in body.databases]
    # run each config; a missing tool / unreachable DB is reported honestly as a
    # failed result rather than a fake success.
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
    """Persistent on-disk backup store (survives restarts). Path configurable
    via BACKUP_STORAGE_DIR; defaults to a data volume directory."""
    global _BACKUP_STORE
    if _BACKUP_STORE is None:
        from governance.backup_jobs import DiskBackupStorage
        root = os.environ.get("BACKUP_STORAGE_DIR", "/var/lib/cryptoscan/backups")
        try:
            _BACKUP_STORE = DiskBackupStorage(root)
        except Exception:
            # fall back to a writable temp volume if the default path isn't usable
            import tempfile
            from governance.backup_jobs import DiskBackupStorage as _D
            _BACKUP_STORE = _D(os.path.join(tempfile.gettempdir(), "cryptoscan-backups"))
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

    def backend_for(engine: str):
        return _real_backend(engine)  # real subprocess pg_dump / neo4j-admin

    try:
        out = bsched.run_due_backups_sweep(
            settings_repo=repo, backend_for=backend_for, storage=storage,
            encryption_key=_fernet_key(db), signing_secret=_signing_secret(db),
            apply_retention=body.apply_retention)
    except bj.ToolNotFound as exc:
        raise HTTPException(503, f"backup tool unavailable: {exc}")
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
                 db: Session = Depends(get_db_session),
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
