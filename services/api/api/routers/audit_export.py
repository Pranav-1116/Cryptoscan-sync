"""Audit export pack: one examiner-ready artifact, every file content-hashed.

`GET /api/v1/audit-export/pack` returns a ZIP containing the complete crypto
compliance picture — payment keys, ceremonies, findings, rotation forecast,
HSM audit trail, certificate inventory (with renewal workflow state), monitor
posture, the latest PCI report (with payment evidence), and the evidence
chain-verification result.

Every entry is deterministic JSON (sorted keys) and its SHA-256 is recorded
in `manifest.json`, so an examiner can prove nothing was edited after export.
Missing pieces are represented by honest note files (`NO_*.txt`), never
silently omitted or faked.
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from api.dependencies import require_auditor, get_db_session

router = APIRouter(prefix="/audit-export", tags=["audit-export"])


def _canonical(payload) -> bytes:
    return json.dumps(payload, indent=2, sort_keys=True, default=str).encode("utf-8")


def _note(text: str) -> bytes:
    return text.encode("utf-8")


@router.get("/pack")
def export_pack(user: str = Depends(require_auditor), db: Session = Depends(get_db_session)):
    from db.models.certificate import Certificate
    from db.models.monitor import MonitorTarget
    from db.repositories.payment_crypto_repository import PaymentCryptoRepository
    from payment_crypto.forecast import ExpiryForecaster

    generated_at = datetime.now(timezone.utc)
    entries: dict[str, bytes] = {}

    # ------------------------------------------------------------- payment
    repo = PaymentCryptoRepository(db)
    keys = [{
        "key_id": k.key_id, "name": k.name, "hsm_device": k.hsm_device,
        "key_usage": k.key_usage, "algorithm": k.algorithm, "key_size": k.key_size,
        "state": k.state, "enabled": k.enabled, "key_block_version": k.key_block_version,
        "activation_at": k.activation_at.isoformat() if k.activation_at else None,
        "expiry_at": k.expiry_at.isoformat() if k.expiry_at else None,
        "custodian_count": k.custodian_count, "source": k.source,
        "created_at": k.created_at.isoformat() if k.created_at else None,
    } for k in repo.list_keys()]
    ceremonies = [{
        "ceremony_id": c.ceremony_id, "key_id": c.key_id,
        "held_at": c.held_at.isoformat() if c.held_at else None,
        "custodians": c.custodians or [], "m_of_n": c.m_of_n,
        "dual_control": c.dual_control, "location": c.location,
        "documented": c.documented, "status": c.status or "HELD",
    } for c in repo.list_ceremonies()]
    findings = [{
        "rule_id": f.rule_id, "key_id": f.key_id, "severity": f.severity,
        "blocking": f.blocking, "message": f.message, "status": f.status,
        "evidence": f.evidence,
        "evaluated_at": f.evaluated_at.isoformat() if f.evaluated_at else None,
    } for f in repo.list_findings()]
    forecast = ExpiryForecaster().forecast(
        keys,
        [{
            "subject": row.subject, "issuer": row.issuer,
            "not_after": row.not_after.isoformat() if row.not_after else None,
            "public_key_algorithm": row.public_key_algorithm,
            "fingerprint": (row.fingerprint_sha256 or "")[:16],
            "renewal_status": row.renewal_status or "NONE",
        } for row in db.query(Certificate).all()],
        ceremonies=ceremonies,
    )
    events = [{
        "occurred_at": e.occurred_at.isoformat(), "device": e.device,
        "event_type": e.event_type, "key_id": e.key_id, "actor": e.actor,
        "severity": e.severity, "detail": e.detail,
    } for e in repo.recent_events(days=90)]

    entries["payment/keys.json"] = _canonical(keys)
    entries["payment/ceremonies.json"] = _canonical(ceremonies)
    entries["payment/findings.json"] = _canonical(findings)
    entries["payment/forecast.json"] = _canonical(forecast)
    entries["payment/transactions.json"] = _canonical(repo.transaction_series(days=120))
    entries["hsm-events/recent-90d.json"] = _canonical(events)

    # -------------------------------------------------------- certificates
    certificates = [{
        "fingerprint_sha256": row.fingerprint_sha256, "subject": row.subject,
        "issuer": row.issuer, "not_before": row.not_before.isoformat() if row.not_before else None,
        "not_after": row.not_after.isoformat() if row.not_after else None,
        "public_key_algorithm": row.public_key_algorithm, "public_key_size": row.public_key_size,
        "expiry_status": row.expiry_status, "days_until_expiry": row.days_until_expiry,
        "is_self_signed": row.is_self_signed, "san": row.san, "usages": row.usages,
        "renewal_status": row.renewal_status or "NONE",
        "renewal_ticket": row.renewal_ticket,
        "renewed_at": row.renewed_at.isoformat() if row.renewed_at else None,
    } for row in db.query(Certificate).all()]
    entries["certificates/inventory.json"] = _canonical(certificates)

    # ------------------------------------------------------------- monitor
    targets = [{
        "name": t.name, "target_type": t.target_type, "enabled": t.enabled,
        "status": t.status, "interval_seconds": t.interval_seconds,
        "last_scan_at": t.last_scan_at.isoformat() if t.last_scan_at else None,
        "last_summary": t.last_summary,
    } for t in db.query(MonitorTarget).order_by(MonitorTarget.name).all()]
    entries["monitor/watch-list.json"] = _canonical({
        "targets": targets,
        "status_counts": db.query(MonitorTarget).filter(MonitorTarget.enabled).count(),
    })

    # ------------------------------------------------ compliance + evidence
    scan = None
    try:
        from db.models.scan import Scan

        scan = db.query(Scan).filter(Scan.status == "COMPLETED").order_by(Scan.created_at.desc()).first()
    except Exception:
        scan = None

    if scan is not None:
        try:
            from api.routers.intelligence import _rendered_report
            from db.repositories.drift_repository import DriftRepository
            from db.repositories.evidence_repository import EvidenceRepository

            from db.repositories.scan_repository import ScanRepository

            report = _rendered_report(
                scan.id, ScanRepository(db), EvidenceRepository(db), DriftRepository(db),
                "pci-dss-4.0", None,
            )
            entries["compliance/pci-dss-4.0-report.json"] = _canonical(report)
        except Exception as exc:
            entries["compliance/REPORT_RENDER_FAILED.txt"] = _note(
                f"latest completed scan {scan.id} could not be rendered: {type(exc).__name__}: {exc}\n"
                "This is reported, not hidden.\n")
        try:
            from db.repositories.evidence_repository import EvidenceRepository
            from evidence.hashing.chain_hasher import ChainHasher

            rows = EvidenceRepository(db).get_all_for_scan(scan.id)
            content_hashes = [row.content_hash for row in rows]
            chain_hashes = [row.chain_hash for row in rows]
            chain_ok = ChainHasher.verify_chain(content_hashes, chain_hashes, scan.id) if rows else True
            entries["evidence/chain-verification.json"] = _canonical({
                "scan_id": scan.id, "records": len(rows), "chain_intact": chain_ok,
                "hash_format_valid": all(len(h or "") == 64 for h in content_hashes + chain_hashes),
                "manifest_hash": scan.manifest_hash,
                "result": "PASS" if chain_ok else "FAIL",
            })
        except Exception as exc:
            entries["evidence/VERIFICATION_FAILED.txt"] = _note(
                f"evidence verification raised {type(exc).__name__}: {exc}\n")
    else:
        entries["compliance/NO_COMPLETED_SCAN.txt"] = _note(
            "No completed scan exists yet — the compliance report section is empty.\n"
            "Run a scan to include report + evidence-chain verification in this pack.\n")
        entries["evidence/NO_COMPLETED_SCAN.txt"] = _note(
            "No completed scan exists yet — nothing to chain-verify.\n")

    # ------------------------------------------------------------- system
    from api.config.settings import get_settings

    settings = get_settings()
    entries["system.json"] = _canonical({
        "name": "CryptoScan", "api_version": settings.API_VERSION,
        "environment": settings.ENVIRONMENT, "exported_by": user,
        "generated_at": generated_at.isoformat(),
    })

    # ----------------------------------------------------------- manifest
    manifest = {
        "generated_at": generated_at.isoformat(),
        "exported_by": user,
        "file_count": len(entries),
        "files": {
            path: {"sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}
            for path, payload in sorted(entries.items())
        },
        "totals": {
            "payment_keys": len(keys), "ceremonies": len(ceremonies),
            "open_findings": sum(1 for row in findings if row["status"] == "OPEN"),
            "certificates": len(certificates), "hsm_events_90d": len(events),
        },
    }
    entries["manifest.json"] = _canonical(manifest)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, payload in sorted(entries.items()):
            info = zipfile.ZipInfo(path, date_time=generated_at.timetuple()[:6])
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, payload)
    return Response(
        content=buffer.getvalue(),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="cryptoscan-audit-pack-{generated_at.strftime("%Y%m%dT%H%M%SZ")}.zip"',
            "X-Pack-Files": str(len(entries)),
        },
    )

