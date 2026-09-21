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


@router.get("/exit-report")
def exit_report(
    client: str = "",
    window: str = "",
    owner: str = "",
    accepted_by: str = "",
    format: str = "json",
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    """PoC exit report — the engagement deliverable, generated from the SAME
    inventories the audit pack exports. Deterministic: identical estate +
    scope produce an identical SHA-256 (report_hash), so the client's audit
    function can re-verify independently."""
    from db.models.certificate import Certificate
    from db.models.crypto_asset import CryptoAsset
    from reporting.exit_report import build_exit_report, render_markdown

    cloud_sources = ("aws-kms", "azure-keyvault", "gcp-kms")
    cloud_rows = db.query(CryptoAsset).filter(
        CryptoAsset.source_language.in_(cloud_sources)).count()
    code_rows = db.query(CryptoAsset).filter(
        CryptoAsset.source_language.notin_(cloud_sources)).count()
    acm_rows = db.query(Certificate).filter(
        Certificate.extra["collector"].as_string() == "aws-acm").count()

    shor_families = sorted({
        row.algorithm
        for row in db.query(CryptoAsset.algorithm).distinct()
        if row.algorithm and (row.algorithm.startswith("RSA") or row.algorithm.startswith("ECDSA"))
    })

    from api.routers.telecom import _load_snapshot as _telecom_snapshot

    telecom = _telecom_snapshot() or {}
    telecom_rows = telecom.get("rows") or []
    estate = {
        "payment_keys": 0,  # payment surface counted below when present
        "certificates": db.query(Certificate).count(),
        "cloud_kms": {"assets": cloud_rows, "skipped": []},
        "acm": {"certificates": acm_rows, "skipped": []},
        "code": {"assets": code_rows},
        "roadmap_families": shor_families,
    }
    # telecom block only when a snapshot exists (scanned estate); honest zeros
    # for registered-but-empty passes, absent entirely when never scanned
    if telecom_rows or telecom.get("targets_registered"):
        estate["telecom"] = {
            "targets": int(telecom.get("targets_registered") or 0),
            "rows": len(telecom_rows),
            "critical": sum(1 for r in telecom_rows if r.get("severity") == "critical"),
        }


    try:
        payment_repo_count = 0
        from db.repositories.payment_crypto_repository import PaymentCryptoRepository

        payment_repo_count = len(PaymentCryptoRepository(db).list_keys())
    except Exception:
        payment_repo_count = 0
    estate["payment_keys"] = payment_repo_count

    report = build_exit_report(
        estate, client=client, window=window, owner=owner, accepted_by=accepted_by)
    if format == "md":
        return Response(
            content=render_markdown(report),
            media_type="text/markdown",
            headers={"X-Report-Hash": report["report_hash"]},
        )
    return report


@router.get("/engagement-archive")
def engagement_archive(
    client: str = "",
    window: str = "",
    owner: str = "",
    accepted_by: str = "",
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    """The final engagement deliverable in ONE archive: the examiner audit
    pack + the exit report (JSON + markdown, ONE report — same hash in both
    renderings) + a top-level manifest whose SHA-256s cover every file.
    Verified by the client with any sha256sum -c-style check."""
    import io
    import json as _json
    import zipfile
    from datetime import datetime, timezone

    from reporting.exit_report import render_markdown

    generated_at = datetime.now(timezone.utc)
    pack = export_pack(user=user, db=db)  # reuse the route function directly
    report = exit_report(client=client, window=window, owner=owner,
                         accepted_by=accepted_by, format="json", user=user, db=db)
    files: dict[str, bytes] = {
        "audit-pack.zip": pack.body,
        "exit-report.json": _json.dumps(report, indent=2, sort_keys=True,
                                        default=str).encode("utf-8"),
        "exit-report.md": render_markdown(report).encode("utf-8"),
    }
    manifest = {
        "kind": "cryptoscan-engagement-archive",
        "version": "1.0.0",
        "client": report["client"],
        "window": report.get("window", ""),
        "generated_at": generated_at.isoformat(),
        "exit_report_hash": report["report_hash"],
        "files": {
            name: {"sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}
            for name, payload in sorted(files.items())
        },
    }
    files["manifest.json"] = _json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, payload in sorted(files.items()):
            info = zipfile.ZipInfo(path, date_time=generated_at.timetuple()[:6])
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, payload)
    return Response(
        content=buffer.getvalue(),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="cryptoscan-engagement-{generated_at.strftime("%Y%m%dT%H%M%SZ")}.zip"',
            "X-Archive-Files": str(len(files)),
        },
    )


@router.get("/pack")
def export_pack(user: str = Depends(require_auditor), db: Session = Depends(get_db_session)):
    from db.models.certificate import Certificate
    from db.models.crypto_asset import CryptoAsset
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

    # ------------------------------------------- estate: cloud KMS + ACM
    # Whole-estate evidence: the same inventories the dashboards use, in the
    # examiner's hands — cloud KMS keys, ACM certificates, code findings and
    # the telecom posture. Empty areas get honest note files, never silence.
    cloud_sources = ("aws-kms", "azure-keyvault", "gcp-kms")
    cloud_rows = db.query(CryptoAsset).filter(
        CryptoAsset.source_language.in_(cloud_sources)).all()
    if cloud_rows:
        by_collector: dict[str, int] = {}
        for row in cloud_rows:
            name = str((row.extra or {}).get("collector") or row.source_language)
            by_collector[name] = by_collector.get(name, 0) + 1
        entries["cloud/kms-inventory.json"] = _canonical({
            "total": len(cloud_rows),
            "by_collector": dict(sorted(by_collector.items())),
            "assets": [{
                "algorithm": row.algorithm, "key_size": row.key_size,
                "purpose": row.purpose, "reference": row.file_path,
                "first_seen_at": (row.extra or {}).get("first_seen_at"),
                "last_seen_at": (row.extra or {}).get("last_seen_at"),
            } for row in cloud_rows],
        })
    else:
        entries["cloud/NO_CLOUD_INVENTORY.txt"] = _note(
            "No cloud KMS/KeyVault keys collected yet — run "
            "POST /api/v1/inventory/cloud/collect with provider credentials.\n")
    acm_rows = [row for row in db.query(Certificate).all()
                if str((row.extra or {}).get("collector") or "") == "aws-acm"]
    if acm_rows:
        entries["cloud/acm-certificates.json"] = _canonical({
            "total": len(acm_rows),
            "certificates": [{
                "fingerprint_sha256": row.fingerprint_sha256, "subject": row.subject,
                "not_after": row.not_after.isoformat() if row.not_after else None,
                "public_key_algorithm": row.public_key_algorithm,
                "public_key_size": row.public_key_size,
                "expiry_status": row.expiry_status,
                "arn": (row.extra or {}).get("arn"),
                "region": (row.extra or {}).get("region"),
            } for row in acm_rows],
        })
    else:
        entries["cloud/NO_ACM_CERTIFICATES.txt"] = _note(
            "No AWS ACM certificates collected yet — run POST "
            "/api/v1/inventory/cloud/collect with provider aws-acm.\n")

    # ------------------------------------------- estate: code findings
    code_rows = [row for row in db.query(CryptoAsset).all()
                 if row.source_language and row.source_language not in cloud_sources
                 and row.source_language != "cloud-kms"]
    if code_rows:
        by_language: dict[str, int] = {}
        by_algorithm: dict[str, int] = {}
        hardcoded = 0
        for row in code_rows:
            by_language[row.source_language] = by_language.get(row.source_language, 0) + 1
            by_algorithm[row.algorithm] = by_algorithm.get(row.algorithm, 0) + 1
            hardcoded += int(bool(row.is_hardcoded_key))
        entries["code/findings-summary.json"] = _canonical({
            "total": len(code_rows),
            "hardcoded_keys": hardcoded,
            "by_language": dict(sorted(by_language.items(), key=lambda kv: -kv[1])),
            "by_algorithm": dict(sorted(by_algorithm.items(), key=lambda kv: -kv[1])),
            "note": "Full deduplicated inventory with file/line evidence lives "
                    "in the CBOM surfaces; this is the examiner summary.",
        })
    else:
        entries["code/NO_CODE_FINDINGS.txt"] = _note(
            "No source-code crypto findings recorded yet — run a repository "
            "scan so the pipeline can populate the asset inventory.\n")

    # ------------------------------------------- estate: telecom posture
    from api.routers.telecom import _load_snapshot as _telecom_snapshot

    telecom = _telecom_snapshot()
    if telecom and (telecom.get("rows") or telecom.get("targets_registered")):
        entries["telecom/posture.json"] = _canonical({
            "generated_at": telecom.get("generated_at"),
            "scanner": telecom.get("scanner"),
            "targets_registered": telecom.get("targets_registered"),
            "rollup": telecom.get("rollup"),
            "rows": telecom.get("rows"),
        })
    else:
        entries["telecom/NO_TELECOM_DATA.txt"] = _note(
            "No telecom scan snapshot yet — register NF targets and run "
            "POST /api/v1/telecom/scan (see docs/runbooks/telecom-operations.md).\n")

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
            "cloud_kms_assets": len(cloud_rows),
            "cloud_acm_certificates": len(acm_rows),
            "code_finding_assets": len(code_rows),
            "telecom_targets": int((telecom or {}).get("targets_registered") or 0),
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


@router.get("/access-review")
def access_review(
    stale_after_days: int = 90,
    format: str = "json",
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    """Quarterly access-review report (SOC 2 CC6.3) — deterministic and signed.

    Everything a reviewer needs in one artifact: every account (roles, MFA
    state, last login), every API key (prefix only — never material), active
    session counts, and computed review signals (privileged accounts, active
    accounts without MFA, stale/no-login accounts, expired-but-unrevoked
    keys). ``report_hash`` is the SHA-256 of the canonical data (excluding
    ``generated_at``), so identical estate state produces an identical hash
    and a reviewer can detect any post-export edit.
    """
    from datetime import timedelta

    from sqlalchemy import func as _sa_func

    from api.security.rbac import normalize_roles
    from db.models.user import UserSession
    from db.repositories.api_key_repository import ApiKeyRepository
    from db.repositories.user_repository import UserRepository

    def _aware(dt: datetime | None) -> datetime | None:
        # SQLite returns naive datetimes, Postgres aware — normalize to UTC
        if dt is None:
            return None
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

    def _iso(dt: datetime | None) -> str | None:
        norm = _aware(dt)
        return norm.isoformat() if norm else None

    now = datetime.now(timezone.utc)
    stale_cutoff = now - timedelta(days=max(1, stale_after_days))

    users = []
    for u in UserRepository(db).list_users():
        users.append({
            "username": u.username,
            "display_name": u.display_name,
            "email": u.email,
            "roles": normalize_roles(u.roles.split(",")),
            "is_active": u.is_active,
            "mfa_enabled": u.mfa_enabled,
            "last_login_at": _iso(u.last_login_at),
            "locked_until": _iso(u.locked_until),
            "deleted_at": _iso(u.deleted_at),
        })

    keys = []
    for k in ApiKeyRepository(db).list_keys(include_revoked=True):
        keys.append({
            "name": k.name,
            "key_prefix": k.key_prefix,
            "created_by": k.created_by,
            "roles": normalize_roles((k.roles or "").split(",")),
            "tenant_id": k.tenant_id,
            "created_at": _iso(k.created_at),
            "expires_at": _iso(k.expires_at),
            "last_used_at": _iso(k.last_used_at),
            "revoked_at": _iso(k.revoked_at),
        })

    session_counts: dict[str, int] = {}
    for username, n in (
        db.query(UserSession.username, _sa_func.count(UserSession.token_hash))
        .filter(UserSession.revoked_at.is_(None), UserSession.expires_at > now)
        .group_by(UserSession.username)
        .all()
    ):
        session_counts[username] = int(n)

    privileged_roles = {"superadmin", "ciso"}
    active = [u for u in users if u["is_active"] and not u["deleted_at"]]
    signals = {
        "privileged_accounts": sorted(
            u["username"] for u in active
            if privileged_roles & set(u["roles"])),
        "active_without_mfa": sorted(
            u["username"] for u in active if not u["mfa_enabled"]),
        "stale_accounts": sorted(
            u["username"] for u in active
            if u["last_login_at"] is None
            or datetime.fromisoformat(u["last_login_at"]) < stale_cutoff),
        "never_logged_in": sorted(
            u["username"] for u in active if u["last_login_at"] is None),
        "locked_accounts": sorted(
            u["username"] for u in active if u["locked_until"]),
        "expired_keys_not_revoked": sorted(
            k["name"] for k in keys
            if k["expires_at"] and not k["revoked_at"]
            and datetime.fromisoformat(k["expires_at"]) < now),
        "revoked_keys": sum(1 for k in keys if k["revoked_at"]),
        "active_sessions_total": sum(session_counts.values()),
    }

    data = {
        "review": {
            "generated_at": now.isoformat(timespec="seconds"),
            "stale_after_days": max(1, stale_after_days),
            "requested_by": user,
        },
        "users": users,
        "api_keys": keys,
        "active_sessions": session_counts,
        "signals": signals,
        "totals": {
            "users": len(users),
            "active_users": len(active),
            "api_keys": len(keys),
        },
    }
    hashed = {k: v for k, v in data.items() if k != "review"}
    report_hash = hashlib.sha256(_canonical(hashed)).hexdigest()

    if format == "md":
        lines = [
            f"# Access review — {data['review']['generated_at']}",
            "",
            f"Requested by: {user} · stale threshold: {data['review']['stale_after_days']} days",
            f"Report hash: `{report_hash}`",
            "",
            f"Users: {data['totals']['users']} ({data['totals']['active_users']} active) · "
            f"API keys: {data['totals']['api_keys']} · "
            f"active sessions: {signals['active_sessions_total']}",
            "",
            "| username | roles | MFA | active | last login |",
            "|---|---|---|---|---|",
        ]
        for u in users:
            lines.append(
                f"| {u['username']} | {', '.join(u['roles']) or '-'} | "
                f"{'yes' if u['mfa_enabled'] else 'NO'} | "
                f"{'yes' if u['is_active'] else 'no'} | {u['last_login_at'] or 'never'} |")
        lines += ["", "## Review signals", ""]
        for name, value in signals.items():
            shown = ", ".join(value) if isinstance(value, list) else str(value)
            lines.append(f"- **{name}**: {shown or 'none'}")
        return Response(content="\n".join(lines), media_type="text/markdown",
                        headers={"X-Report-Hash": report_hash})
    return {**data, "report_hash": report_hash}
