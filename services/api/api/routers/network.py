"""TLS probe, certificate inventory, and scan targets."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from datetime import datetime, timezone

from api.dependencies import get_current_user, get_db_session, require_auditor
from db.repositories.certificate_repository import CertificateRepository
from db.repositories.intelligence_repository import IntelligenceRepository
from db.repositories.maturity_repository import MaturityRepository
from db.repositories.scan_run_repository import ScanRunRepository
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
    persist_run: bool = True  # store the run so /network/drift/latest can diff it later


class TargetCreate(BaseModel):
    endpoint: str
    system_id: str | None = None
    scan_frequency: str = "daily"
    enabled: bool = True


class FilesystemTlsRequest(BaseModel):
    path: str
    live: bool = False


class CertificateRenewalUpdate(BaseModel):
    status: str                 # NONE | PLANNED | IN_PROGRESS | DONE
    ticket: str | None = None   # change-management reference
    note: str | None = None


@router.get("/network/protocols")
def list_protocols(
    category: str | None = None,
    status: str | None = None,
    user: str = Depends(get_current_user),
):
    """Canonical network protocol/service catalog: every service the scanner
    can name, with port, transport, category, encryption and risk verdict.

    Read-only reference data (used by the network dashboards); filtering by
    ``category`` (web/mail/database/ot-ics/vpn/...) or ``status``
    (DISALLOWED/RESTRICTED/ALLOWED/DEPRECATED).
    """
    try:
        from shared_models.network_registry import catalog as protocol_catalog
    except Exception as exc:  # pragma: no cover - registry always present
        raise HTTPException(status_code=503, detail=f"protocol registry unavailable: {exc}")
    entries = protocol_catalog()
    if category:
        cat = category.lower()
        entries = [e for e in entries if e["category"].lower() == cat]
    if status:
        st = status.upper()
        entries = [e for e in entries if e["status"].upper() == st]
    counts: dict[str, int] = {}
    for e in entries:
        counts[e["status"]] = counts.get(e["status"], 0) + 1
    return {
        "count": len(entries),
        "status_counts": counts,
        "protocols": entries,
    }


@router.get("/certificates")
def list_certificates(
    expiring_days: int | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    rows = CertificateRepository(db).list_all(expiring_days=expiring_days)
    return {"certificates": [row.to_dict() for row in rows], "total_count": len(rows)}


@router.patch("/certificates/{fingerprint}/renewal")
def update_certificate_renewal(
    fingerprint: str,
    body: CertificateRenewalUpdate,
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    """Renewal workflow for one certificate (sha256 fingerprint)."""
    repo = CertificateRepository(db)
    try:
        row = repo.update_renewal(fingerprint, body.status, ticket=body.ticket, note=body.note)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if row is None:
        raise HTTPException(status_code=404, detail="Certificate not found")
    db.commit()
    return {
        "fingerprint_sha256": row.fingerprint_sha256,
        "subject": row.subject,
        "renewal_status": row.renewal_status,
        "renewal_ticket": row.renewal_ticket,
        "renewed_at": row.renewed_at.isoformat() if row.renewed_at else None,
    }


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
    ports: list[int] = Field(default_factory=list)  # empty => full DEFAULT_PORTS set
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
    """Sweep a CIDR for open service ports and optionally scan each endpoint.

    Sweeps the full crypto/risk-relevant port set (web, mail, remote admin,
    databases, OT/ICS, legacy cleartext) by default, and names + risk-scores
    every open service via the canonical network registry.
    """
    from network_scanner.discovery.subnet_discoverer import DEFAULT_PORTS, discover_subnet

    # SSRF guard: reject loopback/link-local/metadata/multicast/reserved and
    # non-CIDR inputs (URLs, hostnames, shell metacharacters) before sweeping.
    try:
        from api.security.target_validation import validate_network_target

        safe_cidr = validate_network_target(body.cidr)
    except Exception as exc:  # TargetValidationError
        raise HTTPException(status_code=400, detail={"error": "invalid_target", "reason": str(exc)})

    result = discover_subnet(safe_cidr, body.ports or list(DEFAULT_PORTS), timeout=body.timeout)
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


class SshScanRequest(BaseModel):
    hosts: list[str] = Field(default_factory=list)
    timeout: float = 8.0
    include_kex: bool = False  # also read each server's KEXINIT algorithm offer
    strict_kex: bool = False  # flag legacy (sha1/umac-64/ssh-rsa) offers too
    # baseline {endpoint: {key_type: fingerprint}} for TOFU drift; updated map is returned
    known_host_keys: dict[str, dict[str, str]] = Field(default_factory=dict)


@router.post("/network/ssh-scan")
def scan_ssh_hosts(body: SshScanRequest, user: str = Depends(get_current_user)):
    """SSH host-key scan with optional TOFU baselines (no DB state kept)."""
    from network_scanner.probing.ssh_kex import probe_ssh_kex_offer
    from network_scanner.probing.ssh_keyscan import scan_ssh_host_keys, split_ssh_target, ssh_probe_telemetry

    if not body.hosts:
        raise HTTPException(status_code=400, detail="hosts required")
    baselines = body.known_host_keys or {}
    findings = []
    updated: dict[str, dict[str, str]] = dict(baselines)
    for item in body.hosts:
        host, port = split_ssh_target(item)
        endpoint = f"{host}:{port}"
        finding = scan_ssh_host_keys(host, port, timeout=body.timeout, baseline=baselines.get(endpoint))
        if body.include_kex:
            offer = probe_ssh_kex_offer(host, port, timeout=body.timeout, strict=body.strict_kex)
            finding["kex_offer"] = offer
            merged = list(finding.get("policy_issues") or []) + list(offer.get("policy_issues") or [])
            finding["policy_issues"] = sorted(set(merged))
            if merged and not finding.get("compliance_issue"):
                finding["compliance_issue"] = finding["policy_issues"][0]
        findings.append(finding)
        drift = finding.get("key_drift") or {}
        if drift.get("observed"):
            updated[endpoint] = {str(k): str(v) for k, v in drift["observed"].items()}
    return {
        "findings": findings,
        "ssh_probe_telemetry": ssh_probe_telemetry(findings),
        "known_host_keys": updated,
    }


class AlertDispatchRequest(BaseModel):
    certificates: list[dict] = Field(default_factory=list)  # cert inventory rows
    notification_state: dict[str, str] = Field(default_factory=dict)  # fingerprint -> last-notified ISO
    days: int = 30


@router.post("/network/alerts/dispatch")
def dispatch_expiry_alerts(body: AlertDispatchRequest, user: str = Depends(get_current_user)):
    """Escalate expiry alerts (cooldown-aware) and fan out to configured channels.

    Webhook target + secret come from the environment
    (CRYPTOSCAN_ALERT_WEBHOOK_URL / _SECRET / _TIMEOUT / _RETRIES); the
    updated notification_state is returned for the caller to persist.
    """
    from network_scanner.alerts.escalation import route_alerts

    return route_alerts(body.certificates, state=body.notification_state, days=body.days)


class ScanDriftRequest(BaseModel):
    previous: dict  # scan_hosts-shaped result (findings + certificates)
    current: dict
    expiry_warn_days: int = 7


@router.post("/network/scan/drift")
def scan_drift(body: ScanDriftRequest, user: str = Depends(get_current_user)):
    """What changed between two scans: regressions, expiries, downgrades."""
    from network_scanner.reports.scan_drift import diff_scans

    return diff_scans(body.previous, body.current, expiry_warn_days=body.expiry_warn_days)


class MetricsRenderRequest(BaseModel):
    report: dict  # scan result, SSH scan, or drift report


@router.post("/network/metrics")
def render_metrics(body: MetricsRenderRequest, user: str = Depends(get_current_user)):
    """Render scan/SSH/drift telemetry as Prometheus text (format 0.0.4)."""
    from fastapi.responses import Response

    from network_scanner.reports.metrics import CONTENT_TYPE, render_prometheus

    return Response(content=render_prometheus(body.report), media_type=CONTENT_TYPE)


@router.get("/network/runs")
def list_scan_runs(
    limit: int = 20,
    target_kind: str | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Stored scan runs, newest first (metadata only — no result payloads)."""
    rows = ScanRunRepository(db).list_runs(limit=limit, target_kind=target_kind)
    return {
        "runs": [row.to_dict(exclude={"result"}) for row in rows],
        "total": ScanRunRepository(db).count_runs(target_kind=target_kind),
    }


@router.get("/network/runs/{run_id}")
def get_scan_run(run_id: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Fetch one stored scan run (full result payload)."""
    row = ScanRunRepository(db).get_run(run_id)
    if row is None:
        raise HTTPException(status_code=404, detail="run not found")
    return row.to_dict()


@router.get("/network/runs/{run_id}/metrics")
def scan_run_metrics(run_id: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Prometheus text for one stored run."""
    from fastapi.responses import Response

    from network_scanner.reports.metrics import CONTENT_TYPE, render_prometheus

    row = ScanRunRepository(db).get_run(run_id)
    if row is None:
        raise HTTPException(status_code=404, detail="run not found")
    return Response(content=render_prometheus(row.result or {}), media_type=CONTENT_TYPE)


@router.get("/network/drift/latest")
def latest_scan_drift(
    target_kind: str = "hosts",
    expiry_warn_days: int = 7,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Drift between the two most recent stored runs — no caller bookkeeping."""
    from network_scanner.reports.scan_drift import diff_scans

    runs = ScanRunRepository(db).latest_runs(count=2, target_kind=target_kind)
    if len(runs) < 2:
        return {
            "verdict": "UNCHANGED",
            "change_count": 0,
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "summary": {},
            "headline": None,
            "changes": [],
            "detail": f"only {len(runs)} stored run(s) for target_kind={target_kind}; drift needs two",
        }
    current, previous = runs[0], runs[1]
    report = diff_scans(previous.result or {}, current.result or {}, expiry_warn_days=expiry_warn_days)
    report["previous_run_id"] = previous.id
    report["current_run_id"] = current.id
    return report


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
    # SSRF guard: active TLS probes must never target loopback/cloud-metadata.
    # Hostnames and RFC1918 endpoints (the internal-asset use case) are allowed.
    try:
        from api.security.target_validation import TargetValidationError, validate_probe_targets

        safe_hosts = validate_probe_targets(body.hosts, label="hosts")
    except TargetValidationError as exc:
        raise HTTPException(status_code=400, detail={"error": "invalid_target",
                                                     "field": exc.field, "reason": str(exc)})
    result = NetworkTlsScanner(live=True, timeout=body.timeout, workers=body.workers).scan_hosts(
        safe_hosts,
        body.hosts,
        sni=body.sni,
        starttls=body.starttls,
        scan_versions=body.scan_versions,
        scan_ciphers=body.scan_ciphers,
        check_renegotiation=body.check_renegotiation,
        check_chain_sent=body.check_chain_sent,
        live_revocation=body.live_revocation,
    )
    if body.persist_run:
        try:
            result["run_id"] = ScanRunRepository(db).create_run(result).id
        except Exception as exc:  # noqa: BLE001 — storage must not sink the scan
            result["storage_error"] = f"{type(exc).__name__}: {exc}"[:200]
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
    # Path-traversal / secret-exposure guard: confine filesystem cert scans to
    # the allow-listed source roots (the same choke point as source scans).
    try:
        from api.security.target_validation import TargetValidationError, validate_source_target

        safe_path = validate_source_target(body.path, label="path")
    except TargetValidationError as exc:
        raise HTTPException(status_code=400, detail={"error": "invalid_target",
                                                     "field": "path", "reason": str(exc)})
    result = NetworkTlsScanner(live=body.live).scan_filesystem(safe_path)
    repo = CertificateRepository(db)
    usages = MaturityRepository(db)
    for cert in result.get("certificates") or []:
        if cert.get("fingerprint_sha256"):
            repo.upsert(cert)
    for usage in result.get("usages") or []:
        if usage.get("fingerprint_sha256") and usage.get("location"):
            usages.upsert_usage(usage["fingerprint_sha256"], usage["location"], usage.get("usage_type") or "UNKNOWN")
    return result
