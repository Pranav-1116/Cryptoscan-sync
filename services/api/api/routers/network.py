"""TLS probe, certificate inventory, and scan targets."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from datetime import datetime, timezone

from api.dependencies import TenantContext, get_current_user, get_db_session, require_auditor
from api.security.estate_history import history_context
from api.security.audit_diff import write_audited_diff
from api.security.network_collection import (
    NetworkHostRequest,
    admit_network,
    checked_hosts,
    meter_network,
    network_run,
    persist_network,
    network_coverage,
    network_context,
)
from db.tenancy import current_tenant
from db.repositories.certificate_repository import CertificateRepository
from db.repositories.intelligence_repository import IntelligenceRepository
from db.repositories.maturity_repository import MaturityRepository
from db.repositories.scan_run_repository import ScanRunRepository
from network_scanner.certificates.crl_checker import check_crl
from network_scanner.certificates.ocsp_checker import check_ocsp
from network_scanner.core.scanner import NetworkTlsScanner
from network_scanner.core.scheduler import due_targets, next_scan_time

router = APIRouter(tags=["network"])


class NetworkInventoryWrite(BaseModel):
    inventory: dict[str, Any]
    inventory_id: str = Field(default="default", min_length=1, max_length=160)
    status: Literal["DRAFT", "IN_REVIEW", "APPROVED", "EXPIRED"] = "DRAFT"
    source: Literal["SNMP", "SSH", "API", "NMAP", "CONFIG_IMPORT", "MANUAL", "MIXED"] = "MANUAL"
    reviewed_by: str | None = Field(default=None, max_length=160)
    review_notes: str | None = None


class NetworkInventoryDiscoveryRequest(BaseModel):
    scope_specs: list[str | dict[str, Any]] = Field(default_factory=list, min_length=1, max_length=100)
    inventory_id: str = Field(default="default", min_length=1, max_length=160)
    authorization_scope: str = Field(default="", max_length=200)
    plugins: list[str] = Field(default_factory=list, max_length=10)


class NetworkInventoryAnalysisRequest(BaseModel):
    inventory: dict[str, Any]


class HostScanRequest(NetworkHostRequest):
    # Keep the old field discoverable, but never permit unrecorded live work.
    persist_run: Literal[True] = True


class TargetCreate(BaseModel):
    endpoint: str
    system_id: str | None = None
    scan_frequency: str = "daily"
    enabled: bool = True


class FilesystemTlsRequest(BaseModel):
    path: str
    live: bool = False


class CertificateRenewalUpdate(BaseModel):
    status: str  # NONE | PLANNED | IN_PROGRESS | DONE
    ticket: str | None = None  # change-management reference
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


@router.get("/certificates/composite")
def list_composite_certificates(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Composite / hybrid certificate inventory (audit 59).

    Certificates that pair a post-quantum algorithm with a classical one
    (e.g. ML-DSA-65 + ECDSA-P384) in a single identifier. Detection runs on
    ingest against the registered composite OID arcs and algorithm-name
    registry — a composite scheme outside both registries is NOT reported
    here (unknown identifiers stay unknown, they are not guessed).
    """
    rows = CertificateRepository(db).list_composite()
    entries = []
    scheme_counts: dict[str, int] = {}
    for row in rows:
        composite = (row.extra or {}).get("composite") or {}
        scheme_counts[composite.get("scheme") or "unknown"] = (
            scheme_counts.get(composite.get("scheme") or "unknown", 0) + 1
        )
        entries.append(
            {
                "fingerprint_sha256": row.fingerprint_sha256,
                "subject": row.subject,
                "issuer": row.issuer,
                "not_after": row.not_after.isoformat() if row.not_after else None,
                "days_until_expiry": row.days_until_expiry,
                "public_key_algorithm": row.public_key_algorithm,
                "composite": composite,
            }
        )
    return {
        "model": "composite-certificates/read-projection-v1",
        "count": len(entries),
        "scheme_counts": scheme_counts,
        "certificates": entries,
        "detection": "registered composite OID arcs (2.16.840.1.114027.80/81/82) "
        "and the composite name registry; unknown identifiers are "
        "not reported as composite",
    }


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
        current = repo.get_by_fingerprint(fingerprint)
        before = (
            {
                "renewal_status": current.renewal_status,
                "renewal_ticket": current.renewal_ticket,
                "renewal_note": current.renewal_note,
            }
            if current is not None
            else {}
        )
        row = repo.update_renewal(fingerprint, body.status, ticket=body.ticket, note=body.note)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if row is None:
        raise HTTPException(status_code=404, detail="Certificate not found")
    db.commit()
    # field-level audit diff (audit 78): the renewal workflow changes state,
    # so the change is audited like every other mutation
    write_audited_diff(
        db,
        user,
        "certificate.renewal_update",
        target_type="certificate",
        target_id=row.fingerprint_sha256,
        before=before,
        after={
            "renewal_status": row.renewal_status,
            "renewal_ticket": row.renewal_ticket,
            "renewal_note": row.renewal_note,
        },
    )
    return {
        "fingerprint_sha256": row.fingerprint_sha256,
        "subject": row.subject,
        "renewal_status": row.renewal_status,
        "renewal_ticket": row.renewal_ticket,
        "renewed_at": row.renewed_at.isoformat() if row.renewed_at else None,
    }


@router.get("/certificates/expiry-calendar")
def certificate_expiry_calendar(
    include_renewed: bool = False,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """SLA-tiered certificate expiry calendar.

    Deterministic day-based buckets: expired / critical (0-7d) / warning
    (8-30d) / scheduled (31-90d) / healthy (>90d). Remaining days are
    re-computed live from ``not_after`` so stale scans never mislead.
    Certs already marked renewed are excluded unless ``include_renewed=true``.
    """
    from network_scanner.certificates.expiry_calendar import build_expiry_calendar

    rows = CertificateRepository(db).list_all()
    certs = [row.to_dict() for row in rows]
    if not include_renewed:
        certs = [c for c in certs if (c.get("renewal_status") or "").lower() not in ("renewed", "completed", "done")]
    calendar = build_expiry_calendar(certs)
    # return the summary counts/tier structure plus entries; drop nothing
    return calendar


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
        source="manual",
    )
    return row.to_dict()


@router.get("/network/due")
def list_due(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    rows = IntelligenceRepository(db).list_targets()
    due = due_targets([row.to_dict() for row in rows])
    return {"targets": due, "total_count": len(due)}


@router.post("/network/run-due")
def run_due(
    user: str = Depends(get_current_user), db: Session = Depends(get_db_session), _ctx=Depends(network_context)
):
    # A bank may read shared platform inventory, but cannot execute/advance
    # platform-owned or foreign scheduled work. Select the exact estate.
    from db.models.network_scan_target import NetworkScanTarget

    rows = db.query(NetworkScanTarget).filter(NetworkScanTarget.tenant_id == current_tenant()).all()
    due = due_targets([row.to_dict() for row in rows])
    if not due:
        # No executor and no run, but stop/outage policy still applies.
        from api.security.scan_admission import admit_scan

        admit_scan(active_probing_requested=True)
        return {"scanned": 0, "findings": []}
    hosts = checked_hosts([item["endpoint"] for item in due if item.get("endpoint")])
    admission = admit_network(hosts)
    meter_network(db, hosts)
    with network_run(
        db,
        user=user,
        target=",".join(hosts)[:2000],
        admission=admission,
        kind="scheduled",
        profile={"workers": 8, "timeout": 5.0, "scan_versions": False, "scan_ciphers": False},
    ) as run:
        result = NetworkTlsScanner(live=True, workers=8).scan_hosts(hosts)
        result = persist_network(db, result, run, kind="scheduled")
        # An unsuccessful/incomplete probe is not fresh observation. Keep the
        # batch due unless telemetry reports every probe successfully observed.
        # Weak-crypto findings may make a fully observed batch PARTIAL; that
        # is a fresh observation, not a safe posture or a reason to retry-spin.
        telemetry = result.get("probe_telemetry") or {}
        if (
            telemetry.get("status") in {"OK", "PARTIAL"}
            and telemetry.get("probed") == len(hosts)
            and telemetry.get("ok") == len(hosts)
        ):
            now = datetime.now(timezone.utc)
            for row in rows:
                if row.endpoint in {item["endpoint"] for item in due}:
                    row.last_scan_time = now
                    row.next_scan_time = next_scan_time(now, row.scan_frequency)
        result["scanned"] = len(hosts)
        run.succeed(coverage=network_coverage(result))
    return result


class SubnetDiscoverRequest(BaseModel):
    cidr: str
    ports: list[Annotated[int, Field(ge=1, le=65535)]] = Field(
        default_factory=list, max_length=64
    )  # empty => DEFAULT_PORTS
    timeout: float = Field(default=1.5, gt=0, le=30, allow_inf_nan=False)
    scan: bool = True
    register: bool = False  # upsert discovered endpoints into the due-scan rotation
    scan_frequency: str = "daily"  # hourly | daily | weekly | monthly
    scan_versions: bool = False
    scan_ciphers: bool = False
    check_renegotiation: bool = False
    check_chain_sent: bool = False
    live_revocation: bool = False
    workers: int | None = Field(default=None, ge=1, le=32)


@router.post("/network/discover")
def discover_subnet_endpoints(
    body: SubnetDiscoverRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
    _ctx=Depends(network_context),
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

    # A CIDR sweep is active probing by nature: fail-closed admission first
    # (emergency stop / OT passive boundary), then execution-time
    # authorization — the range must sit inside the tenant's declared
    # network scope (or be a registered single host). Authorized at
    # registration is not authorized at execution: both halves are checked.
    from api.security.scan_admission import authorize_network_sweep

    ports = sorted(set(body.ports or list(DEFAULT_PORTS)))
    admission = admit_network([safe_cidr], protocol="tcp", ports=ports)
    authorized, auth_reason = authorize_network_sweep(safe_cidr)
    if not authorized:
        raise HTTPException(403, detail={"error": "target_outside_authorized_scope", "reason": auth_reason})
    with network_run(
        db,
        user=user,
        target=safe_cidr,
        admission=admission,
        kind="discovery",
        profile={**body.model_dump(exclude={"cidr"}), "ports": ports, "workers": body.workers or 8},
    ) as run:
        result = discover_subnet(safe_cidr, ports, timeout=body.timeout, workers=body.workers or 8)
        if result.get("error"):
            raise HTTPException(422, detail="Network discovery could not evaluate the requested scope")
        endpoints = checked_hosts(result["endpoints"]) if result.get("endpoints") else []
        # A sweep is not authorization for a subsequent TLS phase. Re-read
        # policy, validate all discovered endpoints, and check containment.
        import ipaddress

        scope = ipaddress.ip_network(safe_cidr)
        for endpoint in endpoints:
            host = endpoint.rsplit(":", 1)[0].strip("[]")
            if ipaddress.ip_address(host) not in scope:
                raise HTTPException(422, detail="Discovery returned an endpoint outside the admitted scope")
        if body.scan and endpoints:
            tls_admission = admit_network(endpoints)
            meter_network(db, endpoints)
            # Charge admitted attempts before the second external phase, as
            # direct/due paths do in their initial durable-job commit.
            db.commit()
            scanned = NetworkTlsScanner(live=True, workers=body.workers or 8).scan_hosts(
                endpoints,
                scan_versions=body.scan_versions,
                scan_ciphers=body.scan_ciphers,
                check_renegotiation=body.check_renegotiation,
                check_chain_sent=body.check_chain_sent,
                live_revocation=body.live_revocation,
            )
            stored = persist_network(
                db, {**scanned, "discovery": result}, run, kind="discovery_tls", phase_admission=tls_admission
            )
            result = {
                **result,
                "scan": {key: scanned.get(key) for key in ("probe_telemetry", "certificates", "alerts")},
                "job_id": stored["job_id"],
                "run_id": stored["run_id"],
                "probe_telemetry": scanned.get("probe_telemetry"),
            }
        else:
            # Discovery is durable but does not masquerade as a TLS probe.
            result = persist_network(db, result, run, kind="discovery")
        if body.register and endpoints:
            admit_network(endpoints, protocol="tcp")
            from network_scanner.discovery.registration import register_targets

            intel = IntelligenceRepository(db)
            result["registration"] = register_targets(
                intel,
                endpoints,
                scan_frequency=body.scan_frequency,
                existing={row.endpoint for row in intel.list_targets()},
            )
        run.succeed(coverage=network_coverage(result))
    return result


class SshScanRequest(BaseModel):
    hosts: list[str] = Field(default_factory=list, max_length=256)
    timeout: float = Field(default=8.0, gt=0, le=30, allow_inf_nan=False)
    include_kex: bool = False  # also read each server's KEXINIT algorithm offer
    strict_kex: bool = False  # flag legacy (sha1/umac-64/ssh-rsa) offers too
    # baseline {endpoint: {key_type: fingerprint}} for TOFU drift; updated map is returned
    known_host_keys: dict[str, dict[str, str]] = Field(default_factory=dict)


@router.post("/network/ssh-scan")
def scan_ssh_hosts(
    body: SshScanRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
    _ctx=Depends(network_context),
):
    """Persist each admitted SSH attempt and its bounded host-key/KEX observations."""
    from network_scanner.probing.ssh_kex import probe_ssh_kex_offer
    from network_scanner.probing.ssh_keyscan import scan_ssh_host_keys, split_ssh_target, ssh_probe_telemetry

    if not body.hosts:
        raise HTTPException(status_code=400, detail="hosts required")
    # Banner/KEX reads are live probes: same admission as every other active
    # surface. Emergency stop and the OT passive boundary apply here too.
    endpoints = []
    try:
        for item in body.hosts:
            host, port = split_ssh_target(item)
            endpoints.append(f"[{host}]:{port}" if ":" in host else f"{host}:{port}")
    except (TypeError, ValueError) as exc:
        raise HTTPException(422, detail="Invalid SSH target") from exc
    endpoints = checked_hosts(endpoints)
    admission = admit_network(endpoints, protocol="ssh")
    with network_run(
        db,
        user=user,
        target=",".join(endpoints),
        admission=admission,
        kind="ssh",
        profile={**body.model_dump(exclude={"known_host_keys"}), "baseline_source": "CALLER_SUPPLIED_UNVERIFIED"},
    ) as run:
        try:
            meter_network(db, endpoints, detail="admitted SSH host-key/KEX collection attempt")
            baselines = body.known_host_keys or {}
            findings = []
            phases = []
            updated: dict[str, dict[str, str]] = dict(baselines)
            for item in endpoints:
                host, port = split_ssh_target(item)
                endpoint = f"{host}:{port}"
                phases.append({"phase": "host_keys", "admission": admit_network([item], protocol="ssh")})
                finding = scan_ssh_host_keys(host, port, timeout=body.timeout, baseline=baselines.get(endpoint))
                if body.include_kex:
                    phases.append({"phase": "kex", "admission": admit_network([item], protocol="ssh")})
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
            telemetry = ssh_probe_telemetry(findings)
            result = persist_network(
                db,
                {
                    "findings": findings,
                    "known_host_keys": updated,
                    "ssh_probe_telemetry": telemetry,
                    "probe_telemetry": telemetry,
                    "admission": admission,
                },
                run,
                kind="ssh",
                phase_admission=phases,
                collection_metadata={
                    "protocol": "ssh",
                    "durable": True,
                    "coverage": "HOST_KEY_AND_OPTIONAL_KEX_ONLY",
                    "baseline_source": "CALLER_SUPPLIED_UNVERIFIED",
                },
            )
            run.succeed(coverage={**network_coverage(result), "protocol": "ssh"})
            return result
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(503, detail="SSH collection/receipt unavailable; inspect the durable job") from exc


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
    ctx: TenantContext = Depends(history_context),
):
    """Stored scan runs, newest first (metadata only — no result payloads)."""
    rows = ScanRunRepository(db).list_runs(limit=limit, target_kind=target_kind, owner=ctx.tenant_id)
    return {
        "runs": [row.to_dict(exclude={"result"}) for row in rows],
        "total": ScanRunRepository(db).count_runs(target_kind=target_kind, owner=ctx.tenant_id),
    }


@router.get("/network/runs/{run_id}")
def get_scan_run(
    run_id: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
    ctx: TenantContext = Depends(history_context),
):
    """Fetch one stored scan run (full result payload)."""
    row = ScanRunRepository(db).get_run(run_id, owner=ctx.tenant_id)
    if row is None:
        raise HTTPException(status_code=404, detail="run not found")
    return row.to_dict()


@router.get("/network/runs/{run_id}/metrics")
def scan_run_metrics(
    run_id: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
    ctx: TenantContext = Depends(history_context),
):
    """Prometheus text for one stored run."""
    from fastapi.responses import Response

    from network_scanner.reports.metrics import CONTENT_TYPE, render_prometheus

    row = ScanRunRepository(db).get_run(run_id, owner=ctx.tenant_id)
    if row is None:
        raise HTTPException(status_code=404, detail="run not found")
    return Response(content=render_prometheus(row.result or {}), media_type=CONTENT_TYPE)


@router.get("/network/drift/latest")
def latest_scan_drift(
    target_kind: str = "hosts",
    expiry_warn_days: int = 7,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
    ctx: TenantContext = Depends(history_context),
):
    """Drift between the two most recent stored runs — no caller bookkeeping."""
    from network_scanner.reports.scan_drift import diff_scans

    runs = ScanRunRepository(db).latest_runs(count=2, target_kind=target_kind, owner=ctx.tenant_id)
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
    row = repo.upsert(
        {
            "fingerprint_sha256": row.fingerprint_sha256,
            "revocation_status": chosen.get("status"),
            "revocation_method": chosen.get("method"),
            "ocsp_url": (ocsp.get("urls") or [None])[0],
            "crl_url": (crl.get("urls") or [None])[0],
            "revocation": {"ocsp": ocsp, "crl": crl},
        }
    )
    # the check RAN — record when, even when neither probe could
    # determine a status (no AIA URLs): "checked, undetermined" is a
    # different fact from "never checked" (§5, round 74)
    row.revocation_checked_at = datetime.now(timezone.utc)
    db.commit()
    return {"ocsp": ocsp, "crl": crl}


@router.post("/network/scan")
def scan_network(
    body: HostScanRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
    _ctx=Depends(network_context),
):
    hosts = checked_hosts(body.hosts)
    admission = admit_network(hosts)
    meter_network(db, hosts)
    with network_run(
        db,
        user=user,
        target=",".join(hosts)[:2000],
        admission=admission,
        profile={**body.model_dump(exclude={"hosts"}), "workers": body.workers or 8},
    ) as run:
        result = NetworkTlsScanner(live=True, timeout=body.timeout, workers=body.workers or 8).scan_hosts(
            hosts,
            sni=body.sni,
            starttls=body.starttls,
            scan_versions=body.scan_versions,
            scan_ciphers=body.scan_ciphers,
            check_renegotiation=body.check_renegotiation,
            check_chain_sent=body.check_chain_sent,
            live_revocation=body.live_revocation,
        )
        result = persist_network(db, result, run)
        run.succeed(coverage=network_coverage(result))
    return result


@router.post("/network/scan-path")
def scan_path(body: FilesystemTlsRequest, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    # Path-traversal / secret-exposure guard: confine filesystem cert scans to
    # the allow-listed source roots (the same choke point as source scans).
    try:
        from api.security.target_validation import TargetValidationError, validate_source_target

        safe_path = validate_source_target(body.path, label="path")
    except TargetValidationError as exc:
        raise HTTPException(status_code=400, detail={"error": "invalid_target", "field": "path", "reason": str(exc)})
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


# ---------------------------------------------------------------------------
# Structured network inventory (devices, topology, configuration, services,
# controls, WAN, monitoring, wireless, firmware and documentation).
# ---------------------------------------------------------------------------


@router.get("/network/inventory/schema")
def network_inventory_schema(user: str = Depends(get_current_user)):
    from network_scanner.inventory.network_inventory import NetworkInventoryDocument

    return NetworkInventoryDocument.model_json_schema(by_alias=True)


@router.post("/network/inventory/validate")
def validate_network_inventory(
    body: NetworkInventoryWrite,
    user: str = Depends(get_current_user),
):
    from network_scanner.inventory.network_inventory import (
        inventory_approval_issues,
        inventory_completeness,
        inventory_hash,
        parse_inventory,
    )
    from pydantic import ValidationError

    try:
        document = parse_inventory(body.inventory)
    except (ValidationError, ValueError) as exc:
        detail = exc.errors() if isinstance(exc, ValidationError) else str(exc)
        raise HTTPException(status_code=422, detail=detail) from exc
    completeness = inventory_completeness(document)
    approval_issues = inventory_approval_issues(document)
    return {
        "valid": True,
        "status_allowed": body.status != "APPROVED"
        or (completeness["status"] == "COMPLETE" and not approval_issues and body.reviewed_by == user),
        "completeness": completeness,
        "approval_issues": approval_issues,
        "content_sha256": inventory_hash(document),
        "persisted": False,
    }


@router.get("/network/inventory")
def get_network_inventory(
    inventory_id: str = "default",
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    from db.repositories.network_inventory_repository import NetworkInventoryRepository
    from network_scanner.inventory.network_inventory import NetworkInventoryDocument, inventory_completeness

    revision = NetworkInventoryRepository(db).latest(inventory_id)
    if revision is None:
        document = NetworkInventoryDocument(inventory_id=inventory_id)
        return {
            "inventory_id": inventory_id,
            "revision": None,
            "persisted": False,
            "status": "DRAFT",
            "inventory": document.model_dump(mode="json", by_alias=True),
            "completeness": inventory_completeness(document),
            "audit": {"source": "system-default", "content_sha256": None},
        }
    return {
        "inventory_id": inventory_id,
        "revision": revision.revision,
        "persisted": True,
        "status": revision.status,
        "inventory": revision.inventory_json,
        "completeness": revision.completeness_json,
        "audit": {
            "source": revision.source,
            "content_sha256": revision.content_sha256,
            "captured_at": revision.captured_at.isoformat() if revision.captured_at else None,
            "created_by": revision.created_by,
            "reviewed_by": revision.reviewed_by,
            "review_notes": revision.review_notes,
        },
    }


@router.put("/network/inventory")
def put_network_inventory(
    body: NetworkInventoryWrite,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    from db.repositories.network_inventory_repository import NetworkInventoryRepository
    from network_scanner.inventory.network_inventory import (
        inventory_approval_issues,
        inventory_completeness,
        inventory_hash,
        parse_inventory,
    )
    from pydantic import ValidationError

    try:
        document = parse_inventory(body.inventory)
    except (ValidationError, ValueError) as exc:
        detail = exc.errors() if isinstance(exc, ValidationError) else str(exc)
        raise HTTPException(status_code=422, detail=detail) from exc
    completeness = inventory_completeness(document)
    approval_issues = inventory_approval_issues(document)
    if body.status == "APPROVED":
        if completeness["status"] != "COMPLETE" or approval_issues:
            raise HTTPException(
                status_code=422,
                detail={
                    "message": "Network inventory cannot be approved with missing or unverified observations",
                    "completeness": completeness,
                    "approval_issues": approval_issues,
                },
            )
        if body.reviewed_by != user:
            raise HTTPException(status_code=403, detail="reviewed_by must match the authenticated reviewer")
    revision = NetworkInventoryRepository(db).create_revision(
        body.inventory_id,
        schema_version=document.inventory_schema,
        status=body.status,
        source=body.source,
        inventory_json=document.model_dump(mode="json", by_alias=True),
        completeness_json=completeness,
        content_sha256=inventory_hash(document),
        captured_at=document.captured_at or datetime.now(timezone.utc),
        created_by=user,
        reviewed_by=body.reviewed_by,
        review_notes=body.review_notes,
    )
    return {
        "inventory_id": body.inventory_id,
        "revision": revision.revision,
        "status": revision.status,
        "inventory": revision.inventory_json,
        "completeness": completeness,
        "audit": {
            "source": revision.source,
            "content_sha256": revision.content_sha256,
            "created_by": revision.created_by,
            "captured_at": revision.captured_at.isoformat() if revision.captured_at else None,
        },
    }


@router.get("/network/inventory/history")
def network_inventory_history(
    inventory_id: str = "default",
    limit: int = 50,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    from db.repositories.network_inventory_repository import NetworkInventoryRepository

    if limit < 1 or limit > 200:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 200")
    rows = NetworkInventoryRepository(db).history(inventory_id, limit=limit)
    return {"inventory_id": inventory_id, "revisions": [row.to_dict() for row in rows]}


@router.get("/network/inventory/risk")
def network_inventory_risk(
    inventory_id: str = "default",
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    from db.repositories.network_inventory_repository import NetworkInventoryRepository
    from network_scanner.inventory.network_inventory import NetworkInventoryDocument, inventory_risk, parse_inventory

    revision = NetworkInventoryRepository(db).latest(inventory_id)
    document = (
        parse_inventory(revision.inventory_json) if revision else NetworkInventoryDocument(inventory_id=inventory_id)
    )
    result = inventory_risk(document)
    result.update(
        {
            "inventory_id": inventory_id,
            "revision": revision.revision if revision else None,
            "profile_status": revision.status if revision else "DRAFT",
            "posture": "RED"
            if result["risk_score"] >= 70 or result["status"] == "INCOMPLETE"
            else "AMBER"
            if result["risk_score"] >= 30
            else "GREEN",
            "reasons": [factor["reason"] for factor in result["factors"]],
            "unknowns": list(result["completeness"]["missing"]),
            "next_actions": list(result["completeness"]["next_actions"]),
        }
    )
    return result


@router.post("/network/inventory/discover")
def discover_network_inventory(
    body: NetworkInventoryDiscoveryRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Run the existing safe discovery engine and persist its structured view.

    Discovery produces a DRAFT only. Scanner observations do not prove device
    ownership, configuration correctness, topology, firmware currency, or
    control effectiveness; a reviewer must enrich and verify the inventory.
    """
    # The enterprise engine can expand ranges and invoke plugins/secondary
    # protocols after the initial plan. A generic admission is not a receipt
    # for those destinations. Keep imports/engine construction behind a hard
    # refusal until phase admission + metering + durable receipts are wired.
    raise HTTPException(
        409,
        detail="Enterprise/plugin discovery is not qualified for bounded admission; use bounded network scan/discovery or import a reviewed inventory",
    )


@router.get("/network/inventory/topology")
def get_network_inventory_topology(
    inventory_id: str = "default",
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Return the typed topology graph plus explicit integrity gaps."""
    from db.repositories.network_inventory_repository import NetworkInventoryRepository
    from network_scanner.inventory.network_inventory import NetworkInventoryDocument, parse_inventory, topology_graph

    revision = NetworkInventoryRepository(db).latest(inventory_id)
    document = (
        parse_inventory(revision.inventory_json) if revision else NetworkInventoryDocument(inventory_id=inventory_id)
    )
    result = topology_graph(document)
    result.update({"inventory_id": inventory_id, "revision": revision.revision if revision else None})
    return result


@router.post("/network/inventory/topology/validate")
def validate_network_inventory_topology(
    body: NetworkInventoryAnalysisRequest,
    user: str = Depends(get_current_user),
):
    from network_scanner.inventory.network_inventory import parse_inventory, topology_graph
    from pydantic import ValidationError

    try:
        document = parse_inventory(body.inventory)
    except (ValidationError, ValueError) as exc:
        detail = exc.errors() if isinstance(exc, ValidationError) else str(exc)
        raise HTTPException(status_code=422, detail=detail) from exc
    result = topology_graph(document)
    result["valid"] = not result["unknown_endpoints"]
    result["warnings"] = []
    if result["unknown_endpoints"]:
        result["warnings"].append("topology contains endpoints that are not in the device inventory")
    if result["unlinked_devices"]:
        result["warnings"].append("one or more devices have no observed topology link")
    if result["unverified_edges"]:
        result["warnings"].append("one or more topology edges are not confirmed or observed")
    return result


@router.get("/network/inventory/configuration/drift")
def get_network_configuration_drift(
    inventory_id: str = "default",
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    from db.repositories.network_inventory_repository import NetworkInventoryRepository
    from network_scanner.inventory.network_inventory import (
        NetworkInventoryDocument,
        configuration_drift,
        parse_inventory,
    )

    revision = NetworkInventoryRepository(db).latest(inventory_id)
    document = (
        parse_inventory(revision.inventory_json) if revision else NetworkInventoryDocument(inventory_id=inventory_id)
    )
    result = configuration_drift(document)
    result.update({"inventory_id": inventory_id, "revision": revision.revision if revision else None})
    return result


@router.post("/network/inventory/configuration/drift")
def analyze_network_configuration_drift(
    body: NetworkInventoryAnalysisRequest,
    user: str = Depends(get_current_user),
):
    from network_scanner.inventory.network_inventory import configuration_drift, parse_inventory
    from pydantic import ValidationError

    try:
        document = parse_inventory(body.inventory)
    except (ValidationError, ValueError) as exc:
        detail = exc.errors() if isinstance(exc, ValidationError) else str(exc)
        raise HTTPException(status_code=422, detail=detail) from exc
    return configuration_drift(document)


@router.get("/network/inventory/coverage")
def get_network_inventory_coverage(
    inventory_id: str = "default",
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Expose section-level readiness instead of a misleading single green score."""
    from db.repositories.network_inventory_repository import NetworkInventoryRepository
    from network_scanner.inventory.network_inventory import (
        NetworkInventoryDocument,
        configuration_drift,
        inventory_completeness,
        inventory_risk,
        parse_inventory,
        topology_graph,
    )

    revision = NetworkInventoryRepository(db).latest(inventory_id)
    document = (
        parse_inventory(revision.inventory_json) if revision else NetworkInventoryDocument(inventory_id=inventory_id)
    )
    return {
        "inventory_id": inventory_id,
        "revision": revision.revision if revision else None,
        "completeness": inventory_completeness(document),
        "risk": inventory_risk(document),
        "topology": topology_graph(document),
        "configuration_drift": configuration_drift(document),
        "section_states": {
            "devices": document.devices,
            "topology": document.topology.observation,
            "configuration": document.configuration.observation,
            "network_services": document.network_services.observation,
            "security_controls": document.security_controls.observation,
            "wan_connectivity": document.wan_connectivity.observation,
            "monitoring": document.monitoring.observation,
            "wireless_networks": document.wireless_networks.observation,
            "firmware_software": document.firmware_software.observation,
            "documentation": document.documentation.observation,
            "evidence": document.evidence,
        },
    }
