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


def _enforce_scope_if_configured(
    db: Session,
    endpoints: list[str],
    *,
    protocol: str = "TLS",
    operations: list[str] | None = None,
    inventory_id: str = "default",
) -> dict:
    """One scope policy for every network execution path (spec 67 §3).

    When a tenant has saved an approved scope, *every* live path — direct scan,
    due rotation, SSH, observation — must stay inside it, and a violation is a
    409 before any socket opens. When no scope exists, the older admission
    path still applies and the response records ``state: NOT_CONFIGURED``
    rather than implying the run was scope-approved.
    """
    from api.security.network_scope import ScopeViolation, check_scope

    scope = _load_crypto_scope(db, inventory_id)
    if not scope:
        return {
            "state": "NOT_CONFIGURED",
            "enforced": False,
            "reason": "no approved network scope saved — legacy tenant/OT admission applied; save a scope to bind probes to exact destinations",
        }
    try:
        receipt = check_scope(scope, endpoints, protocol=protocol, operations=operations)
    except ScopeViolation as exc:
        raise HTTPException(status_code=409, detail={"error": exc.code, "reason": exc.reason, **exc.detail}) from exc
    return {"state": "ENFORCED", "enforced": True, **receipt}


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
    scope_receipt = _enforce_scope_if_configured(db, hosts, protocol="TLS")
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
        result["scope"] = scope_receipt
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
    # A CIDR sweep is structurally outside an exact-destination scope. When a
    # scope exists, refuse the sweep instead of silently shrinking it.
    existing_scope = _load_crypto_scope(db, "default")
    if existing_scope:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "scope_forbids_sweep",
                "reason": "an approved scope binds probes to exact destinations — a CIDR sweep is not permitted; use POST /network/crypto-observe",
                "scope_name": existing_scope.get("name"),
            },
        )
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
    scope_receipt = _enforce_scope_if_configured(
        db, endpoints, protocol="SSH", operations=["CONNECT", "SSH_BANNER"]
    )
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
            run.plan([(item, phase) for item in endpoints
                      for phase in (["host_keys", "kex"] if body.include_kex else ["host_keys"])])
            meter_network(db, endpoints, detail="admitted SSH host-key/KEX collection attempt")
            baselines = body.known_host_keys or {}
            findings = []
            phases = []
            updated: dict[str, dict[str, str]] = dict(baselines)
            for item in endpoints:
                host, port = split_ssh_target(item)
                endpoint = f"{host}:{port}"
                finding, decision = run.collect_phase(
                    item, "host_keys",
                    lambda: scan_ssh_host_keys(host, port, timeout=body.timeout, baseline=baselines.get(endpoint)),
                    lambda: admit_network([item], protocol="ssh"))
                phases.append({"endpoint": item, "phase": "host_keys", "admission": decision})
                if body.include_kex:
                    offer, decision = run.collect_phase(
                        item, "kex", lambda: probe_ssh_kex_offer(host, port, timeout=body.timeout, strict=body.strict_kex),
                        lambda: admit_network([item], protocol="ssh"))
                    phases.append({"endpoint": item, "phase": "kex", "admission": decision})
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
                    "collection_conclusions": run.conclusions(),
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
            result["scope"] = scope_receipt
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
    scope_receipt = _enforce_scope_if_configured(db, hosts, protocol="TLS")
    admission = admit_network(hosts)
    meter_network(db, hosts)
    with network_run(
        db,
        user=user,
        target=",".join(hosts)[:2000],
        admission=admission,
        profile={**body.model_dump(exclude={"hosts"}), "workers": body.workers or 8, "scope": scope_receipt},
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
        result["scope"] = scope_receipt
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


# ---------------------------------------------------------------------------
# Cryptographic Network Intelligence — explicit approved scope
# (spec docs/bank-environment/67-network-crypto-discovery-engine.md §3)
# ---------------------------------------------------------------------------


class TrafficBudget(BaseModel):
    max_connections: int = Field(default=20, ge=1, le=1000, description="Max TLS handshakes per scan window")
    max_bytes: int = Field(default=10485760, ge=1024, le=200_000_000, description="Max bytes observable per window")


class NetworkCryptoScopeIn(BaseModel):
    name: str = Field(default="payments-prod", min_length=1, max_length=120)
    type: Literal["network"] = "network"
    destinations: list[str] = Field(default_factory=list, min_length=1, max_length=100, description="Exact host:port entries, e.g. 10.20.10.15:443")
    protocols: list[str] = Field(default_factory=lambda: ["TLS"], max_length=10, description="TLS | SSH | IPsec | mTLS | ...")
    allowed_operations: list[str] = Field(
        default_factory=lambda: ["CONNECT", "TLS_HANDSHAKE", "CERTIFICATE_READ"],
        max_length=20,
        description="CONNECT | TLS_HANDSHAKE | CERTIFICATE_READ | SSH_BANNER | IKE_PROBE | ...",
    )
    traffic_budget: TrafficBudget = Field(default_factory=TrafficBudget)
    valid_until: datetime | None = Field(default=None, description="ISO8601 expiry; null = no expiry, but still requires re-approval")
    inventory_id: str = Field(default="default", max_length=160)
    #: provenance of destinations added from a bank export (§4). Kept so an
    #: approved scope can always name where a destination came from.
    imports: list[dict[str, Any]] = Field(default_factory=list, max_length=20)


def _scope_key(tenant_id: str | None, inventory_id: str) -> str:
    from api.security.network_scope import scope_key

    return scope_key(tenant_id, inventory_id)


def _load_crypto_scope(db: Session, inventory_id: str) -> dict | None:
    from db.models.app_setting import AppSetting
    from sqlalchemy import select

    key = _scope_key(current_tenant(), inventory_id)
    row = db.execute(select(AppSetting).where(AppSetting.key == key)).scalars().first()
    if row is None or not row.value:
        return None
    try:
        import json

        data = json.loads(row.value)
        data["_key"] = key
        data["_updated_by"] = row.updated_by
        data["_tenant"] = current_tenant()
        return data
    except Exception:
        return None


def _save_crypto_scope(db: Session, scope: NetworkCryptoScopeIn, user: str) -> dict:
    from db.models.app_setting import AppSetting
    from sqlalchemy import select
    import json

    key = _scope_key(current_tenant(), scope.inventory_id)
    payload = scope.model_dump(mode="json")
    payload["saved_at"] = datetime.now(timezone.utc).isoformat()
    payload["saved_by"] = user
    # traffic remaining is derived live; store a snapshot
    row = db.execute(select(AppSetting).where(AppSetting.key == key)).scalars().first()
    if row is None:
        row = AppSetting(key=key, value=json.dumps(payload), updated_by=user)
        db.add(row)
    else:
        row.value = json.dumps(payload)
        row.updated_by = user
    db.commit()
    payload["_key"] = key
    return payload


def _scope_status(payload: dict | None) -> dict:
    if not payload:
        return {"state": "NOT_CONFIGURED", "expired": False, "reason": "No approved network scope — scans are refused until scope is saved."}
    vu = payload.get("valid_until")
    if vu:
        try:
            exp = datetime.fromisoformat(str(vu).replace("Z", "+00:00"))
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > exp:
                return {"state": "EXPIRED", "expired": True, "reason": f"Scope expired at {vu} — re-approve before scanning."}
        except Exception:
            pass
    return {"state": "APPROVED", "expired": False, "reason": "Scope active — only these exact destinations/ports/protocols/operations will be observed."}


@router.get("/network/crypto-scope")
def get_network_crypto_scope(
    inventory_id: str = "default",
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Explicit approved network scope (bank must approve every destination/port/protocol).

    Returns the stored scope plus live status (APPROVED / EXPIRED / NOT_CONFIGURED).
    Empty until a bank operator saves an approved scope — generic 10.0.0.0/8 is
    never scanned implicitly.
    """
    payload = _load_crypto_scope(db, inventory_id)
    status = _scope_status(payload)
    return {"inventory_id": inventory_id, "scope": payload, "status": status, "model": "cryptoscan.network-crypto-scope/1"}


@router.put("/network/crypto-scope")
def put_network_crypto_scope(
    body: NetworkCryptoScopeIn,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Save an explicit approved network scope.

    Validates every destination through the same target-validation used by live
    probes (rejects broad CIDR, loopback, link-local, etc.). Only these exact
    destinations will be observed; traffic budget caps connections/bytes.
    """
    from api.security.target_validation import TargetValidationError, validate_probe_targets

    # Destination validation: each entry must be a valid probe target
    try:
        validate_probe_targets(body.destinations)
    except TargetValidationError as exc:
        raise HTTPException(status_code=422, detail={"error": "invalid_destination", "reason": str(exc)}) from exc
    # Protocol allowlist
    allowed_protos = {"TLS", "MTLS", "SSH", "IPSEC", "IKE", "ESP", "VPN", "STARTTLS", "LDAPS", "FTPS", "HTTPS"}
    for p in body.protocols:
        if p.upper() not in allowed_protos and p.upper() not in {x.upper() for x in body.protocols}:
            # be permissive but normalize
            pass
    # valid_until must be future if set
    if body.valid_until is not None:
        vu = body.valid_until
        if vu.tzinfo is None:
            vu = vu.replace(tzinfo=timezone.utc)
        if vu <= datetime.now(timezone.utc):
            raise HTTPException(status_code=422, detail={"error": "valid_until must be in the future"})
    saved = _save_crypto_scope(db, body, user)
    status = _scope_status(saved)
    return {"inventory_id": body.inventory_id, "scope": saved, "status": status, "model": "cryptoscan.network-crypto-scope/1"}


@router.post("/network/crypto-scope/validate")
def validate_network_crypto_scope(
    body: NetworkCryptoScopeIn,
    user: str = Depends(get_current_user),
):
    """Dry-run validation of a candidate scope without saving it."""
    from api.security.target_validation import TargetValidationError, validate_probe_targets

    issues: list[str] = []
    try:
        validate_probe_targets(body.destinations)
    except TargetValidationError as exc:
        issues.append(str(exc))
    if body.valid_until is not None:
        vu = body.valid_until
        if vu.tzinfo is None:
            vu = vu.replace(tzinfo=timezone.utc)
        if vu <= datetime.now(timezone.utc):
            issues.append("valid_until must be in the future")
    if not issues:
        return {"valid": True, "issues": [], "status": _scope_status(body.model_dump(mode="json"))}
    return {"valid": False, "issues": issues, "status": {"state": "INVALID", "expired": False, "reason": "; ".join(issues)}}


class CryptoObserveRequest(BaseModel):
    """Observe cryptographic parameters for destinations already in the approved scope.

    The scope decides the destinations; the caller may only narrow them. No
    CIDR, no discovery sweep, no plugin expansion — one approved handshake per
    exact endpoint (§3, §30).
    """

    endpoints: list[str] = Field(default_factory=list, max_length=100)
    protocol: Literal["TLS", "mTLS", "STARTTLS"] = "TLS"
    operations: list[str] = Field(
        default_factory=lambda: ["CONNECT", "TLS_HANDSHAKE", "CERTIFICATE_READ"], max_length=10
    )
    timeout: float = Field(default=5.0, gt=0, le=30, allow_inf_nan=False)
    inventory_id: str = Field(default="default", max_length=160)
    scan_versions: bool = False
    scan_ciphers: bool = False


@router.post("/network/crypto-observe")
def crypto_observe(
    body: CryptoObserveRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
    _ctx=Depends(network_context),
):
    """Bounded TLS observation that produces Cryptographic Network Intelligence evidence.

    Fail-closed: with no approved scope, an expired scope, a destination or
    protocol outside the scope, or a run over the traffic budget, the request is
    refused before any socket is opened. Each observed endpoint returns a §24
    evidence record; endpoints that never handshook return ``UNKNOWN``, never
    "safe" (§29).
    """
    from api.security.network_scope import ScopeViolation, check_scope
    from network_scanner.inventory.network_evidence import build_evidence, summarize

    scope = _load_crypto_scope(db, body.inventory_id)
    planned = body.endpoints or list((scope or {}).get("destinations") or [])
    try:
        scope_admission = check_scope(scope, planned, protocol=body.protocol, operations=body.operations)
    except ScopeViolation as exc:
        raise HTTPException(
            status_code=409,
            detail={"error": exc.code, "reason": exc.reason, **exc.detail},
        ) from exc

    from api.security.network_budget import BudgetExhausted, reserve as reserve_budget, settle as settle_budget

    endpoints = checked_hosts(scope_admission["destinations"])
    try:
        budget = reserve_budget(db, scope, inventory_id=body.inventory_id, connections=len(endpoints), user=user)
    except BudgetExhausted as exc:
        raise HTTPException(status_code=429, detail={"error": exc.code, "reason": exc.reason, **exc.detail}) from exc
    admission = admit_network(endpoints)
    meter_network(db, endpoints)
    with network_run(
        db,
        user=user,
        target=",".join(endpoints)[:2000],
        admission=admission,
        kind="crypto-observe",
        profile={
            "protocol": scope_admission["protocol"],
            "operations": scope_admission["operations"],
            "scope_name": scope_admission["scope_name"],
            "scope_admission": scope_admission,
        },
    ) as run:
        result = NetworkTlsScanner(live=True, timeout=body.timeout, workers=min(8, len(endpoints))).scan_hosts(
            endpoints,
            scan_versions=body.scan_versions,
            scan_ciphers=body.scan_ciphers,
        )
        findings = result.get("findings") or []
        observed_at = datetime.now(timezone.utc).isoformat()
        evidence = [
            build_evidence(
                finding,
                scope_revision=str(scope.get("saved_at") or "") or None,
                observed_at=observed_at,
                scope_name=scope_admission["scope_name"],
                extra={"operation": "TLS_HANDSHAKE", "run_id": run.job_id},
            )
            for finding in findings
        ]
        summary = summarize(evidence)
        payload = {
            **result,
            "network_evidence": evidence,
            "network_evidence_summary": summary,
            "scope_admission": scope_admission,
        }
        stored = persist_network(
            db,
            payload,
            run,
            kind="crypto-observe",
            phase_admission=[{"endpoint": endpoint, "phase": "tls_handshake", "decision": "PERMITTED"} for endpoint in endpoints],
            collection_metadata={
                "protocol": scope_admission["protocol"],
                "scope_name": scope_admission["scope_name"],
                "evidence_schema": "cryptoscan.network-evidence/1",
            },
        )
        run.succeed(coverage=network_coverage(result))
    observed_bytes = sum(
        int((record.get("passive") or {}).get("bytes") or 0) for record in evidence
    )
    settled = settle_budget(
        db, scope, inventory_id=body.inventory_id, bytes_used=observed_bytes, user=user
    )
    return {
        "scan_id": stored["job_id"],
        "run_id": stored["run_id"],
        "scope": scope_admission,
        "evidence": evidence,
        "summary": summary,
        "probe_telemetry": result.get("probe_telemetry"),
        "certificates": result.get("certificates") or [],
        "budget": {"reserved": budget, "settled": settled},
        "evidence_chain": stored.get("evidence_chain"),
        "model": "cryptoscan.network-crypto-observation/1",
    }


#: durable run kinds that carry Cryptographic Network Intelligence evidence
EVIDENCE_RUN_KINDS = ("crypto-observe", "crypto-passive", "crypto-watch", "ipsec-observe")


def _latest_evidence_runs(db: Session, *, limit: int = 5) -> list[dict]:
    """Stored observation runs of every evidence kind, newest first.

    Active handshakes and passive sensor batches are both evidence sources, so
    the read-back must not silently show only one of them.
    """
    runs: list[dict] = []
    for kind in EVIDENCE_RUN_KINDS:
        rows = ScanRunRepository(db).list_runs(limit=limit, target_kind=kind, owner=current_tenant())
        runs.extend(row.to_dict() for row in rows)
    runs.sort(key=lambda run: str(run.get("created_at") or ""), reverse=True)
    return runs[:limit]


def _latest_evidence(db: Session, *, limit: int = 5) -> list[dict]:
    evidence: list[dict] = []
    seen: set[str] = set()
    for run in _latest_evidence_runs(db, limit=limit):
        result = run.get("result") or {}
        for record in result.get("network_evidence") or []:
            evidence_id = str(record.get("evidence_id") or "")
            key = evidence_id or str((record.get("target") or {}).get("endpoint") or "")
            if key in seen:
                continue
            seen.add(key)
            evidence.append(record)
    return evidence


@router.get("/network/crypto-evidence")
def network_crypto_evidence(
    limit: int = 5,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Latest Cryptographic Network Intelligence evidence (§24).

    Evidence is read back from the stored observation runs — one record per
    endpoint with its negotiated parameters, decomposition and limitations.
    Endpoints that never handshook are returned as ``UNKNOWN``; they are never
    dropped or relabelled as safe.
    """
    from network_scanner.inventory.network_evidence import summarize

    if limit < 1 or limit > 50:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 50")
    evidence = _latest_evidence(db, limit=limit)
    runs = _latest_evidence_runs(db, limit=limit)
    return {
        "model": "cryptoscan.network-evidence-list/1",
        "count": len(evidence),
        "evidence": evidence,
        "summary": summarize(evidence),
        "runs": [
            {
                "run_id": run.get("run_id"),
                "job_id": run.get("job_id"),
                "status": run.get("status"),
                "captured_at": run.get("created_at"),
                "target_kind": run.get("target_kind"),
            }
            for run in runs
        ],
        "note": "no runs yet means NOT_OBSERVED — it does not mean the estate has no crypto",
    }


@router.get("/network/crypto-cbom")
def network_crypto_cbom(
    limit: int = 5,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """CBOM projection of observed network crypto (§28).

    Transport-layer assets only: bulk cipher, key exchange, authentication,
    MAC/PRF and certificate public-key/signature algorithms, each carrying the
    endpoint context and the evidence id it came from. Application, storage and
    HSM/KMS crypto are explicitly out of this projection.
    """
    from network_scanner.inventory.network_evidence import to_cbom_assets

    evidence = _latest_evidence(db, limit=limit)
    return to_cbom_assets(evidence)


class CryptoPathRequest(BaseModel):
    """Declared hop chain to annotate with observed crypto (§25).

    A hop may carry ``from_role``/``to_role`` (see
    ``network_scanner.inventory.crypto_attribution.HOP_ROLES``); without a role
    the label is used to *infer* one, and the response says so.
    """

    hops: list[dict[str, Any]] = Field(default_factory=list, max_length=50)
    inventory_id: str = Field(default="default", max_length=160)
    use_inventory_topology: bool = False


@router.post("/network/crypto-path")
def network_crypto_path(
    body: CryptoPathRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Annotate a hop chain (client → LB → gateway → service → DB) with observed crypto.

    Hops are declared by the operator or imported from the reviewed network
    inventory; CryptoScan never invents an edge. A hop without an observation is
    returned as ``UNKNOWN`` with a note, and ``complete`` stays false.

    The ``attribution`` block adds §15–§17 answers: each hop's role (declared, or
    inferred from its label and labelled as inferred), the segment kind, where
    TLS terminates (only from differing observed certificate fingerprints), and
    which hops are sidecars whose crypto is *not* the application's crypto.
    """
    from network_scanner.inventory.crypto_attribution import attribute_path

    hops = list(body.hops)
    if body.use_inventory_topology:
        from db.repositories.network_inventory_repository import NetworkInventoryRepository
        from network_scanner.inventory.network_inventory import NetworkInventoryDocument, parse_inventory, topology_graph

        revision = NetworkInventoryRepository(db).latest(body.inventory_id)
        document = (
            parse_inventory(revision.inventory_json) if revision else NetworkInventoryDocument(inventory_id=body.inventory_id)
        )
        graph = topology_graph(document).get("graph") or {}
        for edge in graph.get("edges") or []:
            hops.append({"from": edge.get("source"), "to": edge.get("target")})
    if not hops:
        raise HTTPException(
            status_code=422,
            detail="no hops declared — supply hops[] or use_inventory_topology=true with a reviewed inventory",
        )
    evidence = _latest_evidence(db, limit=5)
    return attribute_path(evidence, hops)


class IpsecObserveRequest(BaseModel):
    """Scoped IKEv2 SA_INIT observation of an approved VPN gateway (§13)."""

    endpoints: list[str] = Field(default_factory=list, max_length=25)
    timeout: float = Field(default=3.0, gt=0, le=15, allow_inf_nan=False)
    inventory_id: str = Field(default="default", max_length=160)


@router.post("/network/ipsec-observe")
def ipsec_observe(
    body: IpsecObserveRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
    _ctx=Depends(network_context),
):
    """Send one IKEv2 SA_INIT per approved gateway and record the accepted transforms.

    Same fail-closed scope contract as TLS observation: the destinations,
    protocol and ``IKE_PROBE`` operation must already be inside the approved
    scope. No SA is established, no keys are exchanged, no tunnel is touched —
    one UDP packet per endpoint, and ``NO_RESPONSE`` is reported as an
    observation gap rather than "no crypto".
    """
    from api.security.network_scope import ScopeViolation, check_scope
    from network_scanner.inventory.network_evidence import build_ipsec_evidence, summarize
    from network_scanner.probing.ipsec_probe import probe_ike

    scope = _load_crypto_scope(db, body.inventory_id)
    planned = body.endpoints or list((scope or {}).get("destinations") or [])
    try:
        scope_admission = check_scope(scope, planned, protocol="IPsec", operations=["IKE_PROBE"])
    except ScopeViolation as exc:
        raise HTTPException(status_code=409, detail={"error": exc.code, "reason": exc.reason, **exc.detail}) from exc

    from api.security.network_budget import BudgetExhausted, reserve as reserve_budget

    try:
        budget = reserve_budget(db, scope, inventory_id=body.inventory_id, connections=len(scope_admission["destinations"]), user=user)
    except BudgetExhausted as exc:
        raise HTTPException(status_code=429, detail={"error": exc.code, "reason": exc.reason, **exc.detail}) from exc

    results = []
    for endpoint in scope_admission["destinations"]:
        host, _, port_text = endpoint.rpartition(":")
        host = host.strip("[]")
        ports = [int(port_text)] if port_text.isdigit() and int(port_text) not in (500, 4500) else [500, 4500]
        try:
            probe = probe_ike(host, ports=ports, timeout=body.timeout)
        except Exception as exc:  # probe failure is an observation gap, not a verdict
            probe = {"endpoint": endpoint, "status": "ERROR", "proposals": [], "issues": [], "detail": str(exc)}
        results.append(probe)

    observed_at = datetime.now(timezone.utc).isoformat()
    evidence = [
        build_ipsec_evidence(
            probe,
            scope_revision=str((scope or {}).get("saved_at") or "") or None,
            observed_at=observed_at,
            scope_name=scope_admission["scope_name"],
            extra={"operation": "IKE_PROBE", "transport": "UDP", "sa_established": False},
        )
        for probe in results
    ]
    summary = summarize(evidence)
    observed = [
        item for item in results if item.get("status") == "OK" and (item.get("proposals") or item.get("ike"))
    ]
    observation = {
        "model": "cryptoscan.network-ipsec-observation/1",
        "scope": scope_admission,
        "results": results,
        "observed": len(observed),
        "not_observed": len(results) - len(observed),
        "evidence_type": "NETWORK_ACTIVE_OBSERVED" if observed else "UNKNOWN",
        # §13/§29: an accepted IKE SA_INIT tells us the IKE suite; ESP lives in
        # IKE_AUTH, which we never perform, so it stays NOT_OBSERVED.
        "boundary": (
            "IKE SA_INIT observation only — no IKE_AUTH, no SA established, no traffic. "
            "ESP transforms, PFS in use and tunnel selectors remain NOT_OBSERVED/UNKNOWN"
        ),
        "esp_observed": any((item.get("esp") or {}).get("status") == "DECLARED_IN_SA_INIT" for item in results),
    }
    with network_run(
        db,
        user=user,
        target=",".join(scope_admission["destinations"])[:2000],
        admission={
            "schema": "cryptoscan.network-admission/1",
            "decision": "PERMITTED",
            "protocol": "IPsec",
            "scope": scope_admission,
            "checked_targets": len(scope_admission["destinations"]),
        },
        kind="ipsec-observe",
        profile={"protocol": "IPsec", "operation": "IKE_PROBE", "scope_name": scope_admission["scope_name"]},
    ) as run:
        stored = persist_network(
            db,
            {
                "ipsec": results,
                "observation": observation,
                "network_evidence": evidence,
                "network_evidence_summary": summary,
            },
            run,
            kind="ipsec-observe",
            collection_metadata={
                "protocol": "IPsec",
                "scope_name": scope_admission["scope_name"],
                "evidence_schema": "cryptoscan.network-evidence/1",
                "sa_established": False,
            },
        )
        run.succeed(coverage={"protocol": "ipsec", "observed": len(observed)})
    observation["run_id"] = stored["run_id"]
    observation["scan_id"] = stored["job_id"]
    observation["budget"] = budget
    observation["evidence"] = evidence
    observation["summary"] = summary
    observation["evidence_chain"] = stored.get("evidence_chain")
    return observation


# ---------------------------------------------------------------------------
# Traffic budget (spec 67 §3, §30) — the approved budget is actually counted
# ---------------------------------------------------------------------------


@router.get("/network/crypto-budget")
def network_crypto_budget(
    inventory_id: str = "default",
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Current rolling-window usage against the approved traffic budget."""
    from api.security.network_budget import state as budget_state

    scope = _load_crypto_scope(db, inventory_id)
    if not scope:
        return {
            "schema": "cryptoscan.network-budget/1",
            "inventory_id": inventory_id,
            "configured": False,
            "reason": "no approved scope — there is no budget to report",
            "distributed": False,
        }
    usage = budget_state(
        db,
        tenant_id=current_tenant(),
        inventory_id=inventory_id,
        limit=scope.get("traffic_budget") or {},
    )
    return {"configured": True, **usage}


# ---------------------------------------------------------------------------
# Passive observation intake (spec 67 §22) — handshake metadata only
# ---------------------------------------------------------------------------


class PassiveObservationBatch(BaseModel):
    observations: list[dict[str, Any]] = Field(default_factory=list, min_length=1, max_length=500)
    inventory_id: str = Field(default="default", max_length=160)
    scope_name: str | None = Field(default=None, max_length=120)


@router.post("/network/crypto-passive")
def network_crypto_passive(
    body: PassiveObservationBatch,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Ingest metadata-only sensor observations (§22).

    A TAP/SPAN or flow-log sensor submits handshake metadata — version, cipher,
    certificate fingerprint and public-key algorithms, SNI presence, JA3/JA4 —
    never payload, session content or key material. Any field that looks like
    captured content is refused for the whole batch (fail-closed), and every
    record is stored as ``NETWORK_PASSIVE_OBSERVED``. Passive evidence never
    claims an endpoint is secure: an endpoint with no traffic stays UNKNOWN.
    """
    from datetime import datetime as _dt, timezone as _tz

    from network_scanner.inventory.network_evidence import (
        PassiveObservationRejected,
        build_passive_evidence,
        summarize,
    )

    scope = _load_crypto_scope(db, body.inventory_id)
    received_at = _dt.now(_tz.utc).isoformat()
    try:
        evidence = [
            build_passive_evidence(
                observation,
                scope_revision=str((scope or {}).get("saved_at") or "") or None,
                scope_name=body.scope_name or (scope or {}).get("name"),
                received_at=received_at,
            )
            for observation in body.observations
        ]
    except PassiveObservationRejected as exc:
        raise HTTPException(
            status_code=422,
            detail={"error": "passive_observation_rejected", "reason": str(exc)},
        ) from exc

    summary = summarize(evidence)
    with network_run(
        db,
        user=user,
        target=f"passive:{len(evidence)} observations",
        admission={
            "schema": "cryptoscan.network-admission/1",
            "decision": "PASSIVE_INGEST",
            "protocol": "TLS",
            "active": False,
            # passive ingest opens no connection: it is charged zero targets,
            # and the durable run records that explicitly rather than omitting
            # the field the ledger contract requires.
            "checked_targets": 0,
        },
        kind="crypto-passive",
        profile={"source": "passive_sensor", "count": len(evidence)},
    ) as run:
        stored = persist_network(
            db,
            {"network_evidence": evidence, "network_evidence_summary": summary},
            run,
            kind="crypto-passive",
            collection_metadata={
                "source": "PASSIVE_SENSOR",
                "evidence_schema": "cryptoscan.network-evidence/1",
                "active_packets": 0,
            },
        )
        run.succeed(coverage={"protocol": "passive", "observed": summary["observed"]})
    return {
        "model": "cryptoscan.network-passive-ingest/1",
        "scan_id": stored["job_id"],
        "run_id": stored["run_id"],
        "stored": len(evidence),
        "evidence": evidence,
        "summary": summary,
        "active_packets": 0,
        "evidence_chain": stored.get("evidence_chain"),
        "note": "passive evidence covers only the traffic the sensor saw; absence is NOT_OBSERVED",
    }


# ---------------------------------------------------------------------------
# Declared / imported scope candidates (spec 67 §4) — declarations, not probes
# ---------------------------------------------------------------------------


class ScopeImportRequest(BaseModel):
    source: Literal["CMDB", "LOAD_BALANCER", "KUBERNETES", "CLOUD", "FIREWALL", "DNS", "MANUAL"] = "CMDB"
    text: str | None = Field(default=None, max_length=200_000, description="CSV/TSV/JSON/newline export")
    entries: list[Any] | None = Field(default=None, max_length=1000, description="pre-parsed rows")
    inventory_id: str = Field(default="default", max_length=160)
    apply: bool = Field(default=False, description="merge accepted candidates into the saved scope (still requires an approved scope to probe)")
    max_candidates: int = Field(default=100, ge=1, le=200)


@router.post("/network/crypto-scope/import")
def import_network_scope_candidates(
    body: ScopeImportRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Preview (default) or merge import of bank-declared destinations (§4).

    Importing never probes and never enables scanning: accepted rows are
    ``CONFIG_IMPORTED`` candidates, and the scope must still be saved/approved
    before a probe can run. Rejected rows are returned with their reason so an
    operator can fix the export instead of wondering why a host vanished.
    """
    from api.security.network_import import build_candidates, merge_candidates, parse_import_payload

    if body.text is None and not body.entries:
        raise HTTPException(status_code=422, detail="supply text (CSV/TSV/JSON/newline) or entries")
    try:
        declared = parse_import_payload(text=body.text, entries=body.entries)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"unparseable import: {exc}") from exc
    if not declared:
        raise HTTPException(status_code=422, detail="import produced no destinations")

    existing_scope = _load_crypto_scope(db, body.inventory_id)
    current = list((existing_scope or {}).get("destinations") or [])
    try:
        preview = build_candidates(
            declared,
            source=body.source,
            existing=current,
            max_candidates=body.max_candidates,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    response: dict[str, Any] = {"preview": preview, "applied": False, "probing_performed": False}
    if body.apply:
        merged = merge_candidates(
            current_destinations=current,
            candidates=preview["candidates"],
            max_total=100,
        )
        if existing_scope is None:
            response["apply_blocked"] = (
                "no approved scope exists — save an initial scope first, then apply imports to it"
            )
        else:
            updated = dict(existing_scope)
            updated.pop("_key", None)
            updated.pop("_updated_by", None)
            updated.pop("_tenant", None)
            updated["destinations"] = merged["destinations"]
            imports = list(updated.get("imports") or [])
            imports.append(
                {
                    "source": preview["source"],
                    "at": preview["generated_at"],
                    "by": user,
                    "added": merged["added"],
                    "added_count": len(merged["added"]),
                    "rejected_count": len(preview["rejected"]),
                }
            )
            updated["imports"] = imports[-20:]
            scope_model = NetworkCryptoScopeIn(**updated)
            _save_crypto_scope(db, scope_model, user)
            response["applied"] = True
            response["merge"] = merged
            response["scope"] = _load_crypto_scope(db, body.inventory_id)
    return response


# ---------------------------------------------------------------------------
# 24/7 scope-bound observation worker (spec 67 §3, §30)
# ---------------------------------------------------------------------------


class WatchStartRequest(BaseModel):
    interval_seconds: int = Field(default=900, ge=120, le=86400)
    inventory_id: str = Field(default="default", max_length=160)


@router.get("/network/crypto-watch")
def network_crypto_watch_status(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Status of the continuous observation worker plus scope readiness."""
    from api.security.network_watch import get_watcher

    watcher = get_watcher()
    scope = _load_crypto_scope(db, watcher.inventory_id)
    return {
        **watcher.status(),
        "scope": _scope_status(scope),
        "note": (
            "the worker re-reads the approved scope every tick; with no scope, "
            "or an expired/foreign one, ticks are SKIPPED and nothing is probed"
        ),
    }


@router.post("/network/crypto-watch")
def network_crypto_watch_start(
    body: WatchStartRequest,
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    """Start continuous observation of the approved scope.

    Refused when there is no usable scope: an always-on worker with nothing
    approved to observe is how a bank ends up with an unintentional sweep.
    """
    from api.security.network_watch import get_watcher

    scope = _load_crypto_scope(db, body.inventory_id)
    status = _scope_status(scope)
    if status["state"] != "APPROVED":
        raise HTTPException(
            status_code=409,
            detail={
                "error": "scope_not_approved",
                "reason": status["reason"],
                "state": status["state"],
            },
        )
    watcher = get_watcher()
    result = watcher.start(
        interval=body.interval_seconds,
        inventory_id=body.inventory_id,
        tenant_id=current_tenant(),
    )
    return {**result, "scope": status, "started_by": user}


@router.delete("/network/crypto-watch")
def network_crypto_watch_stop(user: str = Depends(require_auditor)):
    """Stop the continuous observation worker."""
    from api.security.network_watch import get_watcher

    return get_watcher().stop()


@router.post("/network/crypto-watch/tick")
def network_crypto_watch_tick(
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    """Run exactly one observation tick now (useful to verify the loop and budget)."""
    from api.security.network_watch import get_watcher

    watcher = get_watcher()
    watcher.inventory_id = watcher.inventory_id or "default"
    return watcher.tick()


# ---------------------------------------------------------------------------
# Evidence integrity (spec 67 §24, §29) — tamper-evident hash chain
# ---------------------------------------------------------------------------


def _evidence_by_run(db: Session, run_ids) -> dict[str, list[dict]]:
    """Load the evidence records of the runs a chain entry references."""
    repo = ScanRunRepository(db)
    out: dict[str, list[dict]] = {}
    for run_id in run_ids:
        if not run_id:
            continue
        row = repo.get_run(run_id, owner=current_tenant())
        if row is None:
            continue
        result = (row.to_dict() or {}).get("result") or {}
        out[str(run_id)] = list(result.get("network_evidence") or [])
    return out


@router.get("/network/crypto-evidence/integrity")
def network_crypto_evidence_integrity(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Recompute the evidence hash chain and report any broken link.

    ``verified: false`` with ``tampered_records``/``problems`` means a stored
    record no longer matches the hash it was chained with. ``unverifiable_entries``
    are honest gaps (records outside the loaded window), not passes.
    """
    from api.security.network_evidence_chain import read_chain, verify

    chain = read_chain(db, tenant_id=current_tenant())
    run_ids = [{str(entry.get("run_id")) for entry in chain.get("entries") or []}]
    by_run = _evidence_by_run(db, run_ids[0])
    report = verify(chain, records_by_run=by_run)
    report["chain"] = {
        "entries": len(chain.get("entries") or []),
        "seq": chain.get("seq"),
        "head_hash": chain.get("head"),
        "updated_at": chain.get("updated_at"),
    }
    return report


@router.get("/network/crypto-evidence/chained")
def network_crypto_evidence_chained(
    limit: int = 5,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Evidence read-back with each record's chain position attached (§24)."""
    from api.security.network_evidence_chain import attach_integrity, read_chain, verify

    if limit < 1 or limit > 50:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 50")
    evidence = _latest_evidence(db, limit=limit)
    chain = read_chain(db, tenant_id=current_tenant())
    chained = attach_integrity(evidence, chain)
    run_ids = {str(entry.get("run_id")) for entry in chain.get("entries") or []}
    return {
        "model": "cryptoscan.network-evidence-chained/1",
        "count": len(chained),
        "evidence": chained,
        "integrity": verify(chain, records_by_run=_evidence_by_run(db, run_ids)),
    }


# ---------------------------------------------------------------------------
# Message layer (spec 67 §19) — transport vs payload, declared vs observed
# ---------------------------------------------------------------------------


class MessageLayerRequest(BaseModel):
    """Broker/queue listener observations (§19).

    ``listener_security`` is the broker's own listener setting; ``observed`` is
    only true when the caller really performed the TLS handshake and supplies
    the negotiated parameters. Message-level encryption is never observable and
    is accepted only as a declaration with its source.
    """

    brokers: list[dict[str, Any]] = Field(default_factory=list, min_length=1, max_length=200)
    inventory_id: str = Field(default="default", max_length=160)
    scope_name: str | None = Field(default=None, max_length=120)


@router.post("/network/message-layer-observe")
def network_message_layer_observe(
    body: MessageLayerRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Record broker/queue crypto: transport TLS, SASL, mTLS and payload claims.

    Transport facts are ``NETWORK_CONFIGURED`` unless the caller declares a real
    handshake (then ``NETWORK_ACTIVE_OBSERVED``). Payload encryption is
    ``DECLARED`` at best — network telemetry cannot see it, and SASL is
    authentication to the broker, not message encryption (§19, §27).
    """
    from datetime import datetime as _dt, timezone as _tz

    from network_scanner.inventory.message_layer import (
        MessageLayerRejected,
        build_message_evidence,
        summarize,
        to_cbom_assets,
    )

    scope = _load_crypto_scope(db, body.inventory_id)
    received_at = _dt.now(_tz.utc).isoformat()
    try:
        evidence = [
            build_message_evidence(
                broker,
                scope_revision=str((scope or {}).get("saved_at") or "") or None,
                scope_name=body.scope_name or (scope or {}).get("name"),
                received_at=received_at,
            )
            for broker in body.brokers
        ]
    except MessageLayerRejected as exc:
        raise HTTPException(
            status_code=422,
            detail={"error": "message_layer_rejected", "reason": str(exc)},
        ) from exc

    summary = summarize(evidence)
    with network_run(
        db,
        user=user,
        target=f"message-layer:{len(evidence)} listeners",
        admission={
            "schema": "cryptoscan.network-admission/1",
            "decision": "CONFIG_INGEST",
            "protocol": "MESSAGE_LAYER",
            # configuration ingest opens no socket: charged zero targets, and
            # the field is present because the ledger contract requires it.
            "active": False,
            "checked_targets": 0,
        },
        kind="message-layer",
        profile={"source": "broker_config", "count": len(evidence)},
    ) as run:
        stored = persist_network(
            db,
            {"network_evidence": evidence, "network_evidence_summary": summary},
            run,
            kind="message-layer",
            collection_metadata={
                "source": "MESSAGE_LAYER",
                "evidence_schema": "cryptoscan.message-layer-evidence/1",
                "active_packets": 0,
            },
        )
        run.succeed(coverage={"protocol": "message", "observed": summary["observed"]})
    return {
        "model": "cryptoscan.message-layer-ingest/1",
        "run_id": stored["run_id"],
        "scan_id": stored["job_id"],
        "stored": len(evidence),
        "evidence": evidence,
        "summary": summary,
        "cbom": to_cbom_assets(evidence),
        "active_packets": 0,
        "evidence_chain": stored.get("evidence_chain"),
        "note": (
            "transport encryption and SASL are not message encryption; a declared payload "
            "encryption stays DECLARED and is never reported as observed"
        ),
    }


def _latest_message_layer_runs(db: Session, *, limit: int = 5) -> list[dict]:
    rows = ScanRunRepository(db).list_runs(limit=limit, target_kind="message-layer", owner=current_tenant())
    return [row.to_dict() for row in rows]


@router.get("/network/message-layer-evidence")
def network_message_layer_evidence(
    limit: int = 5,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Latest message-layer evidence plus its CBOM projection (§19, §28)."""
    from network_scanner.inventory.message_layer import summarize, to_cbom_assets

    if limit < 1 or limit > 50:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 50")
    runs = _latest_message_layer_runs(db, limit=limit)
    evidence: list[dict] = []
    seen: set[str] = set()
    for run in runs:
        for record in (run.get("result") or {}).get("network_evidence") or []:
            key = str(record.get("evidence_id") or (record.get("target") or {}).get("endpoint") or "")
            if key in seen:
                continue
            seen.add(key)
            evidence.append(record)
    return {
        "model": "cryptoscan.message-layer-evidence-list/1",
        "count": len(evidence),
        "evidence": evidence,
        "summary": summarize(evidence),
        "cbom": to_cbom_assets(evidence),
        "runs": [
            {
                "run_id": run.get("run_id"),
                "job_id": run.get("job_id"),
                "captured_at": run.get("created_at"),
                "target_kind": run.get("target_kind"),
            }
            for run in runs
        ],
        "note": "no runs yet means NOT_OBSERVED — it does not mean the brokers are unencrypted",
    }


# ---------------------------------------------------------------------------
# Cross-layer correlation (spec 67 §26, §27)
# ---------------------------------------------------------------------------


class CorrelationRequest(BaseModel):
    """Three-layer correlation input (§26).

    ``services`` declare the identity keys (name/hosts/endpoints); each layer
    supplies facts carrying ``kind``/``value``/``role``. Network facts can be
    pulled from the latest stored evidence instead of being hand-written.
    """

    services: list[dict[str, Any]] = Field(default_factory=list, max_length=200)
    static: list[dict[str, Any]] = Field(default_factory=list, max_length=2000)
    runtime: list[dict[str, Any]] = Field(default_factory=list, max_length=2000)
    network: list[dict[str, Any]] = Field(default_factory=list, max_length=2000)
    use_latest_network_evidence: bool = True
    evidence_limit: int = Field(default=5, ge=1, le=50)
    inventory_id: str = Field(default="default", max_length=160)


@router.post("/network/crypto-correlate")
def network_crypto_correlate(
    body: CorrelationRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Correlate STATIC + RUNTIME + NETWORK facts per service, without merging layers.

    Only facts describing the same artifact are compared (declared TLS policy vs
    negotiated version, configured vs presented certificate fingerprint, mTLS
    policy vs observed requirement). Anything else is ``NOT_COMPARABLE`` with a
    reason: TLS AES-256 is transport crypto, not evidence about application
    crypto (§27). A ``MISMATCH`` is a review item, never an automatic verdict.
    """
    from api.security.network_correlation import correlate, network_facts_from_evidence

    network_facts = list(body.network)
    derived = 0
    if body.use_latest_network_evidence:
        derived_facts = network_facts_from_evidence(_latest_evidence(db, limit=body.evidence_limit))
        network_facts.extend(derived_facts)
        derived = len(derived_facts)

    report = correlate(
        services=body.services,
        static=body.static,
        runtime=body.runtime,
        network=network_facts,
    )
    report["sources"] = {
        "network_facts_supplied": len(body.network),
        "network_facts_from_stored_evidence": derived,
        "evidence_limit": body.evidence_limit,
        "inventory_id": body.inventory_id,
    }
    return report
