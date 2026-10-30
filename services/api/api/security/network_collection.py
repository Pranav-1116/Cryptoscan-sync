"""Shared API TCP/TLS preflight and durable-result contract.

This is not distributed scheduling, a DNS pinning boundary or an in-flight
kill switch. An admission authorizes the checked phase, not future phases.
"""

from __future__ import annotations

from contextlib import contextmanager
import ipaddress
from typing import Literal

from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field

from api.dependencies import TenantContext, get_tenant_context
from api.security import scan_admission
from api.security.scan_runs import DurableScanRun, coverage_from_result
from api.security.target_validation import TargetValidationError, validate_probe_targets
from db.repositories.certificate_repository import CertificateRepository
from db.repositories.maturity_repository import MaturityRepository
from db.repositories.scan_run_repository import ScanRunRepository
from db.tenancy import current_tenant, tenant_scope
from network_scanner.core.scanner import normalize_endpoint
from shared_models.network_registry import classify_port, classify_service

MAX_HOSTS = 256


class NetworkHostRequest(BaseModel):
    hosts: list[str] = Field(min_length=1, max_length=MAX_HOSTS)
    live: Literal[True] = True
    timeout: float = Field(default=5.0, gt=0, le=30, allow_inf_nan=False)
    sni: str | None = Field(default=None, max_length=253)
    starttls: str | None = None
    workers: int | None = Field(default=None, ge=1, le=32)
    scan_versions: bool = False
    scan_ciphers: bool = False
    check_renegotiation: bool = False
    check_chain_sent: bool = False
    live_revocation: bool = False


async def network_context(ctx: TenantContext = Depends(get_tenant_context)):
    # A sync generator dependency's ContextVar changes do not propagate out
    # of its worker thread. Enter scope on the async request task so FastAPI
    # copies it to every synchronous phase, even without tenant middleware.
    with tenant_scope(ctx.tenant_id):
        yield ctx


def checked_hosts(hosts):
    try:
        clean = validate_probe_targets(hosts)
    except TargetValidationError as exc:
        raise HTTPException(422, detail=str(exc)) from exc
    clean = list(dict.fromkeys(normalize_endpoint(h) for h in clean))
    if len(clean) > MAX_HOSTS:
        raise HTTPException(422, detail=f"At most {MAX_HOSTS} TLS targets per collection")
    for endpoint in clean:
        port = endpoint.rsplit(":", 1)[-1]
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise HTTPException(422, detail="Invalid network endpoint port")
    return clean


def _host_port(value):
    value = str(value).strip().lower().rstrip(".")
    if "/" in value:
        return value, None
    endpoint = normalize_endpoint(value)
    host, port = endpoint.rsplit(":", 1)
    # Bare hosts exclude all ports. Explicit endpoint exclusions stay specific.
    explicit = value.startswith("[") and "]:" in value or value.count(":") == 1
    return host.strip("[]").rstrip("."), int(port) if port.isdigit() and explicit else None


def _network(value):
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def _check_exclusions(target, port, decision, protocol, transport="tcp"):
    exclusions = decision.get("exclusions") or {}
    if port in (exclusions.get("ports") or []):
        raise HTTPException(409, detail="Network collection refused: excluded port")
    protocols = {classify_service(str(p)).canonical.lower() for p in exclusions.get("protocols") or []}
    # Port/service classification is a conservative policy hint, not proof
    # that the service behind that port was observed. No network lookup.
    if protocols & {
        transport,
        protocol,
        classify_service(protocol).canonical.lower(),
        classify_port(port, transport).canonical.lower(),
    }:
        raise HTTPException(409, detail="Network collection refused: excluded protocol")
    host, _ = _host_port(target)
    wanted = _network(host)
    for excluded in exclusions.get("assets") or []:
        other, excluded_port = _host_port(excluded)
        if excluded_port is not None and excluded_port != port:
            continue
        forbidden = _network(other)
        overlap = (
            wanted is not None
            and forbidden is not None
            and wanted.version == forbidden.version
            and wanted.overlaps(forbidden)
        )
        if host == other or overlap:
            # Refuse a whole sweep intersecting an exclusion; do not silently
            # shrink its scope or probe the forbidden member first.
            raise HTTPException(409, detail="Network collection refused: excluded target or intersecting scope")


def admit_network(targets, *, protocol="tls", ports=None, transport="tcp"):
    """Check the entire phase before constructing any executor or job."""
    decisions = []
    for target in targets:
        for port in ports or [int(normalize_endpoint(target).rsplit(":", 1)[1])]:
            decision = scan_admission.admit_scan(
                active_probing_requested=True, asset=target, port=port, protocol=protocol, include_exclusions=True
            )
            _check_exclusions(target, port, decision, protocol, transport)
            public_decision = {key: value for key, value in decision.items() if key != "exclusions"}
            decisions.append({"target": target, "port": port, "decision": public_decision})
    if not decisions:
        raise HTTPException(422, detail="No network targets to admit")
    return {
        **decisions[0]["decision"],
        "schema": "cryptoscan.network-admission/1",
        "protocol": protocol,
        "transport": transport,
        "checked_targets": len(targets),
        "decisions": decisions,
    }


def meter_network(db, hosts, *, detail="admitted network TLS collection attempt"):
    """Existing per-host plan accounting, shared across TLS aliases.

    This is a preflight check, not an atomic distributed quota reservation.
    """
    tenant_id = current_tenant()
    if tenant_id is None:
        return
    from api.security.tenancy import quota_check
    from db.repositories.tenant_repository import TenantRepository

    repo = TenantRepository(db)
    tenant = repo.get(tenant_id)
    used = repo.month_usage(tenant_id, "scan_run")
    allowed, reason = quota_check(
        tenant.plan if tenant else "FREE", "scan_run", None if used is None else used + len(hosts) - 1
    )
    if not allowed:
        raise HTTPException(402, detail=f"quota_exceeded: {reason}")
    repo.record_usage(tenant_id, "scan_run", len(hosts), detail=detail)


def _admission_host_count(admission) -> int:
    """How many targets the admission covers, without assuming one key.

    ``admit_network`` reports ``checked_targets``. An admission built by another
    path — a caller that admits per destination, or a test that injects the gate —
    may carry only the per-target decisions. Reading the key directly turned that
    into a ``KeyError`` and a 500 on an otherwise valid observation.
    """
    counted = admission.get("checked_targets")
    if isinstance(counted, int) and not isinstance(counted, bool):
        return counted
    decisions = admission.get("decisions")
    if isinstance(decisions, list):
        return len(decisions)
    destinations = admission.get("destinations")
    if isinstance(destinations, list):
        return len(destinations)
    return 0


@contextmanager
def network_run(db, *, user, target, admission, kind="hosts", profile=None):
    with DurableScanRun(
        db,
        job_type="NETWORK_SCAN" if kind != "discovery" else "NETWORK_DISCOVERY",
        target=target,
        user=user,
        admission=admission,
        tenant_id=current_tenant(),
        metadata={"kind": kind, "live": True, "hosts": _admission_host_count(admission), "profile": profile or {}},
    ) as run:
        try:
            yield run
        except Exception:
            # A flush/commit failure invalidates the SQLAlchemy transaction.
            # Roll back projections/registration/schedule before the outer
            # durable job attempts its independent FAILED transition.
            db.rollback()
            raise


def persist_network(db, result, run, *, kind="hosts", phase_admission=None, collection_metadata=None):
    """Stage ledger + materialized projections; caller completes atomically.

    Never swallow storage failures and never label port discovery as TLS.

    Evidence records are linked into the tenant hash chain here, so every code
    path that stores evidence (active, passive, watch, IPsec, message layer) gets
    the same tamper-evident treatment instead of each caller remembering to.
    """
    from api.security.network_evidence_chain import append as append_to_chain, ensure_evidence_ids

    evidence = ensure_evidence_ids(result.get("network_evidence") or [])
    if evidence:
        # keep the caller's list in sync so the response carries the same ids
        result["network_evidence"] = evidence
    payload = {
        **result,
        "collection": {
            **(collection_metadata or {}),
            "schema": "cryptoscan.network-collection/1",
            "job_id": run.job_id,
            "kind": kind,
        },
    }
    if phase_admission is not None:
        payload["collection"]["phase_admission"] = phase_admission
    row = ScanRunRepository(db).create_run(payload, target_kind=kind)
    certificates, usages = CertificateRepository(db), MaturityRepository(db)
    for cert in result.get("certificates") or []:
        if cert.get("fingerprint_sha256"):
            certificates.upsert(cert)
    for usage in result.get("usages") or []:
        if usage.get("fingerprint_sha256") and usage.get("location"):
            usages.upsert_usage(usage["fingerprint_sha256"], usage["location"], usage.get("usage_type") or "UNKNOWN")
    chain_receipt = (
        append_to_chain(db, evidence, run_id=row.id, tenant_id=current_tenant(), user=None) if evidence else None
    )
    return {**payload, "job_id": run.job_id, "run_id": row.id, "evidence_chain": chain_receipt}


def network_coverage(result):
    return {
        **coverage_from_result(result),
        "network_run_id": result["run_id"],
        "probe_status": (result.get("probe_telemetry") or {}).get("status", "NOT_EVALUATED"),
    }
