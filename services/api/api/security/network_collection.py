"""Shared API TCP/TLS preflight and durable-result contract.

This is not distributed scheduling, a DNS pinning boundary or an in-flight
kill switch. An admission authorizes the checked phase, not future phases.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import ipaddress
import logging
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

logger = logging.getLogger(__name__)


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


@contextmanager
def network_run(db, *, user, target, admission, kind="hosts", profile=None):
    with DurableScanRun(
        db,
        job_type="NETWORK_SCAN" if kind != "discovery" else "NETWORK_DISCOVERY",
        target=target,
        user=user,
        admission=admission,
        tenant_id=current_tenant(),
        # ``checked_targets`` is part of the admission contract
        # (test_network_crypto_budget_passive pins it): a ledger row that cannot say
        # how many hosts it admitted is not worth keeping, so a caller that omits it
        # fails loudly here rather than at read time.
        metadata={"kind": kind, "live": True, "hosts": admission["checked_targets"], "profile": profile or {}},
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
    _materialize_workspace_rows(db, result)
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


def _materialize_workspace_rows(db, result) -> None:
    """Project live TLS findings into the CBOM/NBOM workspace stores.

    The durable evidence (scan run, certificate inventory, usages, hash
    chain) is staged by ``persist_network`` itself; the BOM workspaces read
    the crypto-asset and runtime-finding stores, so without this projection
    a real network observation never surfaces where operators look for it.
    Derived and rebuildable from the run ledger — a projection failure is
    logged, it never fails the scan that produced the evidence.
    """
    try:
        # No savepoint on purpose: releasing one fires the session's
        # before_commit hooks mid-run. Writes are pre-checked instead
        # (owner systems verified to exist, links de-duplicated) so the
        # projection cannot poison the run's transaction.
        _materialize_workspace_rows_inner(db, result)
    except Exception:  # noqa: BLE001 — projection must not sink the run
        logger.exception("network_workspace_projection_failed")


def _endpoint_owners(db, findings) -> dict[str, str]:
    """endpoint → owning system id, from the registered scan targets.

    Ownership is only ever taken from an operator/onboarding declaration on
    the target — an endpoint without one stays unattributed in the
    dependency map rather than being guessed onto a system."""
    from db.models.network_scan_target import NetworkScanTarget

    endpoints = sorted({str(f.get("endpoint") or "").strip() for f in findings
                        if isinstance(f, dict) and f.get("endpoint")})
    if not endpoints:
        return {}
    from db.models.system import System

    rows = db.query(NetworkScanTarget).filter(NetworkScanTarget.endpoint.in_(endpoints)).all()
    claimed = {row.system_id for row in rows if row.system_id}
    live = {sid for (sid,) in db.query(System.id).filter(System.id.in_(claimed)).all()} if claimed else set()
    return {row.endpoint: row.system_id for row in rows if row.system_id in live}


def _link_owner(db, system_id, asset_row, tenant_id) -> None:
    if not system_id or asset_row is None:
        return
    from db.models.system_asset import SystemAsset

    exists = db.query(SystemAsset).filter(SystemAsset.system_id == system_id,
                                          SystemAsset.asset_id == asset_row.id).first()
    if exists is None:
        db.add(SystemAsset(system_id=system_id, asset_id=asset_row.id, tenant_id=tenant_id))
        db.flush()


def _materialize_workspace_rows_inner(db, result) -> None:
    from db.repositories.asset_repository import AssetRepository
    from db.repositories.crypto_repository import CryptoRepository
    from db.repositories.runtime_finding_repository import RuntimeFindingRepository

    findings = result.get("findings") or []
    if not isinstance(findings, list):
        return
    tenant_id = current_tenant()
    owner_of = _endpoint_owners(db, findings)
    assets = AssetRepository(db)
    states = CryptoRepository(db)
    runtime = RuntimeFindingRepository(db)
    now = datetime.now(timezone.utc).isoformat()
    runtime_rows: list[dict] = []
    for finding in findings:
        if not isinstance(finding, dict) or str(finding.get("status") or "") != "OK":
            continue
        endpoint = str(finding.get("endpoint") or "").strip()
        crypto = finding.get("crypto") or {}
        if not endpoint or not isinstance(crypto, dict):
            continue
        tls_version = crypto.get("tls_version")
        cipher = crypto.get("cipher_suite")
        if not tls_version and not cipher:
            continue  # not a TLS observation — SSH/IPsec findings keep their own stores
        # 1) the negotiated cipher stack — one asset per endpoint
        algorithm = str(finding.get("algorithm") or crypto.get("encryption_algorithm") or "").strip()
        if algorithm:
            row, _created = assets.upsert_network_asset({
                "algorithm": algorithm,
                "purpose": "NETWORK_ENCRYPTION",
                "mode": crypto.get("mode") or crypto.get("encryption_mode"),
                "key_size": crypto.get("key_size"),
                "file_path": f"tls://{endpoint}",
                "source_language": "TLS",
                "scanner_ids": [str(finding.get("scanner_id") or "network-tls-scanner-v1.0")],
                "tenant_id": tenant_id,
                "extra": {
                    "endpoint": endpoint,
                    "cipher_suite": cipher,
                    "tls_version": tls_version,
                    "key_exchange": crypto.get("key_exchange_algorithm"),
                    "authentication": crypto.get("authentication_algorithm"),
                    "observation": "live TLS handshake",
                },
            })
            _link_owner(db, owner_of.get(endpoint), row, tenant_id)
            states.upsert_state({
                "asset_id": f"crypto:{row.id}",
                "tenant_id": tenant_id,
                "algorithms": [algorithm.upper()],
                "last_event": "MONITOR_OBSERVED",
                "last_seen": now,
            })
        # 2) the leaf certificate's public key — one asset per endpoint
        chain = finding.get("certificates") or []
        leaf = chain[0] if chain and isinstance(chain[0], dict) else {}
        pk_algo = str(leaf.get("public_key_algorithm") or "").strip()
        if pk_algo:
            row, _created = assets.upsert_network_asset({
                "algorithm": pk_algo,
                "purpose": "CERTIFICATE",
                "key_size": leaf.get("public_key_size"),
                "file_path": endpoint,
                "source_language": "PEM",
                "scanner_ids": [str(finding.get("scanner_id") or "network-tls-scanner-v1.0")],
                "tenant_id": tenant_id,
                "extra": {
                    "endpoint": endpoint,
                    "subject": leaf.get("subject"),
                    "signature_algorithm": leaf.get("signature_algorithm"),
                    "fingerprint_sha256": leaf.get("fingerprint_sha256"),
                    "curve": leaf.get("curve"),
                    "observation": "live TLS handshake",
                },
            })
            _link_owner(db, owner_of.get(endpoint), row, tenant_id)
            states.upsert_state({
                "asset_id": f"crypto:{row.id}",
                "tenant_id": tenant_id,
                "algorithms": [pk_algo.upper()],
                "last_event": "MONITOR_OBSERVED",
                "last_seen": now,
            })
        # 3) protocol observation — feeds the TLS/SSH/IPsec tab and NBOM
        weak = bool(tls_version) and not str(tls_version).startswith(("TLSv1.2", "TLSv1.3", "TLS1.2", "TLS1.3"))
        runtime_rows.append({
            "scanner_id": str(finding.get("scanner_id") or "network-tls-scanner-v1.0"),
            "kind": "session",
            "hostname": endpoint,
            "tls_version": tls_version,
            "cipher_suite": cipher,
            "algorithm": algorithm or None,
            "key_size": crypto.get("key_size"),
            "status": crypto.get("status"),
            "quantum_impact": crypto.get("quantum_impact"),
            "weak_tls": weak,
            "extra": {
                "mode": crypto.get("mode"),
                "key_exchange": crypto.get("key_exchange_algorithm"),
                "authentication": crypto.get("authentication_algorithm"),
                "endpoint": endpoint,
            },
        })
    if runtime_rows:
        runtime.upsert_many(runtime_rows)
