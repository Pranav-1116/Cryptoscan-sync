"""Leader-worker TLS rotation with the API admission/durable collection contract.

This function owns transaction boundaries: call it with committed input and no
unrelated pending writes. Every bounded owner batch is re-admitted, metered and
committed RUNNING before constructing the executor. Ledger, projections, fresh
schedule updates and COMPLETED are accepted atomically. A refusal/fault escapes
to the monitor tick; earlier accepted batches remain durable.

An unscoped leader operates the fleet; a tenant-scoped caller can execute only
its exact estate, never shared platform inventory. This is not distributed job
claiming, quota reservation, DNS pinning or qualification of network_runner's
separate scope/IPsec/DNSSEC profiles.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

from fastapi import HTTPException
from sqlalchemy import select

from api.security.network_collection import (
    MAX_HOSTS,
    admit_network,
    checked_hosts,
    meter_network,
    network_coverage,
    network_run,
    persist_network,
)
from db.models.network_scan_target import NetworkScanTarget
from db.models.tenant import Tenant
from db.repositories.network_scan_target_repository import NetworkScanTargetRepository
from db.tenancy import current_tenant, tenant_scope
from network_scanner.core.scheduler import due_targets, next_scan_time

PROFILE = {"workers": 8, "timeout": 5.0, "scan_versions": False, "scan_ciphers": False}


def _scan_group(
    session: Any,
    *,
    tenant_id: str | None,
    target_rows: list[Any],
    stamp: datetime,
    scanner_factory: Callable[[], Any],
) -> dict[str, Any]:
    """Execute one bounded batch under persisted ownership, never config IDs."""
    with tenant_scope(tenant_id):
        if tenant_id is not None:
            tenant = session.get(Tenant, tenant_id, populate_existing=True)
            if tenant is None or tenant.status != "ACTIVE":
                raise HTTPException(409, detail="Scheduled network owner is missing or inactive")
        ids = [row.id for row in target_rows]
        target_rows = list(
            session.execute(
                select(NetworkScanTarget)
                .where(
                    NetworkScanTarget.id.in_(ids),
                    NetworkScanTarget.tenant_id == tenant_id,
                    NetworkScanTarget.enabled.is_(True),
                )
                .execution_options(populate_existing=True)
            ).scalars()
        )
        if len(due_targets([row.to_dict() for row in target_rows], now=stamp)) != len(ids):
            raise HTTPException(409, detail="Scheduled network batch changed; retry selection")
        endpoints = checked_hosts([row.endpoint for row in target_rows])
        admission = admit_network(endpoints)
        meter_network(session, endpoints)
        with network_run(
            session,
            user="monitor-daemon",
            target=",".join(endpoints)[:2000],
            admission=admission,
            kind="scheduled",
            profile=PROFILE,
        ) as run:
            result = scanner_factory().scan_hosts(endpoints)
            result = persist_network(session, result, run, kind="scheduled")
            telemetry = result.get("probe_telemetry") or {}
            # Fully observed weak posture can legitimately be PARTIAL. Failed,
            # missing or incomplete observations must not fabricate freshness.
            complete = (
                telemetry.get("status") in {"OK", "PARTIAL"}
                and telemetry.get("probed") == len(endpoints)
                and telemetry.get("ok") == len(endpoints)
            )
            if complete:
                for row in target_rows:
                    row.last_scan_time = stamp
                    row.next_scan_time = next_scan_time(stamp, row.scan_frequency)
            result["scanned"] = len(endpoints)
            run.succeed(coverage=network_coverage(result))
        return {
            "tenant_id": tenant_id,
            "due": len(target_rows),
            "scanned": len(endpoints),
            "observed": len(endpoints) if complete else 0,
            "run_id": result["run_id"],
            "job_id": result["job_id"],
            "status": telemetry.get("status") or "NOT_EVALUATED",
            "probed": telemetry.get("probed"),
            "ok": telemetry.get("ok"),
            "findings": len(result.get("findings") or []),
        }


def run_due_network_targets(
    session: Any,
    *,
    now: datetime | None = None,
    scanner_factory: Callable[[], Any] | None = None,
) -> dict[str, Any]:
    """Execute committed due targets in owner batches of at most 256 endpoints.

    ``scanner_factory`` is the controlled executor seam. Policy, tenant and
    persistence checks remain mandatory even when the executor is injected.
    """
    stamp = now or datetime.now(timezone.utc)
    caller = current_tenant()
    rows = NetworkScanTargetRepository(session).list_targets()
    rows = [row for row in rows if caller is None or row.tenant_id == caller]
    due_ids = {item["id"] for item in due_targets([row.to_dict() for row in rows], now=stamp)}
    if not due_ids:
        return {"due": 0, "scanned": 0, "run_id": None, "status": "IDLE"}

    if scanner_factory is None:
        from network_scanner.core.scanner import NetworkTlsScanner

        def scanner_factory():
            return NetworkTlsScanner(live=True, timeout=5.0, workers=8)

    # Derive both grouping and lookup from the same persisted row identity,
    # not a global endpoint map or caller-supplied tenant field.
    rows_by_tenant: dict[str | None, list[Any]] = {}
    for row in rows:
        if row.id in due_ids:
            rows_by_tenant.setdefault(row.tenant_id, []).append(row)

    groups = []
    try:
        for tenant_id, tenant_rows in rows_by_tenant.items():
            for offset in range(0, len(tenant_rows), MAX_HOSTS):
                groups.append(
                    _scan_group(
                        session,
                        tenant_id=tenant_id,
                        target_rows=tenant_rows[offset : offset + MAX_HOSTS],
                        stamp=stamp,
                        scanner_factory=scanner_factory,
                    )
                )
    except Exception:
        # Includes failures before the durable context enters (initial job
        # commit, metering, admission). Leave the daemon session usable for
        # later sweeps; never commit a staged RUNNING job after a refusal.
        session.rollback()
        raise
    run_ids = [str(group["run_id"]) for group in groups]
    return {
        "due": len(due_ids),
        "scanned": sum(group["scanned"] for group in groups),
        "observed": sum(group["observed"] for group in groups),
        "run_id": run_ids[0] if len(run_ids) == 1 else None,
        "run_ids": run_ids,
        "status": "OK"
        if all(group["status"] == "OK" and group["observed"] == group["scanned"] for group in groups)
        else "PARTIAL",
        "groups": groups,
    }
