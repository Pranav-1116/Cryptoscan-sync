"""Scheduled network-target sweep used by the monitor daemon.

The API's ``/network/run-due`` endpoint is useful for an operator, but it is
not a scheduler. This module closes that production gap: rows registered in
``network_scan_targets`` are selected by their persisted due time, scanned by
the real ``NetworkTlsScanner``, written to ``network_scan_runs`` and advanced
to their next interval. NBOM then derives from the same stored run without
requiring a second declaration or a manual API call.

Target rows are grouped by tenant before execution. That keeps each persisted
run, certificate, usage and schedule update attributed to the tenant that owns
the endpoint while still allowing one leader worker to operate the fleet.

A scanner failure is raised and leaves the affected due rows due for the next
monitor tick; a failed attempt must not move the schedule forward and create a
false freshness signal.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

from db.repositories.certificate_repository import CertificateRepository
from db.repositories.maturity_repository import MaturityRepository
from db.repositories.network_scan_target_repository import NetworkScanTargetRepository
from db.repositories.scan_run_repository import ScanRunRepository
from db.tenancy import tenant_scope
from network_scanner.core.scheduler import due_targets, next_scan_time


def _scan_group(
    session: Any,
    *,
    target_rows: list[Any],
    due: list[dict[str, Any]],
    stamp: datetime,
    scanner_factory: Callable[[], Any],
) -> dict[str, Any]:
    """Scan and persist one tenant's due endpoints inside tenant scope."""
    tenant_id = target_rows[0].tenant_id if target_rows else None
    endpoints = [str(item["endpoint"]) for item in due if str(item.get("endpoint") or "").strip()]
    if not endpoints:
        return {
            "tenant_id": tenant_id, "due": len(due), "scanned": 0,
            "run_id": None, "status": "BLOCKED",
            "reason": "due network targets contain no endpoints",
        }

    # The ORM tenant guard filters reads and stamps new rows while this
    # context is active. ``None`` deliberately represents platform-owned rows.
    with tenant_scope(tenant_id):
        scanner = scanner_factory()
        result = scanner.scan_hosts(endpoints)

        # Keep the same certificate/materialized-usage side effects as the
        # manual API flow. The run itself is the authoritative NBOM input.
        certificate_repo = CertificateRepository(session)
        maturity_repo = MaturityRepository(session)
        for certificate in result.get("certificates") or []:
            if certificate.get("fingerprint_sha256"):
                certificate_repo.upsert(certificate)
        for usage in result.get("usages") or []:
            if usage.get("fingerprint_sha256") and usage.get("location"):
                maturity_repo.upsert_usage(
                    usage["fingerprint_sha256"],
                    usage["location"],
                    usage.get("usage_type") or "UNKNOWN",
                )

        run = ScanRunRepository(session).create_run(result, target_kind="scheduled")
        rows_by_endpoint = {row.endpoint: row for row in target_rows}
        for item in due:
            row = rows_by_endpoint.get(item.get("endpoint"))
            if row is None:
                continue
            row.last_scan_time = stamp
            row.next_scan_time = next_scan_time(stamp, row.scan_frequency)
        session.flush()

    telemetry = result.get("probe_telemetry") or {}
    return {
        "tenant_id": tenant_id,
        "due": len(due),
        "scanned": len(endpoints),
        "run_id": run.id,
        "status": telemetry.get("status") or "COMPLETED",
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
    """Scan every due persisted network target and store scheduled runs.

    ``scanner_factory`` is injectable for deterministic tests. Production uses
    the same live scanner class as the API endpoint. The return value is safe
    to put in monitor logs/events and includes no certificate/key material.
    """
    stamp = now or datetime.now(timezone.utc)
    target_repo = NetworkScanTargetRepository(session)
    rows = target_repo.list_targets()
    due = due_targets([row.to_dict() for row in rows], now=stamp)
    if not due:
        return {"due": 0, "scanned": 0, "run_id": None, "status": "IDLE"}

    if scanner_factory is None:
        from network_scanner.core.scanner import NetworkTlsScanner

        scanner_factory = lambda: NetworkTlsScanner(live=True)  # noqa: E731

    rows_by_endpoint = {row.endpoint: row for row in rows}
    rows_by_tenant: dict[str | None, list[Any]] = {}
    due_by_tenant: dict[str | None, list[dict[str, Any]]] = {}
    for item in due:
        if not item.get("endpoint"):
            continue
        row = rows_by_endpoint.get(item.get("endpoint"))
        if row is None:
            continue
        tenant_id = item.get("tenant_id")
        rows_by_tenant.setdefault(tenant_id, []).append(row)
        due_by_tenant.setdefault(tenant_id, []).append(item)

    if not due_by_tenant:
        return {
            "due": len(due), "scanned": 0, "run_id": None, "run_ids": [],
            "status": "BLOCKED", "reason": "due network targets contain no endpoints",
        }

    groups: list[dict[str, Any]] = []
    for tenant_id, tenant_due in due_by_tenant.items():
        # A scanner/database failure intentionally escapes here. The monitor
        # engine records it as an ERROR and the target remains due.
        groups.append(_scan_group(
            session,
            target_rows=rows_by_tenant[tenant_id],
            due=tenant_due,
            stamp=stamp,
            scanner_factory=scanner_factory,
        ))

    run_ids = [str(group["run_id"]) for group in groups if group.get("run_id")]
    return {
        "due": len(due),
        "scanned": sum(int(group.get("scanned") or 0) for group in groups),
        "run_id": run_ids[0] if len(run_ids) == 1 else None,
        "run_ids": run_ids,
        "status": "OK" if all(group.get("status") in {"OK", "COMPLETED"} for group in groups) else "COMPLETED",
        "groups": groups,
    }
