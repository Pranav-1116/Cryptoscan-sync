"""Scheduled network-target sweep used by the monitor daemon.

The API's ``/network/run-due`` endpoint is useful for an operator, but it is
not a scheduler. This module closes that production gap: rows registered in
``network_scan_targets`` are selected by their persisted due time, scanned by
the real ``NetworkTlsScanner``, written to ``network_scan_runs`` and advanced
to their next interval. NBOM then derives from the same stored run without
requiring a second declaration or a manual API call.

A scanner failure is returned as an error and leaves due rows due for the next
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
from network_scanner.core.scheduler import due_targets, next_scan_time


def run_due_network_targets(
    session: Any,
    *,
    now: datetime | None = None,
    scanner_factory: Callable[[], Any] | None = None,
) -> dict[str, Any]:
    """Scan every due persisted network target and store one scheduled run.

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

    endpoints = [str(item["endpoint"]) for item in due if str(item.get("endpoint") or "").strip()]
    if not endpoints:
        return {"due": len(due), "scanned": 0, "run_id": None, "status": "BLOCKED",
                "reason": "due network targets contain no endpoints"}

    if scanner_factory is None:
        from network_scanner.core.scanner import NetworkTlsScanner

        scanner_factory = lambda: NetworkTlsScanner(live=True)  # noqa: E731

    scanner = scanner_factory()
    result = scanner.scan_hosts(endpoints)

    # Keep the same certificate/materialized-usage side effects as the manual
    # API flow. The run itself is the authoritative NBOM input.
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
    rows_by_endpoint = {row.endpoint: row for row in rows}
    for item in due:
        row = rows_by_endpoint.get(item.get("endpoint"))
        if row is None:
            continue
        row.last_scan_time = stamp
        row.next_scan_time = next_scan_time(stamp, row.scan_frequency)
    session.flush()

    telemetry = result.get("probe_telemetry") or {}
    return {
        "due": len(due),
        "scanned": len(endpoints),
        "run_id": run.id,
        "status": telemetry.get("status") or "COMPLETED",
        "probed": telemetry.get("probed"),
        "ok": telemetry.get("ok"),
        "findings": len(result.get("findings") or []),
    }
