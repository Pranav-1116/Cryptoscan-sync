"""Persistence for network scan runs: list, fetch, and latest-two for drift."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from db.models.network_scan_run import NetworkScanRun


class ScanRunRepository:
    def __init__(self, session):
        self.session = session

    def create_run(self, result: dict[str, Any], *, target_kind: str = "hosts") -> NetworkScanRun:
        """Store a scan_hosts-shaped result; telemetry fields extracted for query."""
        telemetry = (result or {}).get("probe_telemetry") or {}
        row = NetworkScanRun(
            scan_id=(result or {}).get("scan_id"),
            target_kind=target_kind or "hosts",
            verdict=telemetry.get("status"),
            probed=telemetry.get("probed"),
            ok=telemetry.get("ok"),
            result=result,
        )
        self.session.add(row)
        self.session.flush()
        return row

    def get_run(self, run_id: str) -> NetworkScanRun | None:
        return self.session.get(NetworkScanRun, run_id)

    def list_runs(
        self, *, limit: int = 20, target_kind: str | None = None
    ) -> list[NetworkScanRun]:
        stmt = select(NetworkScanRun).order_by(NetworkScanRun.created_at.desc(), NetworkScanRun.id.desc()).limit(max(1, min(limit, 500)))
        if target_kind:
            stmt = stmt.where(NetworkScanRun.target_kind == target_kind)
        return list(self.session.execute(stmt).scalars())

    def latest_runs(self, *, count: int = 2, target_kind: str | None = None) -> list[NetworkScanRun]:
        stmt = select(NetworkScanRun).order_by(NetworkScanRun.created_at.desc(), NetworkScanRun.id.desc()).limit(max(1, min(count, 500)))
        if target_kind:
            stmt = stmt.where(NetworkScanRun.target_kind == target_kind)
        return list(self.session.execute(stmt).scalars())

    def count_runs(self, *, target_kind: str | None = None) -> int:
        from sqlalchemy import func

        stmt = select(func.count(NetworkScanRun.id))
        if target_kind:
            stmt = stmt.where(NetworkScanRun.target_kind == target_kind)
        return int(self.session.execute(stmt).scalar() or 0)
