"""Prometheus metrics endpoint (text exposition format, no external client lib).

Scraped by the bundled Prometheus config; Grafana dashboard in
infra/monitoring/grafana consumes these metric names.
"""

from __future__ import annotations

import time

from fastapi import APIRouter, Response

router = APIRouter(tags=["metrics"])

_STARTED_AT = time.time()


def _gauge(name: str, value, help_: str, labels: str = "") -> str:
    label_suffix = f"{{{labels}}}" if labels else ""
    return f"# HELP {name} {help_}\n# TYPE {name} gauge\n{name}{label_suffix} {value}\n"


def _counter(name: str, value, help_: str) -> str:
    return f"# HELP {name} {help_}\n# TYPE {name} counter\n{name} {value}\n"


@router.get("/metrics")
def metrics() -> Response:
    lines: list[str] = []

    # Process health
    lines.append(_gauge("cryptoscan_api_up", 1, "API process is up"))
    lines.append(_gauge("cryptoscan_api_uptime_seconds", round(time.time() - _STARTED_AT, 2), "Seconds since API start"))

    # Inventory counters (best-effort: metrics must never 500)
    try:
        from sqlalchemy import func, select

        from db.connection.session import SessionLocal
        from db.models.drift_event import DriftEvent
        from db.models.evidence_record import EvidenceRecord
        from db.models.scan import Scan
        from db.models.scan_job import ScanJob

        with SessionLocal() as session:
            scans_total = int(session.execute(select(func.count()).select_from(Scan)).scalar_one())
            lines.append(_counter("cryptoscan_scans_total", scans_total, "Total scans stored"))

            for status in ("COMPLETED", "RUNNING", "FAILED"):
                n = int(
                    session.execute(
                        select(func.count()).select_from(Scan).where(Scan.status == status)
                    ).scalar_one()
                )
                lines.append(_gauge("cryptoscan_scans_by_status", n, "Scans by status", f'status="{status}"'))

            findings_total = int(session.execute(select(func.count()).select_from(EvidenceRecord)).scalar_one())
            lines.append(_counter("cryptoscan_findings_total", findings_total, "Total evidence records"))

            for status in ("PASS", "WARN", "FAIL"):
                n = int(
                    session.execute(
                        select(func.count())
                        .select_from(EvidenceRecord)
                        .where(EvidenceRecord.compliance_status == status)
                    ).scalar_one()
                )
                lines.append(_gauge("cryptoscan_findings_by_status", n, "Findings by compliance status", f'status="{status}"'))

            drift_open = int(
                session.execute(
                    select(func.count()).select_from(DriftEvent).where(DriftEvent.resolution_status == "OPEN")
                ).scalar_one()
            )
            lines.append(_gauge("cryptoscan_drift_events_open", drift_open, "Open drift events"))

            jobs_queued = int(
                session.execute(
                    select(func.count()).select_from(ScanJob).where(ScanJob.status == "QUEUED")
                ).scalar_one()
            )
            lines.append(_gauge("cryptoscan_jobs_queued", jobs_queued, "Queued scan jobs"))
    except Exception:
        lines.append(_gauge("cryptoscan_api_db_reachable", 0, "Database reachable for metrics"))
        return Response(content="".join(lines), media_type="text/plain; version=0.0.4; charset=utf-8")

    lines.append(_gauge("cryptoscan_api_db_reachable", 1, "Database reachable for metrics"))
    return Response(content="".join(lines), media_type="text/plain; version=0.0.4; charset=utf-8")
