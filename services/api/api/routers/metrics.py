"""Prometheus metrics endpoint (text exposition format, no external client lib).

Scraped by the bundled Prometheus config; Grafana dashboard in
infra/monitoring/grafana consumes these metric names.
"""

from __future__ import annotations

import hmac
import logging
import time

from fastapi import APIRouter, HTTPException, Request, Response, status

router = APIRouter(tags=["metrics"])
logger = logging.getLogger(__name__)


def _require_metrics_token(request: Request) -> None:
    """Protect the Prometheus surface without routing it through user auth.

    Prometheus is an infrastructure principal, not a human session. In
    development and test the endpoint remains convenient and unauthenticated;
    production startup requires ``METRICS_TOKEN`` and this route accepts it as
    either ``Authorization: Bearer`` or ``X-Metrics-Token``. Constant-time
    comparison prevents turning this low-volume endpoint into a token oracle.
    """
    from api.config.settings import get_settings

    settings = get_settings()
    if not settings.is_production:
        return
    expected = (settings.METRICS_TOKEN or "").strip()
    if len(expected) < 32:
        # Normally caught by validate_runtime_settings during lifespan. Keep a
        # request-time guard for ASGI probes that do not run lifespan hooks.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="metrics authentication is not configured",
        )
    authorization = request.headers.get("authorization", "")
    presented = request.headers.get("x-metrics-token", "")
    if authorization.lower().startswith("bearer "):
        presented = authorization[7:].strip()
    if not presented or not hmac.compare_digest(presented, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="metrics authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

_STARTED_AT = time.time()


def _gauge(name: str, value, help_: str, labels: str = "") -> str:
    label_suffix = f"{{{labels}}}" if labels else ""
    return f"# HELP {name} {help_}\n# TYPE {name} gauge\n{name}{label_suffix} {value}\n"


def _counter(name: str, value, help_: str) -> str:
    return f"# HELP {name} {help_}\n# TYPE {name} counter\n{name} {value}\n"


def _telecom_lines() -> list[str]:
    """Telecom realtime scanner metrics (best-effort — never raises).

    Kept DB-independent on purpose: the scanner's posture lives in its own
    snapshot, so these lines must render even when the database is down
    (that is exactly when an operator is watching dashboards).
    """
    lines: list[str] = []
    try:
        from api.routers.telecom import _load_snapshot
        from datetime import datetime as _dt
        from datetime import timezone as _tz

        snapshot = _load_snapshot() or {}
        rows = snapshot.get("rows") or []
        lines.append(_counter(
            "cryptoscan_telecom_targets_registered",
            int(snapshot.get("targets_registered") or 0),
            "Registered telecom NF targets",
        ))
        by_sev: dict[str, int] = {}
        for row in rows:
            sev = str(row.get("severity") or "info")
            by_sev[sev] = by_sev.get(sev, 0) + 1
        for sev in ("critical", "high", "medium", "low", "info", "ok"):
            lines.append(_gauge(
                "cryptoscan_telecom_targets_by_severity", by_sev.get(sev, 0),
                "Latest-pass verdicts by severity", f'severity="{sev}"',
            ))
        lines.append(_gauge(
            "cryptoscan_telecom_targets_unreachable",
            sum(1 for r in rows if r.get("status") == "UNREACHABLE"),
            "NFs unreachable in the latest pass",
        ))
        generated_at = snapshot.get("generated_at")
        age = -1
        if generated_at:
            try:
                age = int((_dt.now(_tz.utc) - _dt.fromisoformat(str(generated_at))).total_seconds())
            except (TypeError, ValueError):
                age = -1
        lines.append(_gauge(
            "cryptoscan_telecom_scan_age_seconds", age,
            "Seconds since the last telecom pass (-1 = never)",
        ))
    except Exception as telecom_exc:
        logger.warning(
            "telecom_metrics_unavailable",
            extra={"error_type": type(telecom_exc).__name__},
        )
    return lines


@router.get("/metrics")
def metrics(request: Request) -> Response:
    _require_metrics_token(request)
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
        lines.extend(_telecom_lines())  # scanner posture must outlive DB outages
        return Response(content="".join(lines), media_type="text/plain; version=0.0.4; charset=utf-8")

    # 24/7 live-monitor fleet (best-effort — metrics must never 500)
    try:
        from db.models.monitor import MonitorEvent, MonitorTarget

        with SessionLocal() as session:
            targets_total = int(session.execute(select(func.count()).select_from(MonitorTarget)).scalar_one())
            lines.append(_counter("cryptoscan_monitor_targets_total", targets_total, "Monitored targets"))

            for status in ("PENDING", "OK", "DEGRADED", "FAILING", "BLOCKED", "PAUSED"):
                n = int(
                    session.execute(
                        select(func.count()).select_from(MonitorTarget).where(MonitorTarget.status == status)
                    ).scalar_one()
                )
                lines.append(_gauge("cryptoscan_monitor_targets_by_status", n, "Targets by status", f'status="{status}"'))

            targets = list(session.execute(select(MonitorTarget)).scalars().all())
            watch = sum(1 for t in targets if (t.config or {}).get("watch"))
            lines.append(_gauge("cryptoscan_monitor_targets_watch_enabled", watch, "Targets with change-watch enabled"))

            events_total = int(session.execute(select(func.count()).select_from(MonitorEvent)).scalar_one())
            lines.append(_counter("cryptoscan_monitor_events_total", events_total, "Monitor events recorded"))

            changes = int(
                session.execute(
                    select(func.count()).select_from(MonitorEvent).where(MonitorEvent.event_type == "CHANGE_DETECTED")
                ).scalar_one()
            )
            lines.append(_counter("cryptoscan_monitor_changes_detected", changes, "Realtime changes detected"))
    except Exception as monitor_exc:
        logger.warning(
            "monitor_metrics_unavailable",
            extra={"error_type": type(monitor_exc).__name__},
        )

    lines.extend(_telecom_lines())
    lines.append(_gauge("cryptoscan_api_db_reachable", 1, "Database reachable for metrics"))
    return Response(content="".join(lines), media_type="text/plain; version=0.0.4; charset=utf-8")
