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


def _histogram(name: str, buckets: dict[float, int], total: int, sum_: float,
               help_: str) -> str:
    """Prometheus cumulative histogram. Buckets must already be cumulative."""
    out = [f"# HELP {name} {help_}", f"# TYPE {name} histogram"]
    for upper in sorted(buckets):
        out.append(f'{name}_bucket{{le="{upper}"}} {buckets[upper]}')
    out.append(f'{name}_bucket{{le="+Inf"}} {total}')
    out.append(f"{name}_sum {sum_}")
    out.append(f"{name}_count {total}")
    return "\n".join(out) + "\n"


def _dependency_lines() -> list[str]:
    """Readiness of PostgreSQL, Redis and the graph store as metrics.

    /healthz/dependencies already reports this for a human or a probe, but
    an operator cannot alert on an endpoint they have to read. Section 5
    asks for readiness checks as part of the metrics surface, so the same
    report is emitted per dependency with 1 = reachable.
    """
    lines: list[str] = []
    try:
        from api.routers.health import dependency_report

        report = dependency_report()
        for check in report.get("checks", []):
            name = str(check.get("name") or "unknown")
            state = str(check.get("status") or "").lower()
            # skipped (not configured) is deliberately NOT 0: a dependency
            # nobody configured is not a dependency that is down, and
            # alerting on it would train operators to ignore the metric.
            value = 1 if state == "ok" else (-1 if state == "skipped" else 0)
            lines.append(_gauge(
                "cryptoscan_dependency_up", value,
                "Backing service reachable (1 up, 0 down, -1 not configured)",
                f'dependency="{name}"'))
            latency = check.get("latency_ms")
            if isinstance(latency, (int, float)):
                lines.append(_gauge(
                    "cryptoscan_dependency_latency_ms", round(float(latency), 2),
                    "Dependency probe latency", f'dependency="{name}"'))
        lines.append(_gauge(
            "cryptoscan_dependencies_degraded",
            1 if report.get("down") else 0,
            "Any configured backing service is down"))
    except Exception as exc:  # noqa: BLE001 - metrics must render during an outage
        logger.warning("dependency_metrics_unavailable",
                       extra={"error_type": type(exc).__name__})
        lines.append(_gauge("cryptoscan_dependencies_degraded", 1,
                            "Any configured backing service is down"))
    return lines


def _operational_counter_lines() -> list[str]:
    """The security and reliability events section 5 asks to alert on."""
    from api.observability.operational_counters import snapshot

    lines: list[str] = []
    helps = {
        "tenant_isolation_violation": "Cross-tenant access refused by the guard",
        "persistence_failure": "A job was not accepted because its row would not commit",
        "event_replay_gap": "SSE replay could not satisfy a Last-Event-ID",
    }
    for event, value in snapshot().items():
        lines.append(_counter(
            f"cryptoscan_{event}_total", value,
            helps.get(event, f"Occurrences of {event}")))
    return lines


def _scan_duration_lines(session) -> list[str]:
    """Scan duration histogram, derived from the stored start/end times."""
    from sqlalchemy import select

    from db.models.scan import Scan

    bounds = [1, 5, 15, 30, 60, 120, 300, 600, 1800]
    cumulative = dict.fromkeys(bounds, 0)
    total = 0
    total_seconds = 0.0
    rows = session.execute(select(Scan.scan_start, Scan.scan_end)).all()
    for start, end in rows:
        if not start or not end:
            continue  # still running, or never finished: not a duration
        seconds = (end - start).total_seconds()
        if seconds < 0:
            continue
        total += 1
        total_seconds += seconds
        for upper in bounds:
            if seconds <= upper:
                cumulative[upper] += 1
    return [_histogram("cryptoscan_scan_duration_seconds", cumulative, total,
                       round(total_seconds, 3),
                       "Completed scan wall-clock duration")]


def _scanner_family_lines(session) -> list[str]:
    """Per-family job outcome counters.

    job_type is the closest thing to a scanner family on the job row
    (MANUAL/CLOUD/BINARY/...), so the counter is labelled by both family and
    status rather than inventing a taxonomy the data cannot support.
    """
    from sqlalchemy import func, select

    from db.models.scan_job import ScanJob

    lines: list[str] = []
    rows = session.execute(
        select(ScanJob.job_type, ScanJob.status, func.count())
        .group_by(ScanJob.job_type, ScanJob.status)
    ).all()
    for job_type, job_status, count in rows:
        lines.append(_gauge(
            "cryptoscan_scanner_family_jobs", int(count),
            "Jobs by scanner family and outcome",
            f'family="{job_type or "unknown"}",status="{job_status or "unknown"}"'))
    return lines


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

    # Section 5 observability. Each block is independently guarded: a metrics
    # surface that disappears when one query fails is useless during the
    # incident it exists for.
    try:
        from db.connection.session import SessionLocal

        with SessionLocal() as session:
            lines.extend(_scan_duration_lines(session))
            lines.extend(_scanner_family_lines(session))
    except Exception as exc:  # noqa: BLE001 - keep the rest of the surface
        logger.warning("scan_metrics_unavailable", extra={"error_type": type(exc).__name__})

    lines.extend(_dependency_lines())
    lines.extend(_operational_counter_lines())
    lines.extend(_telecom_lines())
    lines.append(_gauge("cryptoscan_api_db_reachable", 1, "Database reachable for metrics"))
    return Response(content="".join(lines), media_type="text/plain; version=0.0.4; charset=utf-8")
