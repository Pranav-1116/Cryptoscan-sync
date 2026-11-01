"""Prometheus metrics endpoint (text exposition format, no external client lib).

Scraped by the bundled Prometheus config; Grafana dashboard in
infra/monitoring/grafana consumes these metric names.
"""

from __future__ import annotations

import hmac
import logging
import os
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


def _job_lifecycle_lines() -> list[str]:
    """Job lifecycle as metrics: queued age, dead letters, scheduled retries.

    ``cryptoscan_jobs_queued`` alone says a queue has work in it. It cannot
    answer the three questions an operator asks during an incident: *how long*
    has the oldest job been waiting, *how many* have already been given up on,
    and *how many* are waiting for a retry. Without those, a stalled worker and
    a busy one look identical.
    """
    lines: list[str] = []
    try:
        from sqlalchemy import func, select

        from db.connection.session import SessionLocal
        from db.models.scan_job import ScanJob
        from datetime import datetime, timezone

        with SessionLocal() as session:
            rows = dict(
                session.execute(
                    select(ScanJob.status, func.count()).group_by(ScanJob.status)
                ).all()
            )
            # every known status is emitted even at zero: an alert cannot fire on a
            # series that only appears once something has already gone wrong
            for status in ("QUEUED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED"):
                rows.setdefault(status, 0)
            for status in sorted(rows):
                lines.append(_gauge(
                    "cryptoscan_jobs_by_status", int(rows[status] or 0),
                    "Scan jobs by terminal or in-flight status",
                    f'status="{status}"'))
            oldest = session.execute(
                select(ScanJob.created_at).where(ScanJob.status == "QUEUED")
                .order_by(ScanJob.created_at.asc()).limit(1)
            ).scalar_one_or_none()
            if oldest is not None:
                moment = oldest if oldest.tzinfo else oldest.replace(tzinfo=timezone.utc)
                age = max(0.0, (datetime.now(timezone.utc) - moment).total_seconds())
                lines.append(_gauge(
                    "cryptoscan_jobs_oldest_queued_seconds", round(age, 1),
                    "Age of the oldest job still waiting in the queue"))
            else:
                lines.append(_gauge(
                    "cryptoscan_jobs_oldest_queued_seconds", 0,
                    "Age of the oldest job still waiting in the queue"))
    except Exception as exc:  # noqa: BLE001 — a metrics surface must not 500
        logger.warning("job_metrics_unavailable", extra={"error_type": type(exc).__name__})

    # the delayed-retry set, the dead-letter list and live worker leases live in
    # Redis; the API reads the counts directly rather than importing the worker,
    # so the queue's condition is visible even when no worker process is up
    redis_url = os.environ.get("REDIS_URL", "").strip()
    if redis_url:
        try:
            import redis  # noqa: PLC0415 — optional dependency of the API image

            client = redis.Redis.from_url(
                redis_url, socket_connect_timeout=0.5, socket_timeout=0.5)
            queue = os.environ.get("JOB_QUEUE_NAME", "cryptoscan:jobs:queue")
            lines.append(_gauge(
                "cryptoscan_jobs_retry_scheduled", int(client.zcard(f"{queue}:retry") or 0),
                "Jobs waiting in the delayed-retry set"))
            lines.append(_gauge(
                "cryptoscan_jobs_dead_letter", int(client.llen(f"{queue}:dead") or 0),
                "Jobs moved to the dead-letter list"))
            alive = 0
            for key in client.scan_iter(match=f"{queue}:worker:*", count=200):
                alive += 1
            lines.append(_gauge(
                "cryptoscan_workers_alive", alive,
                "Worker leases currently held (0 means nothing is consuming)"))
        except Exception as exc:  # noqa: BLE001 — a metrics surface must not 500
            logger.warning("queue_metrics_unavailable",
                           extra={"error_type": type(exc).__name__})
    return lines


def _coverage_lines() -> list[str]:
    """Coverage of the last estate discovery, as metrics rather than a screen.

    The review asked for coverage health, and the product already computes it per
    run: a coverage matrix with one row per plane and a status that is never a
    percentage of "crypto discovered". Emitting it as labelled gauges is what
    turns "a plane stopped collecting" into something an alert can see.

    The read is platform-wide on purpose (:func:`platform_scope`), because a
    metrics endpoint has no tenant context; the limit is stated in guide 117.
    """
    lines: list[str] = []
    try:
        from db.connection.session import SessionLocal
        from db.repositories.scan_run_repository import ScanRunRepository
        from db.tenancy import platform_scope

        with platform_scope(), SessionLocal() as session:
            runs = ScanRunRepository(session).list_runs(
                limit=1, target_kind="estate-discovery")
            if not runs:
                return lines
            payload = runs[0].result or {}
            rows = ((payload.get("coverage") or {}).get("rows")
                    or (payload.get("coverage") or {}).get("matrix") or [])
        unknown = 0
        for row in rows:
            plane = str(row.get("target") or row.get("plane") or "UNKNOWN")
            status = str(row.get("status") or "UNKNOWN").upper()
            if status in {"UNKNOWN", "NOT_OBSERVED", "NOT_ATTEMPTED", "FAILED", "PARTIAL"}:
                unknown += 1
            lines.append(_gauge(
                "cryptoscan_coverage_plane", 1,
                "One series per plane in the last estate discovery, labelled by status",
                f'plane="{plane}",status="{status}"'))
            expected = row.get("expected")
            collected = row.get("collected")
            if isinstance(expected, int) and expected:
                ratio = round(float(collected or 0) / float(expected), 4)
                lines.append(_gauge(
                    "cryptoscan_coverage_collected_ratio", ratio,
                    "Targets read over targets expected in the last discovery",
                    f'plane="{plane}"'))
        lines.append(_gauge(
            "cryptoscan_coverage_planes_unknown", unknown,
            "Planes not fully covered in the last estate discovery"))
    except Exception as exc:  # noqa: BLE001 — a metrics surface must not 500
        logger.warning("coverage_metrics_unavailable", extra={"error_type": type(exc).__name__})
    return lines


def _agent_health_lines() -> list[str]:
    """Agent fleet health: reporting count, and how old the freshest check-in is.

    An agent that stops reporting is the quietest failure in the estate: its
    last observations stay in the catalogue, so every screen keeps answering
    with data that is silently ageing. ``cryptoscan_agents_reporting`` counts the
    agents whose last heartbeat is inside the staleness window, and the age gauge
    is the fleet's *worst* check-in, because the operator needs the outlier.
    """
    lines: list[str] = []
    try:
        from datetime import datetime, timedelta, timezone

        from sqlalchemy import func, select

        from db.connection.session import SessionLocal
        from db.models.control_plane import Agent

        window = timedelta(seconds=int(os.environ.get("AGENT_STALE_SECONDS", "600")))
        now = datetime.now(timezone.utc)
        with SessionLocal() as session:
            total = int(session.execute(
                select(func.count()).select_from(Agent)).scalar_one() or 0)
            seen = [row for row in session.execute(
                select(Agent.last_heartbeat_at)).scalars().all()]
        reporting = 0
        worst: float | None = None
        for moment in seen:
            if moment is None:
                worst = None if worst is None else max(worst, float("inf"))
                continue
            aware = moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)
            age = (now - aware).total_seconds()
            if age <= window.total_seconds():
                reporting += 1
            worst = age if worst is None else max(worst, age)
        lines.append(_gauge("cryptoscan_agents_enrolled", total, "Agents enrolled"))
        lines.append(_gauge("cryptoscan_agents_reporting", reporting,
                            "Agents whose last heartbeat is inside the staleness window"))
        lines.append(_gauge(
            "cryptoscan_agent_last_seen_seconds", 0 if worst is None else round(worst, 1),
            "Age of the stalest agent check-in (0 when no agent exists)"))
    except Exception as exc:  # noqa: BLE001 — a metrics surface must not 500
        logger.warning("agent_metrics_unavailable", extra={"error_type": type(exc).__name__})
    return lines


def _estate_health_lines() -> list[str]:
    """Evidence and estate freshness: the two numbers a BOM claim rests on.

    A BOM is only as current as the observations behind it, and a stale
    catalogue is the failure mode where every screen still answers. Both are
    gauges rather than counters because the question is "how bad is it now".
    """
    lines: list[str] = []
    try:
        from sqlalchemy import func, select

        from db.connection.session import SessionLocal
        from db.models.estate_catalog import (
            EstateAssetRecord, EstateEvidenceRecord, EstateObservationRecord,
        )

        with SessionLocal() as session:
            def _count(model, *where):
                stmt = select(func.count()).select_from(model)
                for clause in where:
                    stmt = stmt.where(clause)
                return int(session.execute(stmt).scalar_one() or 0)

            lines.append(_gauge("cryptoscan_estate_assets", _count(EstateAssetRecord),
                                "Assets in the estate catalogue"))
            lines.append(_gauge(
                "cryptoscan_estate_assets_stale",
                _count(EstateAssetRecord, EstateAssetRecord.lifecycle_state == "STALE"),
                "Catalogue assets no longer observed"))
            lines.append(_gauge("cryptoscan_evidence_records", _count(EstateEvidenceRecord),
                                "Stored evidence records"))
            lines.append(_gauge(
                "cryptoscan_evidence_records_stale",
                _count(EstateEvidenceRecord, EstateEvidenceRecord.lifecycle_state == "STALE"),
                "Evidence records no longer produced by any collector"))
            lines.append(_gauge(
                "cryptoscan_observations_current",
                _count(EstateObservationRecord,
                       EstateObservationRecord.lifecycle_state == "CURRENT"),
                "Facts currently asserted by the twin"))
    except Exception as exc:  # noqa: BLE001 — the table may not exist on an old schema
        logger.warning("estate_metrics_unavailable", extra={"error_type": type(exc).__name__})
    return lines



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

    lines.extend(_job_lifecycle_lines())
    lines.extend(_agent_health_lines())
    lines.extend(_coverage_lines())
    lines.extend(_estate_health_lines())
    lines.extend(_dependency_lines())
    lines.extend(_operational_counter_lines())
    lines.extend(_telecom_lines())
    lines.append(_gauge("cryptoscan_api_db_reachable", 1, "Database reachable for metrics"))
    return Response(content="".join(lines), media_type="text/plain; version=0.0.4; charset=utf-8")
