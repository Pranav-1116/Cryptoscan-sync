"""Operations — live monitoring of the agent-fed estate.

Four read-only views over what the agents already sent (see ``api.operations_monitor``):

* ``GET /operations/fleet``    — every agent: liveness, delivery health, planes and sources;
* ``GET /operations/hosts``    — every observed host: runtime services, listeners, loaded
  libraries, certificates, algorithms and its signed performance samples;
* ``GET /operations/activity`` — one timeline: estate changes, threat patterns, agent
  lifecycle, remediation actions and agents that went silent;
* ``GET /operations/monitor``  — overall status, deterministic alerts, fleet freshness.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from api import estate_change_feed, estate_contributions
from api import operations_monitor as ops
from api.dependencies import get_current_user, get_db_session
from api.routers import estate_graph, ingestion
from db.repositories.scan_run_repository import ScanRunRepository
from db.tenancy import current_tenant

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/operations", tags=["operations"])


# --------------------------------------------------------------------------- #
# loaders — plain dicts in, so the rules in operations_monitor stay pure
# --------------------------------------------------------------------------- #


def _agents(db: Session) -> list[dict[str, Any]]:
    from db.repositories.control_plane_repository import ControlPlaneRepository

    rows = []
    for a in ControlPlaneRepository(db).list_agents(tenant_id=current_tenant()):
        rows.append({
            "id": a.id, "name": a.name, "status": a.status, "version": a.version,
            "target_version": a.target_version, "last_heartbeat_at": a.last_heartbeat_at,
            "healthy": a.healthy, "link": a.link, "offline_events_buffered": a.offline_events_buffered,
            "environment": a.environment, "platform": a.platform, "last_seen_ip": a.last_seen_ip,
            "created_at": a.created_at, "tenant_id": a.tenant_id,
        })
    return rows


def _latest_run(db: Session) -> Any:
    runs = ScanRunRepository(db).list_runs(limit=1, target_kind=estate_graph.RUN_KIND, owner=current_tenant())
    return runs[0] if runs else None


def _slices(run: Any) -> dict[str, dict[str, Any]]:
    if run is None:
        return {}
    payload = ((run.result or {}).get("estate_discovery") or {})
    _base, contributions = estate_contributions.stored_slices(payload)
    return {str(k): dict(v or {}) for k, v in contributions.items()}


def _performance(db: Session, agents: list[dict[str, Any]], names: set[str], now: datetime) -> dict[str, dict[str, Any]]:
    from db.repositories.performance_repository import PerformanceRepository

    from api import cryptava_performance as cp

    repo = PerformanceRepository(db)
    by_name = {a["name"]: a for a in agents}
    start = now - timedelta(minutes=ops.PERF_WINDOW_MINUTES)
    heartbeat = ops.heartbeat_seconds()
    out: dict[str, dict[str, Any]] = {}
    for name in sorted(names):
        tenants = []
        for candidate in ((by_name.get(name) or {}).get("tenant_id"), current_tenant(), cp.default_tenant()):
            if candidate and candidate not in tenants:
                tenants.append(candidate)
        samples: list[dict[str, Any]] = []
        for tenant in tenants:
            try:
                rows = repo.query_metrics(tenant, asset_id=cp.host_asset_id(name), window_start=start, limit=5000)
            except Exception:  # noqa: BLE001 — a missing table is "not sampled", not a crash
                logger.debug("performance read failed for %s", name, exc_info=True)
                rows = []
            if rows:
                samples = [{"metric_name": m.metric_name, "value": m.metric_value, "unit": m.unit,
                            "labels": dict(m.labels or {}), "observed_at": m.observed_at} for m in rows]
                break
        out[name] = ops.performance_summary(samples, now, heartbeat=heartbeat)
    return out


def _connection(db: Session) -> dict[str, Any]:
    last = ingestion._last_observation(db)
    from shared_models import live_estate

    return live_estate.connection_state(ingestion.last_created_at(last), interval_seconds=ingestion.interval_seconds())


def _changes(db: Session, limit: int = 200) -> list[dict[str, Any]]:
    rows = estate_change_feed.list_events(db, tenant_id=current_tenant(), limit=limit)
    return [estate_change_feed.public_event(row) for row in rows]


def _patterns(db: Session, user: str, window_seconds: int) -> list[dict[str, Any]]:
    try:
        result = estate_graph.estate_threat_patterns(
            window_seconds=window_seconds, include_acknowledged=True, limit=200, user=user, db=db)
        return list(result.get("patterns") or [])
    except Exception:  # noqa: BLE001 — no correlation is reported as none, never invented
        logger.debug("threat pattern read failed", exc_info=True)
        return []


def _audit(db: Session, limit: int = 300) -> list[dict[str, Any]]:
    from db.models.user import AuditLog

    stmt = (select(AuditLog)
            .where(or_(AuditLog.action.like("control.agent%"), AuditLog.action.like("remediation.task%"),
                       AuditLog.action == "control.emergency_stop"))
            .order_by(AuditLog.created_at.desc()).limit(limit))
    return [{"id": r.id, "action": r.action, "actor": r.actor, "target_type": r.target_type,
             "target_id": r.target_id, "detail": r.detail, "outcome": r.outcome, "created_at": r.created_at}
            for r in db.execute(stmt).scalars()]


def _state(db: Session, now: datetime) -> tuple[dict[str, Any], dict[str, dict[str, Any]], dict[str, dict[str, Any]], Any]:
    agents = _agents(db)
    run = _latest_run(db)
    slices = _slices(run)
    perf = _performance(db, agents, {a["name"] for a in agents} | set(slices), now)
    stale_after = _connection(db)["stale_after_seconds"]
    view = ops.fleet(agents, slices, perf, now, heartbeat=ops.heartbeat_seconds(), stale_after=stale_after)
    return view, slices, perf, run


# --------------------------------------------------------------------------- #
# endpoints
# --------------------------------------------------------------------------- #


@router.get("/fleet")
def operations_fleet(_user: str = Depends(get_current_user), db: Session = Depends(get_db_session)) -> dict[str, Any]:
    """Every agent, with liveness, delivery health, and the planes and sources it read."""
    now = datetime.now(timezone.utc)
    view, _slices_, _perf, run = _state(db, now)
    view["run_id"] = run.id if run is not None else None
    return view


@router.get("/hosts")
def operations_hosts(_user: str = Depends(get_current_user), db: Session = Depends(get_db_session)) -> dict[str, Any]:
    """Every host an agent observed: what runs on it, what crypto it uses, how loaded it is."""
    now = datetime.now(timezone.utc)
    view, slices, perf, run = _state(db, now)
    result = ops.hosts(view, slices, perf, now, heartbeat=ops.heartbeat_seconds())
    result["run_id"] = run.id if run is not None else None
    return result


@router.get("/activity")
def operations_activity(
    window_hours: int = Query(default=24, ge=1, le=168),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    """One timeline of what happened in the estate and to the agents watching it."""
    now = datetime.now(timezone.utc)
    view, _slices_, _perf, _run = _state(db, now)
    result = ops.activity(
        changes=_changes(db), patterns=_patterns(db, user, window_hours * 3600), audit=_audit(db),
        fleet_view=view, now=now)
    result["window_hours"] = window_hours
    return result


@router.get("/monitor")
def operations_monitor(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)) -> dict[str, Any]:
    """Is the estate being watched right now — and what needs somebody's attention?"""
    now = datetime.now(timezone.utc)
    view, _slices_, _perf, run = _state(db, now)
    connection = _connection(db)
    coverage = (((run.result or {}).get("estate_summary") or {}).get("coverage") if run is not None else None)
    changes = _changes(db)
    patterns = _patterns(db, user, 3600)
    keys = ingestion.trusted_keys()
    trust = [] if keys else [f"{ingestion.NO_TRUSTED_KEY}: observations are accepted and recorded as "
                             f"unauthenticated because no key is configured ({ingestion.TRUST_KEY_ENV})"]
    alert_rows = ops.alerts(view, connection=connection, coverage=coverage, changes=changes,
                            patterns=patterns, trust_findings=trust)
    status = ops.overall(view, alert_rows)
    last_change = changes[0] if changes else None
    return {
        "schema": ops.MONITOR_SCHEMA,
        "at": now.isoformat(),
        "status": status,
        "connection": connection,
        "coverage": coverage,
        "alerts": alert_rows,
        "alert_counts": {sev: sum(1 for a in alert_rows if a["severity"] == sev)
                         for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
        "fleet": {
            "heartbeat_seconds": view["heartbeat_seconds"],
            "late_after_seconds": view["late_after_seconds"],
            "offline_after_seconds": view["offline_after_seconds"],
            "totals": view["totals"],
            "agents": [{
                "name": a["name"], "system": a["system"], "host": a["host"], "liveness": a["liveness"],
                "healthy": a["healthy"], "buffered": a["buffered"], "plane_states": a["plane_states"],
                "performance": a["performance"], "issues": a["issues"],
            } for a in view["agents"]],
        },
        "changes": {
            "total": len(changes),
            "unacknowledged": sum(1 for c in changes if not c.get("acknowledged")),
            "last_at": (last_change or {}).get("first_detected_at"),
            "last_headline": (last_change or {}).get("headline"),
        },
        "twin": {
            "run_id": run.id if run is not None else None,
            "recorded_at": ops.iso(getattr(run, "created_at", None)),
            "assets": (((run.result or {}).get("estate_summary") or {}).get("assets") if run is not None else None),
            "evidence": (((run.result or {}).get("estate_summary") or {}).get("evidence") if run is not None else None),
        },
        "limits": ops.LIMITS,
    }
