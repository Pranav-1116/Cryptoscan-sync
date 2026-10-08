"""Platform self-observability: Prometheus metrics, traces, SLO burn,
self-alerts and capacity forecasting (everything measured on THIS process).
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


from fastapi import APIRouter, Depends, Query, Request

from api.dependencies import get_current_user, get_db_session

router = APIRouter(prefix="/ops", tags=["ops"])


@router.get("/metrics")
def prometheus_metrics(request: Request, user: str = Depends(get_current_user)):
    from fastapi.responses import PlainTextResponse

    registry = request.app.state.metrics
    return PlainTextResponse(registry.render_prometheus(),
                             media_type="text/plain; version=0.0.4")


@router.get("/traces")
def recent_traces(request: Request, limit: int = Query(50, ge=1, le=500),
                  slower_than_ms: float | None = Query(None, ge=0),
                  user: str = Depends(get_current_user)):
    return {"spans": request.app.state.traces.recent(limit, slower_than_ms=slower_than_ms)}


@router.get("/slo")
def slo_status(request: Request, user: str = Depends(get_current_user)):
    from observability.metrics import compute_slo

    registry = request.app.state.metrics
    return compute_slo(registry.window_events())


@router.get("/alerts")
def self_alerts(request: Request, user: str = Depends(get_current_user),
                db=Depends(get_db_session)):
    from observability.metrics import compute_slo, evaluate_self_alerts

    registry = request.app.state.metrics
    slo = compute_slo(registry.window_events())
    bus_lag: dict[str, int] = {}
    cbom_stale: list[str] = []
    try:
        # operator aggregate: platform partition + every tenant partition on
        # disk (self-monitoring must see the whole deployment, never one
        # scope). Tenants reading their own stream use their partition via
        # the /stream endpoints; this is the only cross-partition reader,
        # and it is operator-only.
        from eventstream.bus import iter_bus_partitions
        from eventstream.livecbom import LiveCbomService
        from eventstream.partitions import iter_tenant_partition_dirs
        import os

        seen_topic_lag: dict[str, int] = {}
        for bus in iter_bus_partitions():
            stats = bus.stats()
            for topic, info in stats.get("topics", {}).items():
                worst = max((g.get("lag", 0) for g in
                             info.get("consumer_groups", {}).values()), default=0)
                seen_topic_lag[topic] = max(seen_topic_lag.get(topic, 0), worst)
        bus_lag = seen_topic_lag

        base_store = os.environ.get("CBOM_STORE_DIR") or os.path.join(
            os.environ.get("CRYPTOSCAN_SNAPSHOT_DIR", "data"), "live_cbom")
        stores = [base_store] + [str(p) for p in iter_tenant_partition_dirs(base_store)]
        for store in stores:
            svc = LiveCbomService(store)
            for system in svc.list_systems():
                current = svc.current(system)
                if current and current.get("freshness", {}).get("stale"):
                    cbom_stale.append(system)
    except Exception as _handler_exc:
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        pass  # bus/CBOM optional for the alert sweep
    alerts = evaluate_self_alerts(registry, slo=slo, bus_lag=bus_lag,
                                  cbom_stale=cbom_stale)
    # publish to the alerts topic so subscribers see platform self-alerts too
    fired: list[dict] = []
    if alerts:
        try:
            from eventstream.bus import get_bus

            for a in alerts:
                env = get_bus().publish("alerts", a, key="platform-self",
                                        source="ops-self-monitor")
                a["alert_seq"] = env["seq"]
                fired.append(a)
        except Exception:
            fired = alerts
    return {"alerts": fired, "slo": slo, "watching":
            {"bus_lag": bus_lag, "cbom_stale": cbom_stale}}


@router.get("/capacity/forecast")
def capacity_forecast(user: str = Depends(get_current_user),
                      db=Depends(get_db_session)):
    """Deterministic growth projection from the append-only metering trail."""
    from sqlalchemy import func as sa_func

    from observability.metrics import forecast_quota

    from db.models.tenant import Tenant, TenantUsageEvent

    # Month bucketing must work on both supported dialects: SQLite has
    # strftime(), PostgreSQL has to_char(). The previous strftime-only
    # expression 500'd on every PostgreSQL deployment (compliance burn,
    # 2026-10-04).
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        month = sa_func.to_char(TenantUsageEvent.created_at, "YYYY-MM")
    else:
        month = sa_func.strftime("%Y-%m", TenantUsageEvent.created_at)
    plan_limit = {"FREE": 200, "PRO": 20000, "ENTERPRISE": None}

    def _series(tenant_ids: list[str] | None) -> list[float]:
        q = db.query(month.label("m"), sa_func.sum(TenantUsageEvent.amount))
        if tenant_ids is not None:
            q = q.filter(TenantUsageEvent.tenant_id.in_(tenant_ids))
        rows = q.group_by("m").order_by("m").all()
        return [float(total or 0) for _m, total in rows]

    usage_by_month = _series(None)
    projections = {}
    for plan in sorted({t.plan for t in db.query(Tenant).all()}):
        ids = [t.id for t in db.query(Tenant).filter(Tenant.plan == plan).all()]
        projections[plan] = forecast_quota(_series(ids), plan_limit.get(plan))
    return {"estate_usage_by_month": usage_by_month, "plans": projections,
            "note": "linear projection from the append-only metering trail; "
                    "deterministic, no invented growth assumptions beyond the "
                    "observed trend"}
