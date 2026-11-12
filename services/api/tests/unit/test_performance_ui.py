"""UI brief wiring (docs/performance/03_UI_SPEC.md): the landing's headline
cards, the HSM & KMS workspace and the workload intelligence surface —
production values from delivered telemetry only, unknowns stay unknown,
and a correlation never upgrades to causation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register all tables
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models.performance import PerformanceMetric as PerformanceMetricRow

NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)
TENANT = "tenant_perf_ui"


def _make_app():
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "analyst"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session, engine


def _metric(session, name, value, asset="asset-1", minutes=10, quality="valid", unit=None):
    unit = unit or ("percent" if name.endswith("_pct") else "ms" if name.endswith("_ms") else "count")
    session.add(PerformanceMetricRow(
        metric_id=f"m-{name}-{asset}-{minutes}", tenant_id=TENANT, asset_id=asset,
        metric_name=name, metric_type="gauge",
        metric_value=value, unit=unit, source_id="collector-1",
        observed_at=NOW - timedelta(minutes=minutes),
        labels=None, quality_status=quality,
    ))


async def _get(app, path, params):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        return await c.get(path, params=params)


def _params():
    return {"tenant_id": TENANT,
            "window_start": (NOW - timedelta(hours=2)).isoformat(),
            "window_end": (NOW + timedelta(hours=1)).isoformat()}


@pytest.mark.asyncio
async def test_overview_headline_cards_delivered_and_unknown_never_zero():
    app, session, engine = _make_app()
    _metric(session, "cpu.utilization_pct", 61.5, asset="srv-a")
    _metric(session, "ram.utilization_pct", 72.0, asset="srv-a", minutes=20)
    _metric(session, "api.latency_p95_ms", 28.4, asset="svc-pay")
    _metric(session, "api.error_rate_pct", 0.6, asset="svc-pay", minutes=30)
    session.flush()
    res = await _get(app, "/api/v1/performance/overview", _params())
    assert res.status_code == 200
    body = res.json()
    assert body["cpu_utilization_pct"]["value"] == 61.5
    assert body["memory_utilization_pct"]["value"] == 72.0
    assert body["app_p95_latency_ms"]["value"] == 28.4
    assert body["error_rate_pct"]["value"] == 0.6
    # estate tiles for undelivered families are unknown — never zero fillers
    assert body["network_throughput_mbps"]["state"] == "unknown"
    assert body["network_throughput_mbps"]["value"] is None
    assert body["requests_per_sec"]["value"] is None
    assert "unknown, never zero" in body["network_throughput_mbps"]["note"]
    # per-service row: delivered columns carry values, unread stay null
    svc = body["services"][0]
    assert svc["service"] == "svc-pay"
    assert svc["p95_latency_ms"] == 28.4
    assert svc["error_rate_pct"] == 0.6
    assert svc["requests_per_sec"] is None


@pytest.mark.asyncio
async def test_hsm_workspace_read_only_projection_unknowns_stay_unknown():
    app, session, engine = _make_app()
    _metric(session, "crypto.hsm_operation_latency_ms", 2.7, asset="hsm-payments-1")
    _metric(session, "crypto.hsm_queue_depth", 3, asset="hsm-payments-1", minutes=15, unit="count")
    _metric(session, "crypto.hsm_operation_latency_ms", 3.1, asset="hsm-payments-1", minutes=25)
    session.flush()
    res = await _get(app, "/api/v1/performance/hsm", _params())
    assert res.status_code == 200
    body = res.json()
    device = body["devices"][0]
    assert device["device"] == "hsm-payments-1"
    assert device["operation_latency_ms"] == 2.7  # latest delivered (10 min ago beats 25)
    assert device["queue_depth"] == 3
    # utilization and provider errors were never delivered — unknown, not zero
    assert device["utilization_pct"] is None
    assert device["provider_errors"] is None
    assert body["measurement_kind"] == "observed-production"
    assert "key material is never collected" in body["note"]
    assert "never interfered" in body["note"]


@pytest.mark.asyncio
async def test_workloads_report_correlation_only_causation_unproven():
    app, session, engine = _make_app()
    _metric(session, "crypto.tls_handshake_ms", 41.0, asset="gw-1")
    _metric(session, "api.latency_p95_ms", 210.0, asset="svc-pay")
    _metric(session, "api.requests_per_sec", 520, asset="svc-pay", minutes=5, unit="requests/sec")
    session.flush()
    res = await _get(app, "/api/v1/performance/workloads", _params())
    assert res.status_code == 200
    body = res.json()
    assert body["causation"] == "unproven"
    assert "api.requests_per_sec" in body["workload_metrics"]
    candidate = body["correlation_candidates"][0]
    assert candidate["causation"] == "unproven"
    assert "timestamps and traces must correlate before causation" in candidate["basis"]
    assert "never proves causation" in candidate["basis"]


@pytest.mark.asyncio
async def test_hsm_without_telemetry_is_honest_not_a_healthy_device():
    app, session, engine = _make_app()
    session.flush()
    res = await _get(app, "/api/v1/performance/hsm", _params())
    assert res.status_code == 200
    body = res.json()
    assert body["devices"] == []
    assert body["families"] == {}
