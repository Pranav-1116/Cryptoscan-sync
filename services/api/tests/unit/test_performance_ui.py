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


def _metric(session, name, value, asset="asset-1", minutes=10, quality="valid", unit=None, labels=None):
    unit = unit or ("percent" if name.endswith("_pct") else "ms" if name.endswith("_ms") else "count")
    session.add(PerformanceMetricRow(
        metric_id=f"m-{name}-{asset}-{minutes}", tenant_id=TENANT, asset_id=asset,
        metric_name=name, metric_type="gauge",
        metric_value=value, unit=unit, source_id="collector-1",
        observed_at=NOW - timedelta(minutes=minutes),
        labels=labels, quality_status=quality,
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
async def test_applications_workspace_ten_metrics_and_honest_queue_depth():
    app, session, engine = _make_app()
    _metric(session, "api.requests_per_sec", 520, asset="svc-pay", unit="requests/sec")
    _metric(session, "api.latency_p50_ms", 28, asset="svc-pay")
    _metric(session, "api.latency_p95_ms", 210, asset="svc-pay", minutes=12)
    _metric(session, "api.error_rate_pct", 0.6, asset="svc-pay", minutes=22)
    _metric(session, "api.latency_p95_ms", 210, asset="svc-pay", minutes=5,
            labels={"endpoint": "POST /v1/payments"})
    _metric(session, "performance.regression_ms", 47, asset="svc-pay", minutes=15)
    session.flush()
    res = await _get(app, "/api/v1/performance/applications/workspace", _params())
    assert res.status_code == 200
    body = res.json()
    m = body["metrics"]
    assert m["requests_per_sec"]["value"] == 520
    assert m["latency_p95_ms"]["value"] == 210
    assert m["error_rate_pct"]["value"] == 0.6
    # queue depth has no collector — unknown with a named basis, never zero
    assert m["queue_depth"]["value"] is None
    assert m["queue_depth"]["state"] == "unknown"
    assert "no authorized collector" in m["queue_depth"]["note"]
    assert m["availability_pct"]["value"] is None  # never delivered
    # endpoint rows project controlled label keys only
    assert body["endpoints"][0]["endpoint"] == "POST /v1/payments"
    assert body["endpoints"][0]["service"] == "svc-pay"
    svc = body["services"][0]
    assert svc["service"] == "svc-pay"
    assert svc["p50_latency_ms"] == 28
    assert svc["timeout_rate_pct"] is None  # unread stays unknown
    caps = body["capabilities"]
    assert caps["service_level"]["state"] == "measured"
    assert caps["api_endpoints"]["state"] == "measured"
    assert caps["regression"]["state"] == "measured"
    assert caps["distributed_tracing"]["state"] == "not_collected"
    assert "payment credentials, authorization tokens and sensitive request payloads are never collected" in caps["distributed_tracing"]["basis"]
    assert "a link is not a latency" in caps["dependency_latency"]["basis"]
    assert "a slow transaction cannot be named" in caps["slow_transactions"]["basis"]
    assert body["regression"]["p95"] == 47


@pytest.mark.asyncio
async def test_infrastructure_workspace_links_only_verified_spine_identities():
    from db.models.hardware_live import HardwareAsset
    from db.models.system import System

    app, session, engine = _make_app()
    # srv-a exists as a hardware asset -> hw:srv-a; srv-sys is a System -> app:
    session.add(HardwareAsset(asset_id="srv-a", tenant_id=TENANT))
    session.add(System(id="srv-sys", name="Payments core", environment="PROD",
                       tenant_id=TENANT))
    _metric(session, "cpu.utilization_pct", 61.5, asset="srv-a")
    _metric(session, "ram.utilization_pct", 72.0, asset="srv-a", minutes=12)
    _metric(session, "cpu.utilization_pct", 33.0, asset="srv-sys", minutes=20)
    _metric(session, "cpu.utilization_pct", 88.0, asset="srv-ghost", minutes=5)
    _metric(session, "container.cpu_pct", 40.0, asset="pod-1", minutes=8)
    session.flush()
    res = await _get(app, "/api/v1/performance/infrastructure/workspace", _params())
    assert res.status_code == 200
    body = res.json()
    rows = {r["asset_id"]: r for r in body["inventory"]}
    assert rows["srv-a"]["link"] == "hw:srv-a"
    assert rows["srv-sys"]["link"] == "app:srv-sys"
    # an asset with no canonical spine record stays unlinked — never invented
    assert rows["srv-ghost"]["link"] is None
    assert rows["srv-ghost"]["link_state"] == "not established"
    assert rows["srv-a"]["cpu_pct"] == 61.5
    assert rows["srv-a"]["memory_pct"] == 72.0
    # virtualization is a named gap — not zeros, not a healthy host
    virt = body["categories"]["virtualization"]
    assert virt["state"] == "not_collected"
    assert "no authorized collector" in virt["basis"]
    assert "not a healthy host" in virt["basis"]
    # containers measured from delivered telemetry
    assert body["categories"]["containers"]["state"] == "measured"
    assert body["categories"]["cpu"]["state"] == "measured"


@pytest.mark.asyncio
async def test_infrastructure_workspace_without_telemetry_names_gaps():
    app, session, engine = _make_app()
    session.flush()
    res = await _get(app, "/api/v1/performance/infrastructure/workspace", _params())
    assert res.status_code == 200
    body = res.json()
    assert body["inventory"] == []
    assert body["trends"] == {}
    assert body["hardware_health"]["state"] == "not_collected"
    assert "never as healthy readings" in body["hardware_health"]["basis"]
    assert body["categories"]["cpu"]["state"] == "not_collected"


@pytest.mark.asyncio
async def test_hsm_without_telemetry_is_honest_not_a_healthy_device():
    app, session, engine = _make_app()
    session.flush()
    res = await _get(app, "/api/v1/performance/hsm", _params())
    assert res.status_code == 200
    body = res.json()
    assert body["devices"] == []
    assert body["families"] == {}
