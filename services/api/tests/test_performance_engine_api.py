"""ZELNX Performance query API tests (docs/performance/01_PRODUCT_SPEC.md,
§6 and §8).

The query namespace is time-bounded and tenant-scoped, computed on read
so the same inputs always give the same answers; every gap is named;
the §8 investigation never upgrades correlation to causation; and a
benchmark result is never presented as production performance.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

NOW = datetime.now(timezone.utc)
START = (NOW - timedelta(hours=2)).isoformat()
END = NOW.isoformat()


def _metric(**over):
    base = {
        "metric_id": "m-0001",
        "tenant_id": "tenant_001",
        "asset_id": "asset_gateway_001",
        "metric_name": "network.rtt_ms",
        "metric_type": "histogram",
        "metric_value": 42.0,
        "unit": "ms",
        "source_id": "collector_node_01",
        "observed_at": (NOW - timedelta(minutes=30)).isoformat(),
        "quality_status": "valid",
    }
    base.update(over)
    return base


@pytest.fixture()
def api():
    from db.connection.session import Base
    from db.models.performance import (
        PerformanceAggregate, PerformanceAlert, PerformanceAsset,
        PerformanceBaseline, PerformanceBenchmarkRun,
        PerformanceCapacityForecast, PerformanceCollectorHealth,
        PerformanceIncident, PerformanceMetric, PerformanceMetricDefinition,
        PerformanceSloPolicy,
    )

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False},
        poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=[
        PerformanceMetric.__table__, PerformanceMetricDefinition.__table__,
        PerformanceCollectorHealth.__table__, PerformanceAsset.__table__,
        PerformanceAggregate.__table__, PerformanceBaseline.__table__,
        PerformanceAlert.__table__, PerformanceIncident.__table__,
        PerformanceSloPolicy.__table__, PerformanceCapacityForecast.__table__,
        PerformanceBenchmarkRun.__table__])
    session = sessionmaker(bind=engine)()

    from api import dependencies
    from api.routers import performance
    from api.errors import install_error_contract

    app = FastAPI()
    app.include_router(performance.router, prefix="/api/v1")
    install_error_contract(app)
    app.dependency_overrides[dependencies.get_db_session] = lambda: session
    app.dependency_overrides[dependencies.get_current_user] = lambda: "auditor"
    app.dependency_overrides[dependencies.require_intelligence_writer] = lambda: "writer"
    app.dependency_overrides[dependencies.require_intelligence_manager] = lambda: "manager"
    return TestClient(app)


def _seed(api, **over):
    res = api.post("/api/v1/performance/ingest", json=_metric(**over))
    assert res.status_code in (200, 201), res.text
    return res


def test_overview_tiles_are_unknown_never_zero(api):
    _seed(api)
    res = api.get("/api/v1/performance/overview",
                  params={"tenant_id": "tenant_001",
                          "window_start": START, "window_end": END})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["storage_usage_pct"]["state"] == "unknown"
    assert body["storage_usage_pct"]["value"] is None
    assert "never zero" in body["note"]
    assert body["network_throughput_mbps"]["state"] == "unknown"


def test_network_view_keeps_bandwidth_and_throughput_apart(api):
    _seed(api, metric_id="m-bw", metric_name="network.bandwidth_mbps",
          metric_type="gauge", metric_value=10000.0, unit="Mbps")
    _seed(api, metric_id="m-thr", metric_name="network.throughput_mbps",
          metric_type="gauge", metric_value=840.0, unit="Mbps")
    res = api.get("/api/v1/performance/network",
                  params={"tenant_id": "tenant_001",
                          "window_start": START, "window_end": END})
    body = res.json()
    assert body["bandwidth_capacity_mbps"]["value"] == 10000.0
    assert body["observed_throughput_mbps"]["value"] == 840.0
    assert "different" in body["note"], \
        "a 10 Gbps interface does not mean 10 Gbps is moving"


def test_query_windows_are_bounded_and_tenant_scoped(api):
    wide = api.get("/api/v1/performance/overview", params={
        "tenant_id": "tenant_001",
        "window_start": (NOW - timedelta(days=40)).isoformat(),
        "window_end": END})
    assert wide.status_code == 422
    assert "exceeds 31 days" in wide.json()["detail"]
    no_tenant = api.get("/api/v1/performance/overview", params={
        "window_start": START, "window_end": END})
    assert no_tenant.status_code in (422, 400)


def test_window_over_sample_budget_refuses_partial_analytics(api, monkeypatch):
    from db.repositories.performance_repository import PerformanceRepository

    def over_budget(_repo, tenant_id, **kwargs):
        assert tenant_id == "tenant_001"
        assert kwargs["limit"] == 5001
        return [object()] * 5001

    monkeypatch.setattr(PerformanceRepository, "query_metrics", over_budget)
    res = api.get("/api/v1/performance/overview", params={
        "tenant_id": "tenant_001", "window_start": START, "window_end": END})
    assert res.status_code == 409
    assert "narrow the time window" in res.json()["detail"]


def test_missing_asset_is_unknown_never_a_clean_result(api):
    res = api.get("/api/v1/performance/assets/asset_absent", params={
        "tenant_id": "tenant_001", "window_start": START, "window_end": END})
    assert res.status_code == 200
    body = res.json()
    assert body["metrics"] == {}
    assert "never a clean result" in body["note"]


def test_alerts_state_proven_and_not_proven(api):
    _seed(api, metric_id="m-base", metric_value=30.0,
          observed_at=(NOW - timedelta(hours=1, minutes=30)).isoformat())
    _seed(api, metric_id="m-base2", metric_value=31.0,
          observed_at=(NOW - timedelta(hours=1)).isoformat())
    for i in range(6):
        _seed(api, metric_id=f"m-hot-{i}", metric_value=90.0,
              observed_at=(NOW - timedelta(minutes=25 - i)).isoformat())
    res = api.get("/api/v1/performance/alerts", params={
        "tenant_id": "tenant_001", "window_start": START, "window_end": END})
    assert res.status_code == 200, res.text
    alerts = res.json()
    assert alerts, "a measured threshold crossing raises an alert"
    top = alerts[0]
    assert top["proven"] and top["not_proven"]
    assert top["supporting_measurements"]["value_count"] >= 6
    assert top["severity"] in ("WARNING", "CRITICAL", "INFO")


def test_baselines_are_reproducible_and_named(api):
    for i in range(6):
        _seed(api, metric_id=f"m-b-{i}", metric_value=30.0 + i,
              observed_at=(NOW - timedelta(minutes=55 - i * 5)).isoformat())
    params = {"tenant_id": "tenant_001",
              "window_start": START, "window_end": END}
    first = api.get("/api/v1/performance/baselines", params=params)
    second = api.get("/api/v1/performance/baselines", params=params)
    assert first.status_code == 200
    rows = first.json()
    assert rows and rows[0]["method"] == "median-absolute-deviation-window"
    assert rows[0]["sample_count"] == 6
    assert first.json() == second.json(), "same inputs, same answers"
    assert "reproducible" in rows[0]["note"]


def test_capacity_is_forecast_not_fact(api):
    for i in range(5):
        _seed(api, metric_id=f"m-c-{i}",
              metric_name="storage.used_bytes", metric_type="gauge",
              metric_value=100.0 + i * 10, unit="bytes",
              observed_at=(NOW - timedelta(minutes=50 - i * 10)).isoformat())
    res = api.get("/api/v1/performance/capacity", params={
        "tenant_id": "tenant_001", "window_start": START, "window_end": END,
        "capacity_value": 1000.0})
    assert res.status_code == 200
    rows = res.json()
    assert rows[0]["status"] == "forecast"
    assert "forecast, not fact" in rows[0]["disclaimer"]
    assert rows[0]["estimated_seconds_to_exhaustion"] > 0


def test_the_investigation_never_upgrades_correlation_to_causation(api):
    change_time = (NOW - timedelta(minutes=40)).isoformat()
    for i in range(5):
        _seed(api, metric_id=f"m-pre-{i}", metric_value=35.0,
              observed_at=(NOW - timedelta(hours=1, minutes=30 - i)).isoformat())
    for i in range(5):
        _seed(api, metric_id=f"m-post-{i}", metric_value=82.0,
              observed_at=(NOW - timedelta(minutes=30 - i)).isoformat())
    res = api.get("/api/v1/performance/reports", params={
        "tenant_id": "tenant_001",
        "metric_name": "network.rtt_ms",
        "change_time": change_time,
        "change_description": "TLS configuration changed",
        "evidence_ids": "ev-001"})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["conclusion"] == "Correlation detected — causation unproven"
    joined = " ".join(body["evidence"]["not_proven"])
    assert "A time correlation alone does not prove" in joined
    assert "Other possible causes still need investigation" in joined
    assert body["difference_p95"] is not None


def test_cryptography_view_is_observed_production_only(api):
    _seed(api, metric_id="m-tls", metric_name="crypto.tls_handshake_ms",
          metric_type="histogram", metric_value=35.0, unit="ms")
    res = api.get("/api/v1/performance/cryptography", params={
        "tenant_id": "tenant_001", "window_start": START, "window_end": END})
    body = res.json()
    assert body["measurement_kind"] == "observed-production"
    assert "never presented as production" in body["note"]


def test_benchmarks_are_controlled_and_never_invented(api):
    res = api.post("/api/v1/performance/benchmarks", json={
        "tenant_id": "tenant_001", "algorithm": "Ed25519", "sample_count": 5})
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["measurement_kind"] == "controlled_benchmark"
    assert "never production traffic performance" in body["note"]
    for field in ("hardware", "software", "provider", "algorithm",
                  "algorithm_parameters", "methodology", "concurrency",
                  "sample_count"):
        assert body["method"][field], f"{field} required for reproducibility"
    unsupported = api.post("/api/v1/performance/benchmarks", json={
        "tenant_id": "tenant_001", "algorithm": "ML-KEM-768", "sample_count": 5})
    assert unsupported.status_code == 422
    assert "external act" in unsupported.json()["detail"]


def test_infrastructure_and_cloud_views_are_named_domains(api):
    _seed(api, metric_id="m-cpu", metric_name="cpu.utilization_pct",
          metric_type="gauge", metric_value=37.5, unit="percent")
    _seed(api, metric_id="m-pod", metric_name="k8s.pod_restarts",
          metric_type="counter", metric_value=2.0, unit="count")
    infra = api.get("/api/v1/performance/infrastructure", params={
        "tenant_id": "tenant_001", "window_start": START, "window_end": END})
    assert infra.status_code == 200, infra.text
    body = infra.json()
    assert body["domain"] == "infrastructure"
    assert "cpu.utilization_pct" in body["metrics"]
    assert "k8s.pod_restarts" not in body["metrics"], \
        "a domain view names its own domain only"
    cloud = api.get("/api/v1/performance/cloud", params={
        "tenant_id": "tenant_001", "window_start": START, "window_end": END})
    assert cloud.json()["domain"] == "container_cloud"
    assert "k8s.pod_restarts" in cloud.json()["metrics"]


def test_slo_absence_is_not_compliance(api):
    res = api.get("/api/v1/performance/slo", params={
        "tenant_id": "tenant_001", "window_start": START, "window_end": END})
    assert res.status_code == 200
    assert res.json() == [], "no policies is an honest empty list"
    empty = api.get("/api/v1/performance/benchmarks",
                    params={"tenant_id": "tenant_001"})
    assert empty.status_code == 200
    assert empty.json()["runs"] == []
    assert "never production traffic performance" in empty.json()["note"]
