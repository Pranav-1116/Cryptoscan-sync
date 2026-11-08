"""ZELNX Performance Intelligence API tests (docs/performance/01_PRODUCT_SPEC.md).

Phase 1 collection contracts, test-proven against the §10 success
criteria: unit/source/timestamp on every metric, tenant isolation,
missing telemetry never zero, idempotent ingestion, bounded labels, and
per-item batch outcomes with derived totals.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

AS_OF = "2026-11-07T04:00:00Z"


def _metric(**over):
    base = {
        "metric_id": "m-0001",
        "tenant_id": "tenant_001",
        "asset_id": "asset_gateway_001",
        "metric_name": "network.rtt_ms",
        "metric_type": "gauge",
        "metric_value": 42.0,
        "unit": "ms",
        "source_id": "collector_node_01",
        "observed_at": AS_OF,
        "quality_status": "valid",
    }
    base.update(over)
    return base


@pytest.fixture()
def api():
    from db.connection.session import Base
    from db.models.performance import (
        PerformanceCollectorHealth, PerformanceMetric, PerformanceMetricDefinition,
    )

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False},
        poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=[
        PerformanceMetric.__table__, PerformanceMetricDefinition.__table__,
        PerformanceCollectorHealth.__table__])
    session = sessionmaker(bind=engine)()

    from api import dependencies
    from api.routers import performance
    from api.errors import install_error_contract

    app = FastAPI()
    app.include_router(performance.router, prefix="/api/v1")
    install_error_contract(app)
    app.dependency_overrides[dependencies.get_db_session] = lambda: session
    app.dependency_overrides[dependencies.get_current_user] = lambda: "auditor"
    return TestClient(app)


def test_every_metric_carries_unit_source_and_timestamp(api):
    ok = api.post("/api/v1/performance/ingest", json=_metric())
    assert ok.status_code == 201, ok.text
    assert ok.json()["outcome"] == "inserted"
    for field, value in (("unit", None), ("source_id", None), ("observed_at", None)):
        refused = api.post("/api/v1/performance/ingest",
                           json=_metric(metric_id="m-bad", **{field: value}))
        assert refused.status_code == 422, f"{field} may not be absent"
    missing_unit = _metric(metric_id="m-bad2")
    del missing_unit["unit"]
    refused = api.post("/api/v1/performance/ingest", json=missing_unit)
    assert refused.status_code == 422


def test_missing_telemetry_is_never_drawn_as_zero(api):
    stale = api.post("/api/v1/performance/ingest", json=_metric(
        metric_id="m-stale", metric_value=0.0, quality_status="stale"))
    assert stale.status_code == 422, \
        "a stale measurement carries no value — a zero is a claim"
    stale_no_value = api.post("/api/v1/performance/ingest", json=_metric(
        metric_id="m-stale2", metric_value=None, quality_status="stale"))
    assert stale_no_value.status_code == 201
    missing_no_value = api.post("/api/v1/performance/ingest", json=_metric(
        metric_id="m-missing", metric_value=None, quality_status="missing"))
    assert missing_no_value.status_code == 201
    valid_without = api.post("/api/v1/performance/ingest", json=_metric(
        metric_id="m-none", metric_value=None, quality_status="valid"))
    assert valid_without.status_code == 422, \
        "a valid sample without a value is unknown telemetry, not a sample"


def test_ingestion_is_idempotent(api):
    first = api.post("/api/v1/performance/ingest", json=_metric())
    assert first.status_code == 201
    again = api.post("/api/v1/performance/ingest", json=_metric(metric_value=99.0))
    assert again.status_code == 200
    body = again.json()
    assert body["outcome"] == "duplicate"
    assert body["accepted_id"] == first.json()["accepted_id"], \
        "a duplicate reports the accepted identity, never a second row"


def test_labels_are_bounded_and_never_carry_secrets(api):
    secret = api.post("/api/v1/performance/ingest", json=_metric(
        metric_id="m-secret", labels={"password": "hunter2"}))
    assert secret.status_code == 422
    assert "never carries payloads" in secret.json()["detail"]
    unbounded = api.post("/api/v1/performance/ingest", json=_metric(
        metric_id="m-many", labels={f"k{i}": "v" for i in range(20)}))
    assert unbounded.status_code == 422
    assert "bounded cardinality" in unbounded.json()["detail"]


def test_batch_reports_partial_success_with_reasons(api):
    good = _metric()
    zeroed_stale = _metric(metric_id="m-2", metric_value=0.0,
                           quality_status="stale")
    secret = _metric(metric_id="m-3", labels={"private_key": "-----BEGIN"})
    res = api.post("/api/v1/performance/ingest/batch",
                   json={"metrics": [good, zeroed_stale, secret]})
    assert res.status_code == 200, res.text
    body = res.json()
    statuses = [i["status"] for i in body["items"]]
    assert statuses == ["ACCEPTED", "REJECTED", "REJECTED"], body
    assert body["totals"] == {"accepted": 1, "skipped": 0, "rejected": 2}, \
        "totals are derived from the items, never invented"
    assert all(i["reason"] for i in body["items"] if i["status"] == "rejected")

    dup = api.post("/api/v1/performance/ingest/batch", json={"metrics": [good]})
    assert dup.json()["items"][0]["status"] == "SKIPPED"
    assert dup.json()["totals"]["skipped"] == 1


def test_tenant_isolation_on_every_read(api):
    api.post("/api/v1/performance/ingest", json=_metric())
    api.post("/api/v1/performance/ingest",
             json=_metric(metric_id="m-other", tenant_id="tenant_002"))
    health_tenant1 = api.get("/api/v1/performance/health",
                             params={"tenant_id": "tenant_001"})
    assert health_tenant1.status_code == 200
    assert "m-other" not in health_tenant1.text, \
        "a tenant never sees another tenant's metrics"


def test_health_names_unknown_collectors_never_zero_fills(api):
    res = api.get("/api/v1/performance/health",
                  params={"tenant_id": "tenant_001"})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["engine"] == "zelnx-performance"
    assert body["collectors"] == []
    assert "unknown, never zero" in body["note"], \
        "absence of telemetry is unknown, never zero"
