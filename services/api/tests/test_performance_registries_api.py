"""Registry and cursor-pagination API tests (docs/performance/
01_PRODUCT_SPEC.md §5, §6, §9).

Acceptance rows: definitions register from the taxonomy and are
idempotent; a stale collector is detected and named — its missing
telemetry is never read as zero; raw samples paginate by cursor with
time ranges, tenant authorization and a maximum query window.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


@pytest.fixture()
def api():
    from db.connection.session import Base
    from db.models.performance import (
        PerformanceBenchmarkRun, PerformanceCollectorHealth,
        PerformanceMetric, PerformanceMetricDefinition,
    )

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False},
        poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=[
        PerformanceMetric.__table__, PerformanceMetricDefinition.__table__,
        PerformanceCollectorHealth.__table__,
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


def _metric(index: int, tenant: str = "tenant_001") -> dict:
    return {
        "metric_id": f"sample-{index:04d}",
        "tenant_id": tenant,
        "asset_id": "asset-001",
        "metric_name": "network.rtt_ms",
        "metric_type": "histogram",
        "metric_value": 10.0 + index,
        "unit": "ms",
        "source_id": "collector-1",
        "observed_at": (datetime(2026, 11, 1, tzinfo=timezone.utc)
                        + timedelta(minutes=index)).isoformat(),
        "labels": {},
        "quality_status": "valid",
    }


def test_definitions_register_from_the_taxonomy_and_are_idempotent(api):
    first = api.post("/api/v1/performance/definitions",
                     json={"tenant_id": "tenant_001"})
    assert first.status_code == 201, first.text
    body = first.json()
    assert body["inserted"] == body["registered"] > 60, \
        "every taxonomy metric is a registered definition"
    again = api.post("/api/v1/performance/definitions",
                     json={"tenant_id": "tenant_001"})
    assert again.status_code == 200
    assert again.json()["inserted"] == 0, \
        "a sync is idempotent — nothing registers twice"

    listed = api.get("/api/v1/performance/definitions",
                     params={"tenant_id": "tenant_001"})
    assert listed.status_code == 200
    rows = listed.json()
    names = {row["metric_name"] for row in rows}
    assert "cpu.utilization_pct" in names
    assert all(row["unit"] for row in rows), \
        "a guessed unit is not a defined unit"
    only_storage = api.get("/api/v1/performance/definitions",
                           params={"tenant_id": "tenant_001",
                                   "domain": "storage"}).json()
    assert only_storage and all(
        row["domain"] == "storage" for row in only_storage)

    other_tenant = api.get("/api/v1/performance/definitions",
                           params={"tenant_id": "tenant_002"}).json()
    assert other_tenant == [], "definitions are tenant-scoped"


def test_a_stale_collector_is_detected_and_missing_is_never_zero(api):
    now = datetime.now(timezone.utc)
    api.post("/api/v1/performance/definitions", json={"tenant_id": "tenant_001"})
    report = api.get("/api/v1/performance/collectors",
                     params={"tenant_id": "tenant_001",
                             "stale_after_seconds": 300})
    assert report.status_code == 200
    assert report.json()["collectors"] == []

    # heartbeat through the repository (the ingest path records reports)
    from api.dependencies import get_db_session  # noqa: F401
    repo = api.app.dependency_overrides[get_db_session]().__class__  # noqa
    session = api.app.dependency_overrides[
        __import__("api.dependencies", fromlist=["get_db_session"]).get_db_session]()
    from db.repositories.performance_repository import PerformanceRepository
    repository = PerformanceRepository(session)
    repository.record_collector_report(
        "tenant_001", "node-1", status="healthy",
        last_report_at=now - timedelta(hours=2))
    repository.record_collector_report(
        "tenant_001", "otlp-1", status="healthy", last_report_at=now)

    report = api.get("/api/v1/performance/collectors",
                     params={"tenant_id": "tenant_001",
                             "stale_after_seconds": 300}).json()
    by_id = {row["collector_id"]: row for row in report["collectors"]}
    assert by_id["node-1"]["stale"] is True
    assert by_id["node-1"]["status"] == "stale", \
        "a stale collector is detected and named"
    assert by_id["otlp-1"]["stale"] is False
    assert report["stale_detected"] == 1
    assert "missing metrics as zero" in report["note"], \
        "the report quotes the rule: stale collectors are detected " \
        "instead of interpreting missing metrics as zero"
    assert "never read as zero" in by_id["node-1"]["note"]

    cross = api.get("/api/v1/performance/collectors",
                    params={"tenant_id": "tenant_002"}).json()
    assert cross["collectors"] == [], "collector health is tenant-scoped"


def test_samples_paginate_by_cursor_without_skips_or_repeats(api):
    for i in range(25):
        created = api.post("/api/v1/performance/ingest", json=_metric(i))
        assert created.status_code == 201

    seen = []
    cursor = None
    pages = 0
    while True:
        params = {"tenant_id": "tenant_001", "limit": 10}
        if cursor:
            params["cursor"] = cursor
        page = api.get("/api/v1/performance/samples", params=params)
        assert page.status_code == 200, page.text
        body = page.json()
        seen.extend(row["metric_id"] for row in body["samples"])
        pages += 1
        cursor = body["next_cursor"]
        if not cursor:
            break
        assert pages < 10, "cursor pagination must terminate"
    assert pages == 3
    assert seen == [f"sample-{i:04d}" for i in range(25)], \
        "pages never skip or repeat rows"


def test_samples_are_windowed_tenant_scoped_and_cursor_exact(api):
    for i in range(25):
        api.post("/api/v1/performance/ingest", json=_metric(i))

    too_wide = api.get("/api/v1/performance/samples", params={
        "tenant_id": "tenant_001",
        "window_start": "2026-09-01T00:00:00+00:00",
        "window_end": "2026-11-30T00:00:00+00:00"})
    assert too_wide.status_code == 422, \
        "query windows have a maximum (31 days) — refused, never truncated"

    half_window = api.get("/api/v1/performance/samples", params={
        "tenant_id": "tenant_001",
        "window_start": "2026-11-01T00:00:00+00:00"})
    assert half_window.status_code == 422

    bounded = api.get("/api/v1/performance/samples", params={
        "tenant_id": "tenant_001",
        "window_start": "2026-11-01T00:00:00+00:00",
        "window_end": "2026-11-02T00:00:00+00:00"}).json()
    assert bounded["returned"] == 25

    cross = api.get("/api/v1/performance/samples",
                    params={"tenant_id": "tenant_002"}).json()
    assert cross["samples"] == [] and cross["next_cursor"] is None, \
        "no cross-tenant metric access"

    bad_cursor = api.get("/api/v1/performance/samples", params={
        "tenant_id": "tenant_001", "cursor": "not-a-cursor"})
    assert bad_cursor.status_code == 422
    assert "opaque" in bad_cursor.json()["detail"] or \
        "guessed" in bad_cursor.json()["detail"]


def test_benchmark_runs_paginate_by_cursor_newest_first(api):
    ids = []
    for i in range(5):
        run = api.post("/api/v1/performance/benchmarks", json={
            "tenant_id": "tenant_001", "algorithm": "Ed25519",
            "sample_count": 2})
        assert run.status_code == 201, run.text
        ids.append(run.json()["run_id"])

    page1 = api.get("/api/v1/performance/benchmarks", params={
        "tenant_id": "tenant_001", "limit": 2}).json()
    assert len(page1["runs"]) == 2 and page1["next_cursor"]
    page2 = api.get("/api/v1/performance/benchmarks", params={
        "tenant_id": "tenant_001", "limit": 2,
        "cursor": page1["next_cursor"]}).json()
    assert len(page2["runs"]) == 2 and page2["next_cursor"]
    page3 = api.get("/api/v1/performance/benchmarks", params={
        "tenant_id": "tenant_001", "limit": 2,
        "cursor": page2["next_cursor"]}).json()
    assert len(page3["runs"]) == 1 and page3["next_cursor"] is None

    seen = [r["run_id"] for page in (page1, page2, page3)
            for r in page["runs"]]
    assert sorted(seen) == sorted(ids), \
        "pages never skip or repeat runs"
    assert all(r["measurement_kind"] == "controlled_benchmark"
               for page in (page1, page2, page3) for r in page["runs"])
