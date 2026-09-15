"""GET /api/v1/priority — ranked work queue over real platform tables."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register all tables
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base


def _make_app_with(session):
    from api.config.settings import get_settings

    get_settings.cache_clear()
    app = create_app()
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    app.dependency_overrides[get_current_user] = lambda: "soc"
    return app


@pytest.fixture()
def priority_env():
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = _make_app_with(session)
    yield app, session
    engine.dispose()


def _seed(session):
    from db.models.business_process import BusinessProcess
    from db.models.drift_event import DriftEvent
    from db.models.runtime_finding import RuntimeFinding
    from db.models.system import System
    from db.models.system_agility_score import SystemAgilityScore
    from db.models.system_business_process import SystemBusinessProcess
    from db.models.system_dependency import SystemDependency

    core = System(id="sys-core-0000000000000000000000000000", name="core-bank")
    db_sys = System(id="sys-database-00000000000000000000000000", name="db-cluster")
    edge = System(id="sys-edge-00000000000000000000000000000", name="edge-gw")
    session.add_all([core, db_sys, edge])

    # core depends on db (blast radius), edge isolated
    session.add(SystemDependency(parent_id=core.id, child_id=db_sys.id, relation="uses"))

    # business context: core-bank processes payments at 500k/day -> tier 4
    bp = BusinessProcess(id="bp-000000000000000000000000000000000", name="payments",
                         revenue_daily=500_000, customer_count=1000)
    session.add(bp)
    session.add(SystemBusinessProcess(system_id=core.id, process_id=bp.id, role="supports"))

    # agility: core is agile (80/100), db is frozen (10/100)
    session.add(SystemAgilityScore(system_id=core.id, agility_score=80, category="HIGH"))
    session.add(SystemAgilityScore(system_id=db_sys.id, agility_score=10, category="LOW"))

    now = datetime.now(timezone.utc)
    # CRITICAL drift on the frozen db system
    session.add(DriftEvent(
        id="drift-1", current_scan_id="scan-1", detected_at=now,
        drift_type="algorithm_downgrade", severity="CRITICAL",
        drift_details={"system_id": db_sys.id, "target": "db-cluster:5432",
                       "summary": "3DES reappeared", "algorithm": "3DES"},
        resolution_status="OPEN"))
    # HIGH drift on the agile, revenue-critical core
    session.add(DriftEvent(
        id="drift-2", current_scan_id="scan-1", detected_at=now,
        drift_type="weak_tls", severity="HIGH",
        drift_details={"system_id": core.id, "target": "core-bank:443",
                       "summary": "TLSv1.0 offered"},
        resolution_status="OPEN"))
    # resolved event must NOT rank
    session.add(DriftEvent(
        id="drift-3", current_scan_id="scan-1", detected_at=now,
        drift_type="weak_tls", severity="CRITICAL",
        drift_details={"system_id": edge.id, "target": "edge:443"},
        resolution_status="RESOLVED"))
    # weak-TLS runtime finding
    session.add(RuntimeFinding(
        id="rf-1", scanner_id="runtime-1", kind="session", hostname="edge-gw",
        process_name="nginx", tls_version="TLSv1.0", weak_tls=True,
        dedup_key="rf-1-key", last_seen_at=now))
    session.commit()


@pytest.mark.asyncio
async def test_priority_ranks_by_revenue_severity_agility(priority_env):
    app, session = priority_env
    _seed(session)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/priority")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        ranked = body["ranked"]
        assert len(ranked) == 3  # resolved event excluded
        # drift-1: CRITICAL weight 5 x neutral revenue 3 (unmapped) x agility 0.1 = 1.5
        # drift-2: HIGH weight 4 x revenue tier 4 x agility 0.8 = 12.8
        # rf-1:    HIGH weight 4 x neutral 3 x neutral 0.5 = 6.0
        top = ranked[0]
        assert top["ref_id"] == "drift-2"
        assert top["priority"] == pytest.approx(12.8)
        assert ranked[1]["ref_id"] == "rf-1"
        assert ranked[2]["ref_id"] == "drift-1"
        assert ranked[2]["priority"] == pytest.approx(1.5)
        # blast radius: drift-2 on core-bank correlates to db-cluster
        assert ranked[0]["correlated"] == ["db-cluster"]
        # replacement table engaged for the 3DES finding
        assert ranked[2]["replacement"] is not None
        assert "AES-256-GCM" in ranked[2]["replacement"]["replacement"]
        cov = body["coverage"]
        assert cov["open_drift_events"] == 2 and cov["runtime_findings"] == 1
        assert cov["systems_with_agility"] == 2
        assert cov["systems_with_revenue_mapping"] == 1
        assert cov["graph_edges"] == 1
        assert body["counts_by_severity"]["HIGH"] >= 1


@pytest.mark.asyncio
async def test_priority_empty_estate_is_honestly_empty(priority_env):
    app, session = priority_env
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/priority")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ranked"] == []
        assert body["coverage"]["open_drift_events"] == 0
