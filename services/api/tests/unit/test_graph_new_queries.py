"""Graph API: dependents, path, and hotspots endpoints (memory backend)."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import db.models  # noqa: F401 — register all tables
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models.crypto_asset import CryptoAsset
from db.models.system import System
from db.models.system_asset import SystemAsset
from db.repositories.system_repository import SystemRepository


@pytest.fixture()
def app_db():
    from sqlalchemy.pool import StaticPool

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()

    application = create_app()
    application.dependency_overrides[get_current_user] = lambda: "testuser"

    def _session():
        yield session

    application.dependency_overrides[get_db_session] = _session

    session.add_all(
        [
            System(id="sys-web", name="web-frontend"),
            System(id="sys-pay", name="payment-api", criticality="TIER-1"),
            System(id="sys-db", name="customer-db"),
        ]
    )
    session.flush()
    assets = [
        CryptoAsset(id="ca-rsa", algorithm="RSA-2048", file_path="src/Pay.java", line_number=1),
        CryptoAsset(id="ca-ec", algorithm="ECDSA-P256", file_path="src/Sign.java", line_number=2),
        CryptoAsset(id="ca-aes", algorithm="AES-256-GCM", file_path="src/Seal.java", line_number=3),
    ]
    session.add_all(assets)
    session.flush()
    session.add_all(
        [
            SystemAsset(system_id="sys-pay", asset_id="ca-rsa"),
            SystemAsset(system_id="sys-pay", asset_id="ca-ec"),
            SystemAsset(system_id="sys-db", asset_id="ca-aes"),
        ]
    )
    repo = SystemRepository(session)
    repo.add_dependency("sys-web", "sys-pay")
    repo.add_dependency("sys-pay", "sys-db")
    try:
        yield application
    finally:
        session.close()
        engine.dispose()


@pytest.mark.asyncio
async def test_dependents_endpoint(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/graph/dependents", params={"system_id": "sys-db"})
    assert response.status_code == 200
    body = response.json()
    names = {(row["name"], row["hops"]) for row in body["systems"]}
    assert ("payment-api", 1) in names
    assert ("web-frontend", 2) in names


@pytest.mark.asyncio
async def test_dependents_endpoint_404(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/graph/dependents", params={"system_id": "ghost"})
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_path_endpoint_down_and_up(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        down = await client.get(
            "/api/v1/graph/path", params={"system_id": "sys-web", "target_id": "sys-db"}
        )
        assert down.status_code == 200
        body = down.json()
        assert body["reachable"] is True
        assert body["path"] == ["web-frontend", "payment-api", "customer-db"]
        assert body["hops"] == 2

        # reverse direction is not reachable downstream, but is upstream
        blocked = await client.get(
            "/api/v1/graph/path", params={"system_id": "sys-db", "target_id": "sys-web"}
        )
        assert blocked.status_code == 200
        assert blocked.json()["reachable"] is False

        up = await client.get(
            "/api/v1/graph/path",
            params={"system_id": "sys-db", "target_id": "sys-web", "direction": "upstream"},
        )
        assert up.json()["reachable"] is True and up.json()["hops"] == 2


@pytest.mark.asyncio
async def test_path_endpoint_404_and_bad_direction(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        missing = await client.get(
            "/api/v1/graph/path", params={"system_id": "sys-db", "target_id": "ghost"}
        )
        assert missing.status_code == 404
        assert "ghost" in missing.json()["detail"]
        bad = await client.get(
            "/api/v1/graph/path",
            params={"system_id": "sys-db", "target_id": "sys-web", "direction": "sideways"},
        )
        assert bad.status_code == 422  # pattern-constrained


@pytest.mark.asyncio
async def test_hotspots_endpoint_ranks_payment_first(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/graph/hotspots")
    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 2  # pay + db have assets
    top = body["hotspots"][0]
    assert top["name"] == "payment-api"
    assert top["quantum_vulnerable_assets"] == 2
    assert top["vulnerable_algorithms"] == ["ECDSA-P256", "RSA-2048"]
    assert body["hotspots"][1]["quantum_vulnerable_assets"] == 0


# --------------------------------------------------------------------------- #
# cycles + stats endpoints (second graph fixture with a dependency cycle)
# --------------------------------------------------------------------------- #

@pytest.fixture()
def app_db_cyclic():
    from sqlalchemy.pool import StaticPool

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()

    application = create_app()
    application.dependency_overrides[get_current_user] = lambda: "testuser"

    def _session():
        yield session

    application.dependency_overrides[get_db_session] = _session

    session.add_all(
        [
            System(id="sys-web", name="web-frontend"),
            System(id="sys-pay", name="payment-api"),
            System(id="sys-db", name="customer-db"),
            System(id="sys-lonely", name="forgotten-service"),  # orphan: no deps, no assets
        ]
    )
    session.flush()
    repo = SystemRepository(session)
    repo.add_dependency("sys-web", "sys-pay")
    repo.add_dependency("sys-pay", "sys-db")
    repo.add_dependency("sys-db", "sys-web")  # cycle
    try:
        yield application
    finally:
        session.close()
        engine.dispose()


@pytest.mark.asyncio
async def test_cycles_endpoint_reports_scc(app_db_cyclic):
    transport = ASGITransport(app=app_db_cyclic)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/graph/cycles")
    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 1
    assert set(body["cycles"][0]["members"]) == {"system:sys-web", "system:sys-pay", "system:sys-db"}
    assert "migration" in body["note"]


@pytest.mark.asyncio
async def test_stats_endpoint_flags_orphans(app_db_cyclic):
    transport = ASGITransport(app=app_db_cyclic)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/graph/stats")
    assert response.status_code == 200
    body = response.json()
    assert body["systems"] == 4
    assert body["edges_by_relation"]["CALLS"] == 3
    assert body["orphan_systems"] == ["system:sys-lonely"]
    assert body["nodes_by_kind"]["System"] == 4


@pytest.mark.asyncio
async def test_certificate_exposure_endpoint_empty_ok(app_db_cyclic):
    transport = ASGITransport(app=app_db_cyclic)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/graph/certificates/exposure")
    assert response.status_code == 200
    body = response.json()
    assert body["at_risk"] == []
    assert body["totals"]["certs_at_risk"] == 0
    assert body["totals"]["certs_unknown_status"] == 0
