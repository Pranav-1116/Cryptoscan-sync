"""Regression tests for system-asset attachment (route + repository contract).

Covers a real production bug: POST /systems/{id}/assets used to 500 with a
FOREIGN KEY constraint failure when given a graph node id ("asset:<uuid>")
or a non-existent asset. It must accept prefixed ids and 404 cleanly.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from api.config.settings import get_settings
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.models import crypto_asset, system, system_asset, system_dependency
from db.models.base import Base


@pytest.fixture()
def sqlite_app(monkeypatch):
    """App wired to a real in-memory SQLite session (fresh per test)."""
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "test-webhook-secret-abc123")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    get_settings.cache_clear()

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestSession = sessionmaker(bind=engine)

    app = create_app()

    def _session():
        # Mirror production db.connection.session.get_session: commit on
        # success, rollback on error, always close.
        session = TestSession()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    app.dependency_overrides[get_db_session] = _session
    app.dependency_overrides[get_current_user] = lambda: "testuser"
    return app, TestSession


@pytest.mark.asyncio
async def test_attach_asset_accepts_graph_node_prefix(sqlite_app):
    app, Session = sqlite_app
    with Session() as db:
        sys_row = system.System(name="payments-api", environment="prod")
        asset = crypto_asset.CryptoAsset(
            algorithm="AES", purpose="encryption", file_path="x/AES.java", line_number=3
        )
        db.add_all([sys_row, asset])
        db.commit()
        system_id, asset_id = sys_row.id, asset.id

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            f"/api/v1/systems/{system_id}/assets",
            json={"asset_id": f"asset:{asset_id}"},
        )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["system_id"] == system_id
    assert body["asset_id"] == asset_id

    # Idempotent: attaching twice returns the same link, not an error.
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        again = await client.post(
            f"/api/v1/systems/{system_id}/assets", json={"asset_id": asset_id}
        )
    assert again.status_code == 200
    assert again.json()["id"] == body["id"]


@pytest.mark.asyncio
async def test_attach_asset_unknown_asset_is_404_not_500(sqlite_app):
    app, Session = sqlite_app
    with Session() as db:
        sys_row = system.System(name="payments-api")
        db.add(sys_row)
        db.commit()
        system_id = sys_row.id

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for bad in ("nonexistent", "asset:nonexistent"):
            response = await client.post(
                f"/api/v1/systems/{system_id}/assets", json={"asset_id": bad}
            )
            assert response.status_code == 404, f"{bad}: {response.status_code}"
            assert "not found" in response.json()["detail"]


@pytest.mark.asyncio
async def test_attach_asset_unknown_system_is_404(sqlite_app):
    app, _ = sqlite_app
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/systems/00000000-0000-0000-0000-000000000000/assets",
            json={"asset_id": "whatever"},
        )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_graph_endpoint_vis_payload_contract(sqlite_app):
    """/api/v1/graph must return the vis shape the dashboard renders:
    nodes[{id,label,group}], edges[{from,to,label}], health, backend."""
    app, Session = sqlite_app
    with Session() as db:
        parent = system.System(name="vulnerable-app", environment="dev")
        child = system.System(name="payments-api", environment="prod")
        asset = crypto_asset.CryptoAsset(
            algorithm="AES", purpose="encryption", file_path="x/AES.java", line_number=3
        )
        db.add_all([parent, child, asset])
        db.flush()
        db.add(
            system_asset.SystemAsset(system_id=parent.id, asset_id=asset.id)
        )
        db.add(
            system_dependency.SystemDependency(
                parent_id=parent.id, child_id=child.id, relation="CALLS"
            )
        )
        db.commit()
        parent_id, child_id, asset_id = parent.id, child.id, asset.id

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/graph")

    assert response.status_code == 200, response.text
    body = response.json()
    assert {"nodes", "edges", "health", "backend"} <= set(body)
    ids = {n["id"] for n in body["nodes"]}
    labels = {n["label"] for n in body["nodes"]}
    assert f"system:{parent_id}" in ids and f"system:{child_id}" in ids
    assert f"asset:{asset_id}" in ids
    assert "payments-api" in labels
    edge_set = {(e["from"], e["to"], e["label"]) for e in body["edges"]}
    assert (f"system:{parent_id}", f"system:{child_id}", "CALLS") in edge_set
    # USES edges are system -> asset; the dashboard treats them as undirected.
    assert (f"system:{parent_id}", f"asset:{asset_id}", "USES") in edge_set
