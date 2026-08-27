"""Agility history/trajectory, what-if simulation, and portfolio PQC endpoints."""

from __future__ import annotations

import time

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
from db.repositories.maturity_repository import MaturityRepository


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

    session.add(System(id="sys-a", name="payments-api", environment="KUBERNETES", extra={}))
    session.add(System(id="sys-b", name="legacy-batch", environment="BARE_METAL", extra={}))
    session.flush()

    # crypto assets: sys-a has 2x RSA + 1x AES, sys-b has 1x ECDSA
    assets = [
        CryptoAsset(id="ca-1", algorithm="RSA-2048", file_path="src/Pay.java", line_number=1, confidence="HIGH"),
        CryptoAsset(id="ca-2", algorithm="RSA-2048", file_path="src/Keys.java", line_number=2, confidence="HIGH"),
        CryptoAsset(id="ca-3", algorithm="AES-256-GCM", file_path="src/Seal.java", line_number=3, confidence="HIGH"),
        CryptoAsset(id="ca-4", algorithm="ECDSA-P256", file_path="src/Sign.java", line_number=4, confidence="HIGH"),
    ]
    session.add_all(assets)
    session.flush()
    session.add_all(
        [
            SystemAsset(system_id="sys-a", asset_id="ca-1"),
            SystemAsset(system_id="sys-a", asset_id="ca-2"),
            SystemAsset(system_id="sys-a", asset_id="ca-3"),
            SystemAsset(system_id="sys-b", asset_id="ca-4"),
        ]
    )

    # two agility rows for sys-a: first poor, then improved
    repo = MaturityRepository(session)
    repo.save_agility(
        "sys-a",
        {
            "agility_score": 20,
            "category": "POOR",
            "factor_scores": {"factor1": 0, "factor2": -70, "factor5": -10},
            "readiness_score": 25,
            "readiness_category": "BLOCKED",
        },
    )
    time.sleep(0.01)
    repo.save_agility(
        "sys-a",
        {
            "agility_score": 45,
            "category": "MODERATE",
            "factor_scores": {"factor1": 0, "factor2": -40, "factor5": 35},
            "readiness_score": 55,
            "readiness_category": "NOT_READY",
        },
    )
    try:
        yield application
    finally:
        session.close()
        engine.dispose()


@pytest.mark.asyncio
async def test_history_endpoint_returns_trajectory(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/systems/sys-a/agility/history")
    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 2
    scores = [row["agility_score"] for row in body["history"]]
    assert scores == [20, 45]  # chronological ascending
    assert body["trajectory"]["trajectory"] == "IMPROVING"
    assert body["trajectory"]["net_change"] == 25
    assert body["trajectory"]["factor_deltas"] == {"factor1": 0, "factor2": 30, "factor5": 45}
    assert body["trajectory"]["factors_improved"] == ["factor2", "factor5"]


@pytest.mark.asyncio
async def test_history_endpoint_404_for_unknown_system(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/systems/sys-zzz/agility/history")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_simulate_endpoint_projects_without_persisting(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/systems/sys-a/agility/simulate",
            json={"actions": ["move_to_kms", "nonsense"]},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["projection"] is True
    assert body["actions_applied"] == ["move_to_kms"]
    assert body["unsupported_actions"] == ["nonsense"]
    assert "move_to_kms" in body["available_actions"]
    assert body["current"]["agility_score"] == body["current"]["agility_score"]
    assert body["note"].startswith("projection only")

    # nothing persisted: history still has exactly 2 rows
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        history = (await client.get("/api/v1/systems/sys-a/agility/history")).json()
    assert history["count"] == 2


@pytest.mark.asyncio
async def test_simulate_endpoint_404_for_unknown_system(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/systems/sys-zzz/agility/simulate", json={"actions": ["move_to_kms"]}
        )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_pqc_portfolio_ranks_systems(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/agility/pqc")
    assert response.status_code == 200
    body = response.json()
    assert body["total_systems_with_assets"] == 2
    assert body["total_quantum_vulnerable_sites"] == 3  # RSA x2 + ECDSA x1
    assert body["quantum_vulnerable_algorithms"] == ["ECDSA-P256", "RSA-2048"]
    assert body["hybrid_systems"] == 0
    # ranked by vulnerable sites desc: sys-a (2) before sys-b (1)
    assert [row["system_id"] for row in body["systems"]] == ["sys-a", "sys-b"]
    top = body["systems"][0]
    assert top["quantum_vulnerable_sites"] == 2 and top["sites"] == 3
