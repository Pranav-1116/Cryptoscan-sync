"""Quantum plan + Mosca endpoints (in-memory DB, live crypto assets)."""

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
            System(
                id="sys-pay", name="payment-api", criticality="TIER-1",
                extra={"data_retention_years": 10},
            ),
            System(id="sys-db", name="customer-db", extra={"data_retention_years": 2}),
        ]
    )
    session.flush()
    assets = [
        CryptoAsset(id="ca-rsa", algorithm="RSA-2048", key_size=2048, purpose="KEY_EXCHANGE", file_path="src/a.py", line_number=1),
        CryptoAsset(id="ca-aes128", algorithm="AES-128", purpose="ENCRYPTION", file_path="src/c.py", line_number=3),
        CryptoAsset(id="ca-kem", algorithm="ML-KEM-768", file_path="src/d.py", line_number=4),
    ]
    session.add_all(assets)
    session.flush()
    session.add_all(
        [
            SystemAsset(system_id="sys-pay", asset_id="ca-rsa"),
            SystemAsset(system_id="sys-pay", asset_id="ca-kem"),
            SystemAsset(system_id="sys-db", asset_id="ca-aes128"),
        ]
    )
    try:
        yield application
    finally:
        session.close()
        engine.dispose()


@pytest.mark.asyncio
async def test_quantum_plan_endpoint(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/quantum/plan", params={"migration_years": 2})
    assert response.status_code == 200
    body = response.json()
    inv = body["inventory"]
    assert inv["total_sites"] == 3
    assert inv["vulnerable_sites"] == 2  # RSA + AES-128
    assert inv["pqc_ready_sites"] == 1
    assert inv["by_family"]["RSA"] == 1
    targets = [stream["target"] for stream in body["workstreams"]]
    assert "ML-KEM-768" in targets
    kem = next(stream for stream in body["workstreams"] if stream["target"] == "ML-KEM-768")
    assert kem["systems"] == ["sys-pay"]  # system attribution survives the API path
    assert body["waves"]["1"]["site_count"] == 1  # RSA on a 10y-retention system = HNDL HIGH
    assert body["mosca"]["verdict"] == "ALREADY_LATE"  # x=10, y=2 vs z=4


@pytest.mark.asyncio
async def test_quantum_mosca_endpoint():
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "testuser"
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        late = await client.post(
            "/api/v1/quantum/mosca", json={"retention_years": 10, "migration_years": 2}
        )
        assert late.status_code == 200
        body = late.json()
        assert body["computable"] is True
        assert body["verdict"] == "ALREADY_LATE"
        assert body["x_shelf_life_years"] == 10

        unknown = await client.post("/api/v1/quantum/mosca", json={"retention_years": 3})
        assert unknown.json()["verdict"] == "UNKNOWN_MARGIN"

        honest = await client.post("/api/v1/quantum/mosca", json={})
        assert honest.json()["computable"] is False
