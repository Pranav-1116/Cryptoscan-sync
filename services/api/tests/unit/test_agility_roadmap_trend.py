"""Agility portfolio trend + roadmap endpoints (in-memory DB)."""

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
from db.models.system import System

MODERN_EXTRAS = {
    "kms": True, "configmap": True, "hot_reload": True,
    "crypto_tests": True, "parameterized_crypto_tests": True,
    "has_crypto_docs": True, "has_crypto_inventory_docs": True,
    "has_dr_plan": True, "key_management": "AWS_KMS",
}


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
    session.add(System(id="sys-b", name="legacy-batch", environment="BARE_METAL", extra={"no_tests": True, "static_binary": True}))
    session.flush()
    try:
        yield application
    finally:
        session.close()
        engine.dispose()


@pytest.mark.asyncio
async def test_portfolio_trend_improves_after_remediation(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        first = (await client.get("/api/v1/agility")).json()
        assert len(first["systems"]) == 2
        # first scoring pass: no history to compare against
        assert first["trend"]["no_history"] == 2
        assert first["trend"]["improving"] == 0

        time.sleep(0.01)
        # remediate system A: full modern crypto practices
        system = app_db.dependency_overrides[get_db_session]().__next__().get(System, "sys-a")
        system.extra = dict(MODERN_EXTRAS)
        recalc = await client.post("/api/v1/systems/sys-a/agility/recalculate")
        assert recalc.status_code == 200

        second = (await client.get("/api/v1/agility")).json()
        assert second["trend"]["improving"] == 1
        assert second["trend"]["no_history"] == 1  # legacy-batch still has a single row
        row_a = next(row for row in second["systems"] if row["system_id"] == "sys-a")
        assert row_a["score_delta"] > 0
        assert row_a["previous_agility_score"] is not None


@pytest.mark.asyncio
async def test_roadmap_sequences_both_systems(app_db):
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/agility/roadmap")
    assert response.status_code == 200
    body = response.json()
    assert body["total_systems"] == 2
    assert body["wave_order"] == sorted(body["wave_order"])
    entries = [row for wave in body["waves"].values() for row in wave]
    assert {row["system_id"] for row in entries} == {"sys-a", "sys-b"}
    assert all(row["position"] >= 1 and row["rationale"] for row in entries)
    # each wave's positions are 1..n with no gaps
    for wave, rows in body["waves"].items():
        if rows:
            assert [row["position"] for row in rows] == list(range(1, len(rows) + 1))
