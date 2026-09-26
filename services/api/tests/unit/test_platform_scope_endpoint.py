"""API tests — platform scope endpoint (GET /api/v1/platform/scope)."""

from __future__ import annotations

import os

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register all tables
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base


@pytest.fixture
def app_client():
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:",
                           connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "scope-tester"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    yield AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    session.close()


@pytest.mark.asyncio
async def test_scope_endpoint_returns_manifest(app_client):
    response = await app_client.get("/api/v1/platform/scope")
    assert response.status_code == 200
    body = response.json()
    assert body["platform"] == "CryptoScan"
    assert body["schema_version"] == 2  # v2: adds capabilities (GA/beta/preview)
    assert body["mission"]
    assert body["covered_areas"]
    assert body["non_goals"]
    assert body["access_model"]["read_only"] is True
    assert body["invariants"]


@pytest.mark.asyncio
async def test_scope_names_honest_non_goals(app_client):
    body = (await app_client.get("/api/v1/platform/scope")).json()
    labels = " ".join(goal["label"] for goal in body["non_goals"]).lower()
    # z/OS crypto discovery AND crypto-call scanning of mainframe source (COBOL/PL-I/
    # Natural/HLASM) are COVERED; business-logic analysis of that code is the non-goal.
    covered = " ".join(a["detail"] for a in body["covered_areas"]).lower()
    assert "cobol" in covered
    assert "business-logic" in labels
    assert "cobol" not in labels
    assert "malware" in labels
    assert "endpoint" in labels
    assert "sast" in labels
    covered = " ".join(str(area) for area in body.get("covered_areas", [])).lower()
    assert "z/os" in covered or "zos" in covered


@pytest.mark.asyncio
async def test_scope_invariants_include_metadata_only(app_client):
    body = (await app_client.get("/api/v1/platform/scope")).json()
    invariant_ids = {inv["id"] for inv in body["invariants"]}
    assert "metadata-only" in invariant_ids
    assert "read-only-collection" in invariant_ids
    assert "evidence-chained" in invariant_ids


@pytest.mark.asyncio
async def test_capabilities_endpoint_serves_the_maturity_table(app_client):
    """GA / beta / preview per route; unknown defaults to preview."""
    r = await app_client.get("/api/v1/platform/capabilities")
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body["tiers"]) == {"ga", "beta", "preview"}
    assert body["default_for_unknown"] == "preview"
    by_route = {row["route"]: row for row in body["capabilities"]}
    assert by_route["/cbom"]["tier"] == "ga"
    assert by_route["/telecom"]["tier"] == "beta"
    assert by_route["/what-if"]["tier"] == "preview"
    assert all(row["why"] for row in body["capabilities"])
    # the scope manifest carries the same table
    scope = (await app_client.get("/api/v1/platform/scope")).json()
    assert scope["capabilities"]["counts"] == body["counts"]
