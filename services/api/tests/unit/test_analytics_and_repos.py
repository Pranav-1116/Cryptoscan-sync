"""API tests — analytics router + repo configs router (previously untested)."""

from __future__ import annotations

import os
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
from db.models.crypto_asset import CryptoAsset
from db.models.evidence_record import EvidenceRecord
from db.models.repo_configuration import RepoConfiguration
from db.models.system import System


def _make_app():
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
    app.dependency_overrides[get_current_user] = lambda: "analytics-tester"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session


def _seed(session):
    session.add(CryptoAsset(
        algorithm="DES", purpose="ENCRYPTION", mode="ECB", key_size=56,
        file_path="src/Pay.java", line_number=7, source_language="JAVA",
        confidence="HIGH", is_hardcoded_key=True,
    ))
    session.add(CryptoAsset(
        algorithm="AES", purpose="ENCRYPTION", mode="GCM", key_size=256,
        file_path="src/Crypto.java", line_number=3, source_language="JAVA",
        confidence="MEDIUM",
    ))
    session.add(EvidenceRecord(
        scan_id="scan-1", content_hash="c" * 64, chain_hash="",
        chain_position=0, previous_hash=None, algorithm="DES",
        confidence="HIGH", purpose="ENCRYPTION", mode="ECB", key_size=56,
        file_path="src/Pay.java", line_number=7,
        finding_data={"scanner_id": "s", "metadata": {}},
        compliance_status="FAIL",
    ))
    session.add(System(
        name="payments-core", description="PCI zone", environment="prod",
        compliance_scopes=["PCI_DSS"], current_agility_score=42,
        agility_category="LOW",
    ))
    session.flush()


@pytest.fixture
def app_client():
    app, session = _make_app()
    _seed(session)
    yield AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    session.close()


class TestAnalyticsEndpoints:
    @pytest.mark.asyncio
    async def test_overview_returns_all_sections(self, app_client):
        response = await app_client.get("/api/v1/analytics")
        assert response.status_code == 200
        body = response.json()
        for key in ("trends", "compliance", "heatmap", "forecast",
                    "recommendations", "executive"):
            assert key in body

    @pytest.mark.asyncio
    async def test_trends_section(self, app_client):
        response = await app_client.get("/api/v1/analytics/trends")
        assert response.status_code == 200
        body = response.json()
        assert "trends" in body
        assert "compliance" in body

    @pytest.mark.asyncio
    async def test_heatmap_section(self, app_client):
        response = await app_client.get("/api/v1/analytics/heatmap")
        assert response.status_code == 200
        assert "heatmap" in response.json()

    @pytest.mark.asyncio
    async def test_forecast_section(self, app_client):
        response = await app_client.get("/api/v1/analytics/forecast")
        assert response.status_code == 200
        body = response.json()
        # forecast summary dict with migration projections
        assert "vulnerable" in body or "months_to_completion" in body

    @pytest.mark.asyncio
    async def test_recommendations_section(self, app_client):
        response = await app_client.get("/api/v1/analytics/recommendations")
        assert response.status_code == 200
        assert "recommendations" in response.json()

    @pytest.mark.asyncio
    async def test_executive_section(self, app_client):
        response = await app_client.get("/api/v1/analytics/executive")
        assert response.status_code == 200
        assert response.json()  # non-empty executive summary


class TestRepoConfigsEndpoints:
    @pytest.mark.asyncio
    async def test_empty_list(self, app_client):
        response = await app_client.get("/api/v1/repos")
        assert response.status_code == 200
        assert response.json() == []

    @pytest.mark.asyncio
    async def test_create_and_list(self, app_client):
        created = await app_client.post("/api/v1/repos", json={
            "repo_url": "https://github.com/acme/pay",
            "repo_name": "pay",
            "enabled": True,
            "scan_on_push": True,
            "scan_on_pr": False,
        })
        assert created.status_code == 200
        config_id = created.json()["config_id"]
        assert config_id

        listed = await app_client.get("/api/v1/repos")
        rows = listed.json()
        assert len(rows) == 1
        assert rows[0]["repo_url"] == "https://github.com/acme/pay"
        assert rows[0]["repo_name"] == "pay"
        assert rows[0]["enabled"] is True
        assert rows[0]["scan_on_push"] is True

    @pytest.mark.asyncio
    async def test_duplicate_url_conflict(self, app_client):
        body = {"repo_url": "https://github.com/acme/dup", "repo_name": "dup"}
        first = await app_client.post("/api/v1/repos", json=body)
        assert first.status_code == 200
        second = await app_client.post("/api/v1/repos", json=body)
        assert second.status_code == 409
        assert "already" in second.json()["detail"]

    @pytest.mark.asyncio
    async def test_defaults_applied(self, app_client):
        created = await app_client.post("/api/v1/repos", json={
            "repo_url": "https://github.com/acme/defaults",
            "repo_name": "defaults",
        })
        assert created.status_code == 200
        rows = (await app_client.get("/api/v1/repos")).json()
        assert rows[0]["scan_on_push"] is True
