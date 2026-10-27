"""Server-side estate asset search (§5, round 62).

`GET /assets?q=` searches in the DATABASE — across the whole estate, not
only a loaded page — over the fields an operator actually searches:
asset id, identity spine key, algorithm, file location. This is what the
frontend full-search Assets group consumes; the page-local filter is not
estate search.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register tables
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models.crypto_asset import CryptoAsset
from db.repositories.asset_repository import AssetRepository


@pytest.fixture()
def app_session():
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "assets-search-" + "z" * 21)
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "op"
    app.dependency_overrides[get_db_session] = lambda: (yield session)

    repo = AssetRepository(session)
    repo.replace_for_scan("scan-1", [
        {"algorithm": "RSA-2048", "purpose": "SIGNING", "file_path": "src/Keys.java",
         "line_number": 3, "confidence": "HIGH", "evidence_ids": ["ev-1"]},
        {"algorithm": "AES-256-GCM", "purpose": "ENCRYPTION", "mode": "GCM", "key_size": 256,
         "file_path": "src/Tunnel.java", "line_number": 9, "confidence": "HIGH",
         "evidence_ids": ["ev-2"]},
        {"algorithm": "3DES", "purpose": "ENCRYPTION", "file_path": "legacy/LegacyPad.java",
         "line_number": 1, "confidence": "HIGH", "evidence_ids": ["ev-3"]},
    ])
    session.commit()
    yield app, session
    engine.dispose()


@pytest.mark.asyncio
async def test_q_searches_algorithm_location_and_spine_across_the_estate(app_session):
    app, session = app_session
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        # algorithm substring
        r = await c.get("/api/v1/assets?q=RSA")
        assert r.status_code == 200
        body = r.json()
        assert body["total_count"] == 1
        assert body["assets"][0]["algorithm"] == "RSA-2048"
        # file location substring (different asset)
        r = await c.get("/api/v1/assets?q=legacy/")
        assert {a["algorithm"] for a in r.json()["assets"]} == {"3DES"}
        # identity spine key prefix matches (the durable join key)
        spine = session.query(CryptoAsset).filter_by(algorithm="3DES").one().asset_key
        assert spine
        r = await c.get(f"/api/v1/assets?q={spine[:20]}")
        assert r.json()["total_count"] == 1
        assert r.json()["assets"][0]["asset_key"] == spine
        # exact id
        target = session.query(CryptoAsset).filter_by(algorithm="AES-256-GCM").one()
        r = await c.get(f"/api/v1/assets?q={target.id}")
        assert r.json()["total_count"] == 1
        # no match is an honest empty page, not an error
        r = await c.get("/api/v1/assets?q=DEFINITELY_NOT_PRESENT")
        assert r.status_code == 200
        assert r.json() == {"assets": [], "total_count": 0, "page": 1, "page_size": 50}


@pytest.mark.asyncio
async def test_q_combines_with_paging_and_algorithm_filter(app_session):
    app, _ = app_session
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/api/v1/assets?q=.java&page_size=2")
        body = r.json()
        assert body["total_count"] == 3, "all three assets live under .java paths"
        assert len(body["assets"]) == 2 and body["page_size"] == 2
        r = await c.get("/api/v1/assets?q=.java&algorithm=3DES")
        assert r.json()["total_count"] == 1
