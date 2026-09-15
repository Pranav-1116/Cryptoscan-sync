"""Stream + Live CBOM API: ingest -> pipeline -> attacks -> signed CBOM."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register all tables
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base


@pytest.fixture()
def stream_env(tmp_path, monkeypatch):
    import eventstream.bus as bus_mod
    import services.api.api.routers.stream as stream_router

    monkeypatch.setenv("STREAM_LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv("CBOM_STORE_DIR", str(tmp_path / "cbom"))
    bus_mod.reset_bus()
    stream_router._processor._inst = None
    stream_router._cbom_service._inst = None
    stream_router._projector._inst = None
    yield tmp_path
    bus_mod.reset_bus()
    stream_router._processor._inst = None
    stream_router._cbom_service._inst = None
    stream_router._projector._inst = None


def _make_app():
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    app.dependency_overrides[get_current_user] = lambda: "soc"
    return app, session, engine


@pytest.mark.asyncio
async def test_ingest_detects_downgrade_and_signs_cbom(stream_env):
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1) clean pass -> baseline learned, CBOM v1
        r = await client.post("/api/v1/stream/ingest", json={
            "payload": {"kind": "tls_finding", "system": "core-1",
                        "endpoint": "api.core:443",
                        "crypto": {"tls_version": "TLSv1.3", "key_size": 256}},
            "source": "unit"})
        assert r.status_code == 200, r.text
        assert r.json()["processed"] == 1

        live = (await client.get("/api/v1/cbom/live/core-1")).json()
        assert live["version_no"] == 1
        assert live["freshness"]["stale"] is False
        assert live["jws"].count(".") == 2  # compact JWS

        # 2) downgrade -> detection surfaces in the ingestion verdict AND /attacks
        r2 = await client.post("/api/v1/stream/ingest", json={
            "payload": {"kind": "tls_finding", "system": "core-1",
                        "endpoint": "api.core:443",
                        "crypto": {"tls_version": "TLSv1.0"}},
            "source": "unit"})
        assert r2.status_code == 200
        rules = [d["rule"] for d in r2.json()["recent_detections"]]
        assert "crypto_downgrade" in rules

        attacks = (await client.get("/api/v1/attacks")).json()["detections"]
        assert any(a["rule"] == "crypto_downgrade" for a in attacks)
        summary = (await client.get("/api/v1/attacks/summary")).json()
        assert summary["by_rule"].get("crypto_downgrade", 0) >= 1

        # 3) CBOM v2 written (asset changed), diff works, chain verifies
        live2 = (await client.get("/api/v1/cbom/live/core-1")).json()
        assert live2["version_no"] == 2
        diff = (await client.get("/api/v1/cbom/diff",
                                 params={"system": "core-1", "from_v": 1, "to_v": 2})).json()
        assert diff["changed"] or diff["added"] or diff["removed"]
        verdict = (await client.get("/api/v1/cbom/verify/core-1")).json()
        assert verdict["chain_valid"] is True and verdict["versions"] == 2


@pytest.mark.asyncio
async def test_stream_stats_and_topic_guard(stream_env):
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        stats = (await client.get("/api/v1/stream/stats")).json()
        assert "raw-events" in stats["topics"]
        bad = (await client.get("/api/v1/stream/events",
                                params={"topic": "made-up"}))
        assert bad.status_code == 422
        ok = (await client.get("/api/v1/stream/events",
                               params={"topic": "audit-log"})).json()
        assert ok["topic"] == "audit-log"
        missing = (await client.get("/api/v1/cbom/live/never-scanned"))
        assert missing.status_code == 404
