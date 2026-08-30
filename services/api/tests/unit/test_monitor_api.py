"""Live monitoring API: watch-list CRUD, scan-now, status aggregation."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register all tables
from api.dependencies import get_current_user, get_db_session, require_auditor
from api.main import create_app
from db.connection.session import Base


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
    app.dependency_overrides[get_current_user] = lambda: "soc"
    app.dependency_overrides[require_auditor] = lambda: "soc-auditor"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session, engine


@pytest.mark.asyncio
async def test_target_crud_and_validation():
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        bad_type = await client.post("/api/v1/monitor/targets", json={
            "name": "x", "target_type": "QUANTUM", "config": {}})
        assert bad_type.status_code == 422
        no_endpoints = await client.post("/api/v1/monitor/targets", json={
            "name": "x", "target_type": "NETWORK", "config": {}})
        assert no_endpoints.status_code == 422
        bad_interval = await client.post("/api/v1/monitor/targets", json={
            "name": "x", "target_type": "NETWORK", "config": {"endpoints": ["h:443"]},
            "interval_seconds": 5})
        assert bad_interval.status_code == 422

        created = await client.post("/api/v1/monitor/targets", json={
            "name": "Bank API gateway", "target_type": "NETWORK",
            "config": {"endpoints": ["api.bank.example:443", "mtls.bank.example:8443"]}})
        assert created.status_code == 201, created.text
        target = created.json()
        assert target["status"] == "PENDING"
        assert target["interval_seconds"] == 900  # NETWORK default
        assert (await client.post("/api/v1/monitor/targets", json={
            "name": "Bank API gateway", "target_type": "NETWORK",
            "config": {"endpoints": ["h:443"]}})).status_code == 409

        paused = await client.patch(f"/api/v1/monitor/targets/{target['id']}", json={"enabled": False})
        assert paused.json()["status"] == "PAUSED"
        resumed = await client.patch(f"/api/v1/monitor/targets/{target['id']}", json={"enabled": True})
        assert resumed.json()["status"] == "PENDING"

        assert (await client.delete(f"/api/v1/monitor/targets/{target['id']}")).json()["deleted"]
        assert (await client.patch(f"/api/v1/monitor/targets/{target['id']}", json={"enabled": True})).status_code == 404


@pytest.mark.asyncio
async def test_watch_config_validation_and_daemon_health():
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # watch on REPO is accepted and engine-managed watch_state is stripped
        ok = await client.post("/api/v1/monitor/targets", json={
            "name": "payments repo", "target_type": "REPO",
            "config": {"repo": "https://github.com/org/pay.git", "watch": True,
                       "watch_state": {"state": "forged"}}})
        assert ok.status_code == 201, ok.text
        assert (ok.json()["config"] or {}).get("watch") is True
        assert "watch_state" not in ok.json()["config"]

        # watch on a non-watchable type is rejected with a clear 422
        bad = await client.post("/api/v1/monitor/targets", json={
            "name": "edge", "target_type": "NETWORK",
            "config": {"endpoints": ["h:443"], "watch": True}})
        assert bad.status_code == 422
        assert "watch" in bad.json()["detail"] and "REPO" in bad.json()["detail"]

        # status reports daemon liveness honestly (no lease row -> not observed)
        status = (await client.get("/api/v1/monitor/status")).json()
        daemon = status["overview"]["daemon_health"]
        assert daemon["alive"] is False
        assert "run_monitor.py" in daemon["script"]


@pytest.mark.asyncio
async def test_scan_now_runs_the_engine(monkeypatch):
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        created = (await client.post("/api/v1/monitor/targets", json={
            "name": "Payments edge", "target_type": "NETWORK",
            "config": {"endpoints": ["payments.bank.example:443"]}})).json()

        import worker.monitor.engine as engine_module

        def fake_runner(config, sess):
            return {"summary": {"endpoints": 1, "probed_ok": 1, "unreachable": 0,
                                "issues": ["WEAK_TLS_VERSION:payments.bank.example:443"]},
                    "degraded": True, "issues": ["WEAK_TLS_VERSION:payments.bank.example:443"]}

        monkeypatch.setattr(engine_module, "_default_runners", lambda: {"NETWORK": fake_runner})
        run = await client.post(f"/api/v1/monitor/targets/{created['id']}/scan-now")
        assert run.status_code == 200, run.text
        body = run.json()
        assert body["status"] == "DEGRADED"
        assert body["new_issues"] == ["WEAK_TLS_VERSION:payments.bank.example:443"]

        # unknown target 404s; paused target is an honest 409
        assert (await client.post("/api/v1/monitor/targets/nope/scan-now")).status_code == 404
        await client.patch(f"/api/v1/monitor/targets/{created['id']}", json={"enabled": False})
        assert (await client.post(f"/api/v1/monitor/targets/{created['id']}/scan-now")).status_code == 409


@pytest.mark.asyncio
async def test_status_overview_aggregates_the_live_picture(monkeypatch):
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for name in ("edge-a", "edge-b"):
            await client.post("/api/v1/monitor/targets", json={
                "name": name, "target_type": "NETWORK", "config": {"endpoints": [f"{name}:443"]}})
        await client.post("/api/v1/monitor/targets", json={
            "name": "aws-prod", "target_type": "CLOUD", "config": {}})  # no creds -> BLOCKED
        await client.patch("/api/v1/monitor/targets", json={})  # no-op guard
        targets = (await client.get("/api/v1/monitor/targets")).json()["targets"]
        by_name = {t["name"]: t for t in targets}
        await client.patch(f"/api/v1/monitor/targets/{by_name['edge-a']['id']}", json={"enabled": False})

        import worker.monitor.engine as engine_module

        monkeypatch.setattr(engine_module, "_default_runners", lambda: {
            "NETWORK": lambda c, s: {"summary": {"endpoints": 1}, "issues": []},
            "CLOUD": lambda c, s: {"blocked_reason": "config needs provider and account identifier"},
        })
        for name in ("edge-b", "aws-prod"):
            await client.post(f"/api/v1/monitor/targets/{by_name[name]['id']}/scan-now")

        status = (await client.get("/api/v1/monitor/status")).json()
        overview = status["overview"]
        assert overview["targets_total"] == 3
        assert overview["by_status"] == {"BLOCKED": 1, "OK": 1, "PAUSED": 1}
        assert overview["by_type"] == {"NETWORK": 2, "CLOUD": 1}
        assert overview["enabled"] == 2
        assert "run_monitor.py" in overview["daemon"]  # honest: the API is not the loop
        assert [t["name"] for t in status["needs_attention"]] == ["aws-prod"]
        types = {e["event_type"] for e in status["recent_events"]}
        assert types == {"SCAN_OK", "BLOCKED"}

        events = (await client.get("/api/v1/monitor/events", params={"limit": 10})).json()["events"]
        assert len(events) == 2 and all(events[0]["created_at"] for e in events)
