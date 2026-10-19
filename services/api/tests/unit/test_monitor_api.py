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
        # enterprise extras: ipsec / dnssec-only NETWORK targets are valid
        ipsec_only = await client.post("/api/v1/monitor/targets", json={
            "name": "vpn-watch", "target_type": "NETWORK",
            "config": {"ipsec": ["vpn-gw.example.com"], "ike_ports": "500,4500"}})
        assert ipsec_only.status_code == 201, ipsec_only.text
        dnssec_only = await client.post("/api/v1/monitor/targets", json={
            "name": "zone-watch", "target_type": "NETWORK",
            "config": {"dnssec": ["example.com"], "dns_resolver": "10.0.0.53:53"}})
        assert dnssec_only.status_code == 201, dnssec_only.text
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
async def test_ot_and_vendor_targets():
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # OT target with watch -> accepted (capture-dir fingerprint probe)
        ot = await client.post("/api/v1/monitor/targets", json={
            "name": "plant-floor", "target_type": "OT",
            "config": {"path": "/var/log/ot", "watch": True}})
        assert ot.status_code == 201, ot.text
        assert ot.json()["target_type"] == "OT"
        # OT without a path -> 422
        assert (await client.post("/api/v1/monitor/targets", json={
            "name": "bad-ot", "target_type": "OT", "config": {}})).status_code == 422
        # VENDOR target -> accepted
        vendor = await client.post("/api/v1/monitor/targets", json={
            "name": "acme", "target_type": "VENDOR",
            "config": {"name": "Acme HSM", "algorithms": ["DES"]}})
        assert vendor.status_code == 201, vendor.text
        # VENDOR without a name -> 422
        assert (await client.post("/api/v1/monitor/targets", json={
            "name": "bad-vendor", "target_type": "VENDOR", "config": {}})).status_code == 422
        # watch still rejected on NETWORK
        assert (await client.post("/api/v1/monitor/targets", json={
            "name": "edge", "target_type": "NETWORK",
            "config": {"endpoints": ["h:443"], "watch": True}})).status_code == 422


@pytest.mark.asyncio
async def test_runtime_ingest_publishes_realtime_event(monkeypatch):
    published: list[tuple[str, dict]] = []

    class FakeBus:
        def publish(self, event_type, payload, source=None):
            published.append((event_type, payload))

    monkeypatch.setattr("api.events.bus.get_event_bus", lambda: FakeBus())
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/v1/scans/runtime-findings", json={
            "scanner_id": "tls-tap-agent-v1",
            "findings": [{
                "process_name": "paymentd",
                "hostname": "prod-1",
                "library_name": "openssl",
                "algorithm": "TLS1.0",
                "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                "key_size": 1024,
            }],
        })
        assert resp.status_code == 200, resp.text
        assert resp.json()["anomalies"] == 1
    assert len(published) == 1
    assert published[0][0] == "runtime.finding"
    assert published[0][1]["anomalies"] == 1


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
            return {"observation_complete": True, "summary": {"endpoints": 1, "probed_ok": 1, "unreachable": 0,
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
            "NETWORK": lambda c, s: {"observation_complete": True, "summary": {"endpoints": 1}, "issues": []},
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


@pytest.mark.asyncio
async def test_network_scope_targets():
    """Global discovery scope is a first-class NETWORK target config."""
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        created = await client.post("/api/v1/monitor/targets", json={
            "name": "global-discovery", "target_type": "NETWORK",
            "config": {"scope": ["10.0.0.0/24", "*.corp.example.com"]}})
        assert created.status_code == 201, created.text
        assert created.json()["config"]["scope"] == ["10.0.0.0/24", "*.corp.example.com"]

        # string scope accepted
        created = await client.post("/api/v1/monitor/targets", json={
            "name": "dc-scope", "target_type": "NETWORK",
            "config": {"scope": "10.10.0.0/16"}})
        assert created.status_code == 201, created.text

        # DEEP requires authorization_scope even via API
        bad = await client.post("/api/v1/monitor/targets", json={
            "name": "deep-no-auth", "target_type": "NETWORK",
            "config": {"scope": ["10.0.0.0/24"], "scan_mode": "DEEP"}})
        assert bad.status_code == 422
        assert "authorization_scope" in bad.json()["detail"]

        # DEEP with authorization passes
        ok = await client.post("/api/v1/monitor/targets", json={
            "name": "deep-auth", "target_type": "NETWORK",
            "config": {"scope": ["10.0.0.0/24"], "scan_mode": "DEEP",
                       "authorization_scope": "emirates-dc"}})
        assert ok.status_code == 201, ok.text

        # malformed scope rejected
        bad = await client.post("/api/v1/monitor/targets", json={
            "name": "bad-scope", "target_type": "NETWORK",
            "config": {"scope": [123]}})
        assert bad.status_code == 422


@pytest.mark.asyncio
async def test_network_target_with_live_monitor_config():
    """NETWORK targets accept config.live (modes + priority) and validate it."""
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        ok = await client.post("/api/v1/monitor/targets", json={
            "name": "bank-live",
            "target_type": "NETWORK",
            "config": {
                "scope": ["10.0.0.0/24"],
                "live": {
                    "modes": ["REALTIME_EVENT", "PASSIVE", "PERIODIC_LIGHTWEIGHT",
                              "SCHEDULED_DEEP", "CHANGE_TRIGGERED"],
                    "priority": {"business_criticality": 10.0, "crypto_risk": 8.0},
                },
            },
        })
        assert ok.status_code == 201
        body = ok.json()
        assert body["config"]["live"]["modes"][0] == "REALTIME_EVENT"

        # unknown mode
        bad_mode = await client.post("/api/v1/monitor/targets", json={
            "name": "bad-mode", "target_type": "NETWORK",
            "config": {"scope": ["10.0.0.0/24"], "live": {"modes": ["CONTINUOUS"]}},
        })
        assert bad_mode.status_code == 422

        # priority component out of range
        bad_priority = await client.post("/api/v1/monitor/targets", json={
            "name": "bad-priority", "target_type": "NETWORK",
            "config": {"scope": ["10.0.0.0/24"],
                       "live": {"priority": {"business_criticality": 42}}},
        })
        assert bad_priority.status_code == 422

        # live is not an object
        bad_shape = await client.post("/api/v1/monitor/targets", json={
            "name": "bad-shape", "target_type": "NETWORK",
            "config": {"scope": ["10.0.0.0/24"], "live": "yes"},
        })
        assert bad_shape.status_code == 422


@pytest.mark.asyncio
async def test_telecom_target_type_accepted_with_default_interval():
    """TELECOM (continuous 5GC/roaming posture) is a first-class monitor type:
    accepted with no required config (the registered estate IS the scope),
    stored, and listed like any other target."""
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        created = await client.post("/api/v1/monitor/targets", json={
            "name": "carrier estate watch", "target_type": "TELECOM",
            "config": {"carrier": "de-telekom"}})
        assert created.status_code == 201, created.text
        body = created.json()
        assert (body.get("interval_seconds") in (None, 900)), body

        listed = await client.get("/api/v1/monitor/targets")
        types = {t["target_type"] for t in listed.json().get("targets", listed.json() if isinstance(listed.json(), list) else [])}
        assert "TELECOM" in types


@pytest.mark.asyncio
async def test_shortened_interval_takes_effect_immediately():
    """Lowering the interval pulls next_scan_at in (never waits out the old
    window); lengthening never accelerates the current schedule."""
    from datetime import datetime, timedelta, timezone

    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        created = await client.post("/api/v1/monitor/targets", json={
            "name": "edge", "target_type": "NETWORK",
            "config": {"endpoints": ["h.example:443"]}, "interval_seconds": 900})
        tid = created.json()["id"]
        row = next(t for t in session.execute(__import__("sqlalchemy").select(
            __import__("db.models.monitor", fromlike=["MonitorTarget"]).MonitorTarget)).scalars() if False) if False else None
        from db.models.monitor import MonitorTarget
        from sqlalchemy import select
        row = session.execute(select(MonitorTarget)).scalars().first()
        now = datetime.now(timezone.utc).replace(tzinfo=None)  # DB stores naive UTC
        row.last_scan_at = now
        row.next_scan_at = now + timedelta(seconds=900)
        session.commit()

        r = await client.patch(f"/api/v1/monitor/targets/{tid}", json={"interval_seconds": 60})
        assert r.status_code == 200, r.text
        session.expire_all()
        row = session.execute(select(MonitorTarget)).scalars().first()
        assert row.interval_seconds == 60
        assert row.next_scan_at <= now + timedelta(seconds=61)

        # lengthening never accelerates an already-scheduled sooner run
        soon = now + timedelta(seconds=30)
        row.next_scan_at = soon
        session.commit()
        await client.patch(f"/api/v1/monitor/targets/{tid}", json={"interval_seconds": 3600})
        session.expire_all()
        row = session.execute(select(MonitorTarget)).scalars().first()
        assert row.next_scan_at == soon


@pytest.mark.asyncio
async def test_monitor_network_targets_reject_ssrf_targets():
    """OWASP A10 (found by live attack testing 2026-09-13): the monitor used
    to accept loopback / cloud-metadata / URL-scheme endpoints — a monitor
    target must never become an internal probe primitive. Configs now pass
    the platform's SSRF choke point at create AND update."""
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for name, cfg in [
            ("metadata-ip", {"endpoints": ["169.254.169.254:80"]}),
            ("metadata-url", {"endpoints": ["http://169.254.169.254/latest/meta-data/"]}),
            ("loopback", {"endpoints": ["127.0.0.1:8010"]}),
            ("metadata-v6", {"endpoints": ["[fd00:ec2::254]:80"]}),
            ("scope-metadata", {"scope": ["169.254.169.254/32"]}),
            ("userinfo", {"endpoints": ["user:pass@internal.example:443"]}),
        ]:
            r = await client.post("/api/v1/monitor/targets", json={
                "name": f"ssrf-{name}", "target_type": "NETWORK", "config": cfg})
            assert r.status_code == 422, (name, r.status_code, r.text)

        ok = await client.post("/api/v1/monitor/targets", json={
            "name": "public-edge", "target_type": "NETWORK",
            "config": {"endpoints": ["api.bank.example:443"]}})
        assert ok.status_code == 201, ok.text

        # update path is gated too: a legit target cannot be edited into a probe
        tid = ok.json()["id"]
        bad = await client.patch(f"/api/v1/monitor/targets/{tid}", json={
            "config": {"endpoints": ["169.254.169.254:80"]}})
        assert bad.status_code == 422
