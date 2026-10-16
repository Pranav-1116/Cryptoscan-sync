"""The connector health probe (§4.8, round 79).

A registered, enabled integration is not evidence the external system is
reachable. GET /health/connectors measures each connector from the outbound
delivery audit (cp_delivery_logs — one row per real signed HTTP attempt or
air-gap skip): last outcome and age, recent counts, and an honest verdict.
Registration alone reports Not measured — no synthetic "connected" status
is derived from the enabled flag.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register tables
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models.control_plane import DeliveryLog
from db.models.enterprise import Integration


def _make_app():
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "conn-health-" + "z" * 20)
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "auditor"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session, engine


def _integration(session, *, name="soc", kind="siem", enabled=True, endpoint="https://soc.example/hook"):
    row = Integration(kind=kind, provider="webhook", name=name, enabled=enabled,
                      endpoint=endpoint)
    session.add(row)
    session.flush()
    return row


def _log(session, integration_id, status, *, http_status=None, error=None, age_s=30):
    session.add(DeliveryLog(
        integration_id=integration_id, provider="webhook", kind="siem",
        event_type="notification.remediation_verification", status=status,
        attempts=1, http_status=http_status, error=error,
        created_at=datetime.now(timezone.utc) - timedelta(seconds=age_s)))
    session.commit()


async def _get(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/api/v1/health/connectors")
        assert r.status_code == 200, r.text
        return r.json()


@pytest.mark.asyncio
async def test_no_integrations_is_honestly_not_measured():
    app, session, engine = _make_app()
    body = await _get(app)
    assert body["status"] == "Not measured"
    assert body["count"] == 0
    assert "nothing to measure" in body["detail"]


@pytest.mark.asyncio
async def test_registration_alone_is_not_health_evidence():
    app, session, engine = _make_app()
    _integration(session, name="soc")
    body = await _get(app)
    (row,) = body["connectors"]
    assert row["status"] == "Not measured"
    assert "registration is not health evidence" in row["detail"]
    assert row["last_delivery"] is None
    # the fleet verdict is honest too: nothing measured
    assert body["status"] == "Not measured"


@pytest.mark.asyncio
async def test_last_delivered_attempt_is_operational_with_age():
    app, session, engine = _make_app()
    integ = _integration(session, name="soc")
    _log(session, integ.id, "delivered", http_status=200, age_s=45)
    body = await _get(app)
    (row,) = body["connectors"]
    assert row["status"] == "Operational"
    assert "delivered (HTTP 200)" in row["detail"]
    assert row["last_delivery"]["age_s"] is not None and row["last_delivery"]["age_s"] >= 40
    assert row["recent_counts"] == {"delivered": 1}
    assert body["status"] == "Operational"


@pytest.mark.asyncio
async def test_last_failed_attempt_is_degraded_with_reason():
    app, session, engine = _make_app()
    integ = _integration(session, name="soc")
    _log(session, integ.id, "delivered", http_status=200, age_s=600)
    _log(session, integ.id, "failed", http_status=503, error="receiver unavailable", age_s=30)
    body = await _get(app)
    (row,) = body["connectors"]
    assert row["status"] == "Degraded"
    assert "failed (HTTP 503): receiver unavailable" in row["detail"]
    assert row["recent_counts"] == {"delivered": 1, "failed": 1}
    assert body["status"] == "Degraded"


@pytest.mark.asyncio
async def test_air_gap_connector_reports_outbox_never_delivered():
    app, session, engine = _make_app()
    integ = _integration(session, name="airgap-soc", endpoint=None)
    _log(session, integ.id, "skipped", error="no endpoint configured (air-gap/outbox — event retained)")
    body = await _get(app)
    (row,) = body["connectors"]
    assert row["status"] == "Outbox (air-gap)"
    assert "delivery is not claimed" in row["detail"]
    # an air-gapped connector is neither Operational nor Degraded
    assert body["status"] == "Not measured"


@pytest.mark.asyncio
async def test_disabled_connector_is_disabled_not_degraded():
    app, session, engine = _make_app()
    integ = _integration(session, name="old-soc", enabled=False)
    _log(session, integ.id, "failed", http_status=500, error="boom")
    body = await _get(app)
    (row,) = body["connectors"]
    assert row["status"] == "Disabled"
    assert "disabled by an operator" in row["detail"]
    # disabled failures do not degrade the measured fleet
    assert body["status"] == "Not measured"
