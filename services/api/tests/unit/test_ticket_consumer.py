"""Automation → ITSM ticket consumer (ticketing remainder, round 35)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

import db.models  # noqa: F401
from api.config.settings import get_settings
from db.models.enterprise import Ticket


@pytest.fixture()
def sqlite_app(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/tickets.db")
    monkeypatch.setenv("NEO4J_URI", "")
    get_settings.cache_clear()
    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None
    from api.main import create_app

    app = create_app()
    with TestClient(app) as client:
        yield client, f"sqlite:///{tmp_path}/tickets.db"


def _consume(db_url, event):
    """Call the bridge consumer against the app's database."""
    # the consumer opens SessionLocal itself — run it in-process
    from api.events.automation_bridge import _consume_ticket_request

    return _consume_ticket_request(event)


def _rows(db_url):
    eng = create_engine(db_url)
    session = sessionmaker(bind=eng)()
    rows = list(session.execute(select(Ticket)).scalars())
    out = [(r.external_ref, r.provider, r.severity, r.state, r.title) for r in rows]
    session.close()
    eng.dispose()
    return out


def test_ticket_request_lands_as_ticket(sqlite_app):
    _, db_url = sqlite_app
    result = _consume(db_url, {
        "type": "ticket.requested",
        "source": "automation",
        "payload": {"event_kind": "drift_detected", "asset_id": "asset-9",
                    "severity": "HIGH"},
    })
    assert result["ticket_id"] and result["duplicate"] is False
    rows = _rows(db_url)
    assert rows == [("automation/drift_detected/asset-9", "automation",
                     "high", "open", "[automation] drift_detected — asset asset-9")]


def test_redelivery_is_idempotent(sqlite_app):
    _, db_url = sqlite_app
    event = {"type": "ticket.requested", "source": "automation",
             "payload": {"event_kind": "quantum_vulnerable_detected",
                         "asset_id": "asset-9", "severity": "CRITICAL"}}
    first = _consume(db_url, event)
    second = _consume(db_url, event)
    assert first["duplicate"] is False and second["duplicate"] is True
    assert first["ticket_id"] == second["ticket_id"]
    assert len(_rows(db_url)) == 1


def test_estate_wide_event_gets_a_ticket_too(sqlite_app):
    _, db_url = sqlite_app
    result = _consume(db_url, {
        "type": "ticket.requested", "source": "automation",
        "payload": {"event_kind": "sla_breached", "severity": "MEDIUM"},
    })
    assert result["duplicate"] is False
    rows = _rows(db_url)
    assert rows[0][0] == "automation/sla_breached/estate"
    assert "asset" not in rows[0][4]
