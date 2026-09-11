"""Automation connector endpoints — status, preview, dispatch.

The pure mappers are covered in services/automation/tests; here the API
surface is pinned: configuration names leave the process, values never do;
preview sends nothing; dispatch is honest about configuration and delivery.
"""

from __future__ import annotations

from types import SimpleNamespace

import db.models  # noqa: F401 — register all tables
import pytest
from api.dependencies import get_db_session
from api.main import create_app
from db.connection.session import Base, configure_session
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool


@pytest.fixture()
def app_db(monkeypatch):
    monkeypatch.delenv("SERVICENOW_INSTANCE_URL", raising=False)
    monkeypatch.delenv("SERVICENOW_USER", raising=False)
    monkeypatch.delenv("SERVICENOW_PASSWORD", raising=False)
    monkeypatch.delenv("SPLUNK_HEC_URL", raising=False)
    monkeypatch.delenv("SPLUNK_HEC_TOKEN", raising=False)
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    configure_session(engine)
    from sqlalchemy.orm import sessionmaker

    session = sessionmaker(bind=engine, expire_on_commit=False)()
    application = create_app()

    def _session():
        yield session

    application.dependency_overrides[get_db_session] = _session
    application.state.test_session = session
    yield application
    application.dependency_overrides.clear()
    get_settings.cache_clear()


def _mint(session, username: str, roles: list[str]) -> str:
    from datetime import datetime, timedelta, timezone

    from api.security.passwords import hash_password
    from api.security.session_manager import SessionManager
    from db.repositories.user_repository import UserRepository

    repo = UserRepository(session)
    if repo.get_by_username(username) is None:
        repo.create_user(username, hash_password("x"), roles)
        session.commit()
    token = SessionManager().create_session(username, roles=roles)
    expires = datetime.now(timezone.utc) + timedelta(hours=1)
    repo.create_session(token, username, expires, ip="127.0.0.1")
    session.commit()
    return token


def _auth(session, roles: list[str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {_mint(session, 'conn-' + roles[0], roles)}"}


def _seed_run(session) -> str:
    from db.models.automation import AutomationRun

    row = AutomationRun(
        event_kind="agent_offline", asset_id="asset-9",
        scanners=[], auto_actions=[{"action": "targeted_rescan", "risk": "LOW"}],
        gated_actions=[{"action": "create_ticket", "risk": "HIGH"}],
        matched_rules=[], playbook="pb_telecom_nf_down",
        needs_human=False, recommended_tier="CRITICAL",
        triggered_by="event-bus:telecom-scanner")
    session.add(row)
    session.commit()
    return row.id


@pytest.mark.asyncio
async def test_connectors_status_reports_names_only(app_db):
    session = app_db.state.test_session
    headers = _auth(session, ["ciso"])
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        body = (await client.get("/api/v1/automation/connectors", headers=headers)).json()
    assert body["connectors"]["servicenow"]["configured"] is False
    assert "SERVICENOW_INSTANCE_URL" in body["connectors"]["servicenow"]["missing"]
    assert body["connectors"]["splunk"]["configured"] is False
    assert set(body["catalog"]) == {"servicenow", "splunk"}
    # no configured value ever appears in the response
    assert "pw" not in str(body)


@pytest.mark.asyncio
async def test_connectors_status_reflects_configuration(app_db, monkeypatch):
    monkeypatch.setenv("SPLUNK_HEC_URL", "https://splunk.acme.com:8088/services/collector/event")
    monkeypatch.setenv("SPLUNK_HEC_TOKEN", "hec-secret-token")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    session = app_db.state.test_session
    headers = _auth(session, ["ciso"])
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        body = (await client.get("/api/v1/automation/connectors", headers=headers)).json()
    assert body["connectors"]["splunk"]["configured"] is True
    assert body["connectors"]["splunk"]["missing"] == []
    assert "hec-secret-token" not in str(body)


@pytest.mark.asyncio
async def test_preview_builds_payload_without_sending(app_db):
    session = app_db.state.test_session
    run_id = _seed_run(session)
    headers = _auth(session, ["security_analyst"])
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        body = (await client.post("/api/v1/automation/connectors/preview",
                                  json={"connector": "servicenow", "run_id": run_id},
                                  headers=headers)).json()
        assert body["delivered"] is False and "nothing was sent" in body["note"]
        payload = body["payload"]
        assert payload["impact"] == 1 and payload["urgency"] == 1
        assert payload["correlation_id"] == f"cryptoscan:automation:{run_id}"
        assert "pb_telecom_nf_down" in payload["short_description"]

        splunk = (await client.post("/api/v1/automation/connectors/preview",
                                    json={"connector": "splunk", "run_id": run_id},
                                    headers=headers)).json()["payload"]
    assert splunk["sourcetype"] == "cryptoscan:automation"
    assert splunk["event"]["playbook"] == "pb_telecom_nf_down"


@pytest.mark.asyncio
async def test_dispatch_delivers_via_injected_poster(app_db, monkeypatch):
    import automation.connectors as connectors_module

    monkeypatch.setenv("SERVICENOW_INSTANCE_URL", "https://acme.service-now.com")
    monkeypatch.setenv("SERVICENOW_USER", "svc-cryptoscan")
    monkeypatch.setenv("SERVICENOW_PASSWORD", "pw")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    captured = {}

    def fake_post(url, *, json=None, headers=None, auth=None, timeout=None):
        captured.update({"url": url, "json": json, "auth": auth})
        return SimpleNamespace(status_code=201, text='{"sys_id": "ABC123"}')

    monkeypatch.setattr(connectors_module, "_httpx_post", fake_post)
    session = app_db.state.test_session
    run_id = _seed_run(session)
    headers = _auth(session, ["ciso"])
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        body = (await client.post("/api/v1/automation/connectors/dispatch",
                                  json={"connector": "servicenow", "run_id": run_id},
                                  headers=headers)).json()
    assert body["delivered"] is True and body["status_code"] == 201
    assert captured["url"] == "https://acme.service-now.com/api/now/table/incident"
    assert captured["auth"] == ("svc-cryptoscan", "pw")
    assert body["detail"] == '{"sys_id": "ABC123"}'


@pytest.mark.asyncio
async def test_dispatch_without_configuration_is_honest(app_db):
    session = app_db.state.test_session
    run_id = _seed_run(session)
    headers = _auth(session, ["ciso"])
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        body = (await client.post("/api/v1/automation/connectors/dispatch",
                                  json={"connector": "splunk", "run_id": run_id},
                                  headers=headers)).json()
    assert body["delivered"] is False and body["ok"] is False
    assert "SPLUNK_HEC_URL" in body["detail"] and "SPLUNK_HEC_TOKEN" in body["detail"]


@pytest.mark.asyncio
async def test_dispatch_unknown_run_404_and_readonly_403(app_db):
    session = app_db.state.test_session
    headers = _auth(session, ["ciso"])
    readonly = _auth(session, ["readonly"])
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        missing = await client.post("/api/v1/automation/connectors/preview",
                                    json={"connector": "splunk", "run_id": "nope"},
                                    headers=headers)
        assert missing.status_code == 404

        forbidden = await client.get("/api/v1/automation/connectors", headers=readonly)
        assert forbidden.status_code == 403
