"""Telecom guardrails preset — install, idempotency, RBAC, and firing.

POST /automation/telecom-guardrails installs the curated 3GPP/NIST default
rules through the SAME store/validation as operator-authored rules; the
test proves they (a) install and re-install cleanly, (b) are admin-gated,
(c) actually fire with the right matched rule and actions on roaming-plane
PQC drift — and do NOT fire outside their plane.
"""

from __future__ import annotations

import db.models  # noqa: F401 — register all tables
import pytest
from api.dependencies import get_db_session
from api.main import create_app
from db.connection.session import Base, configure_session
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


@pytest.fixture()
def app_db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    configure_session(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    application = create_app()

    def _session():
        yield session

    application.dependency_overrides[get_db_session] = _session
    application.state.test_session = session
    yield application
    application.dependency_overrides.clear()


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
    return {"Authorization": f"Bearer {_mint(session, 'grd-' + roles[0], roles)}"}


@pytest.mark.asyncio
async def test_guardrails_install_idempotent_and_fire(app_db):
    session = app_db.state.test_session
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        admin = _auth(session, ["superadmin"])

        first = await client.post("/api/v1/automation/telecom-guardrails", headers=admin)
        assert first.status_code == 200, first.text
        body = first.json()
        assert body["installed"] == 3 and body["created"] == 3

        listed = (await client.get("/api/v1/automation/rules", headers=admin)).json()
        ids = {r["rule_id"]: r for r in listed["rules"]}
        assert {"guardrail-roaming-pqc-drop", "guardrail-mission-nf-down",
                "guardrail-sepp-cert-expiry"} <= set(ids)
        assert ids["guardrail-roaming-pqc-drop"]["then"] == ["add_pqc_queue", "create_ticket", "create_alert"]

        # idempotent: re-install updates in place, never duplicates
        second = (await client.post("/api/v1/automation/telecom-guardrails", headers=admin)).json()
        assert second["created"] == 0 and second["updated"] == 3
        listed_again = (await client.get("/api/v1/automation/rules", headers=admin)).json()
        assert listed_again["total_count"] == listed["total_count"]

        # a roaming-plane PQC regression fires THE guardrail with its actions
        run = (await client.post("/api/v1/automation/process-event", headers=admin, json={
            "event_kind": "quantum_vulnerable_detected",
            "data": {"plane": "roaming", "nf_type": "sepp", "nf_id": "gw-za-01",
                     "carrier_code": "de-telekom", "severity": "HIGH"}})).json()
        assert any(m["rule_id"] == "guardrail-roaming-pqc-drop"
                   for m in run["plan"]["matched_rules"])
        actions = {a["action"] for a in run["plan"]["auto_actions"]}
        assert {"add_pqc_queue", "create_ticket", "create_alert"} <= actions

        # the same drift on the 5gc plane does NOT trip the roaming guardrail
        run5gc = (await client.post("/api/v1/automation/process-event", headers=admin, json={
            "event_kind": "quantum_vulnerable_detected",
            "data": {"plane": "5gc", "nf_type": "amf", "nf_id": "amf-01"}})).json()
        assert not any(m.get("rule_id") == "guardrail-roaming-pqc-drop"
                       for m in run5gc["plan"]["matched_rules"])


@pytest.mark.asyncio
async def test_guardrails_are_admin_gated(app_db):
    session = app_db.state.test_session
    transport = ASGITransport(app=app_db)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        readonly = _auth(session, ["readonly"])
        denied = await client.post("/api/v1/automation/telecom-guardrails", headers=readonly)
        assert denied.status_code == 403
