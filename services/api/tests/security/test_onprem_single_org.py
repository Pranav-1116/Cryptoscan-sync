"""A single-bank install must not answer its own admin with a 403.

The deployment the product documents is one bank, one organisation, one
installation. Until now an account the administrator created met
"No tenant membership — ask your organization owner for an invite" on first
login, in an install whose only owner was the platform admin who created it.

``ONPREM_SINGLE_ORG`` fixes that by provisioning the install's organisation on
first use and attaching the account at a configured, least-privileged role.
These tests hold the boundary of that behaviour:

* off (the default, and every SaaS/multi-org install): the 403 stays;
* on: the account is attached once, at the configured role, and the grant is
  attributable in the tenant's provision log;
* a suspended organisation stays suspended;
* the production gate refuses combinations that would turn it into a
  privilege grant or an open door.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import Session

import db.models  # noqa: F401 — register every table
from api.config.settings import get_settings
from api.dependencies import get_db_session
from api.main import create_app
from api.security.session_manager import SessionManager
from db.connection.session import Base, configure_session
from db.models.tenant import Tenant, TenantMembership
from db.repositories.tenant_repository import TenantRepository
from db.repositories.user_repository import UserRepository


@pytest.fixture()
def onprem(monkeypatch):
    """A fresh install with no organisation and one admin-created analyst."""
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    # The tenant-scope middleware resolves through SessionLocal, not through the
    # dependency override, so the process-wide session factory must point here.
    configure_session(engine)
    session = Session(bind=engine)

    UserRepository(session).create_user("analyst", "x", roles=["readonly"])
    session.commit()

    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ONPREM_SINGLE_ORG", "true")
    monkeypatch.setenv("ONPREM_DEFAULT_ORG_SLUG", "bank-onprem")
    monkeypatch.setenv("ONPREM_DEFAULT_ORG_NAME", "Bank On-Prem")
    monkeypatch.setenv("ONPREM_AUTO_MEMBERSHIP_ROLE", "viewer")
    get_settings.cache_clear()

    app = create_app()
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    token = SessionManager().create_session("analyst", roles=["readonly"])
    client = TestClient(app, headers={"Authorization": f"Bearer {token}"})

    try:
        yield {"client": client, "session": session, "engine": engine}
    finally:
        get_settings.cache_clear()
        app.dependency_overrides.clear()
        session.close()
        engine.dispose()


def test_the_first_request_creates_the_install_org_and_a_viewer_membership(onprem):
    response = onprem["client"].get("/api/v1/systems")
    # 200 (empty estate) instead of 403: this account belongs somewhere now.
    assert response.status_code == 200, response.text

    session = onprem["session"]
    tenant = TenantRepository(session).get_by_slug("bank-onprem")
    assert tenant is not None and tenant.name == "Bank On-Prem"
    membership = TenantRepository(session).membership(tenant.id, "analyst")
    assert membership is not None and membership.tenant_role == "viewer"


def test_the_grant_is_attributable_in_the_provision_log(onprem):
    onprem["client"].get("/api/v1/systems")
    session = onprem["session"]
    tenant = TenantRepository(session).get_by_slug("bank-onprem")
    events = TenantRepository(session).events(tenant.id) if hasattr(TenantRepository(session), "events") else None
    if events is None:  # the repository exposes provisioning rows through the model
        from db.models.tenant import TenantProvisionEvent
        from sqlalchemy import select

        events = list(
            session.execute(
                select(TenantProvisionEvent).where(TenantProvisionEvent.tenant_id == tenant.id)
            ).scalars()
        )
    kinds = {event.action for event in events}
    assert "member_add" in kinds
    adds = [event for event in events if event.action == "member_add"]
    # The grant happened without a human clicking; the actor field is what makes
    # it reviewable afterwards.
    assert any(event.actor == "onprem:auto-membership" for event in adds)
    assert any("analyst:viewer" in (event.detail or "") for event in adds)


def test_a_second_request_does_not_duplicate_the_membership(onprem):
    client, session = onprem["client"], onprem["session"]
    assert client.get("/api/v1/systems").status_code == 200
    assert client.get("/api/v1/systems").status_code == 200
    tenant = TenantRepository(session).get_by_slug("bank-onprem")
    rows = [m for m in session.query(TenantMembership).all() if m.tenant_id == tenant.id]
    assert len(rows) == 1


def test_switching_the_setting_off_restores_the_403(onprem, monkeypatch):
    monkeypatch.setenv("ONPREM_SINGLE_ORG", "false")
    get_settings.cache_clear()
    response = onprem["client"].get("/api/v1/systems")
    assert response.status_code == 403
    assert "No tenant membership" in response.text


def test_a_suspended_organisation_stays_suspended(onprem, monkeypatch):
    client, session = onprem["session"], onprem["session"]
    repo = TenantRepository(session)
    tenant = repo.create(name="Bank On-Prem", slug="bank-onprem")
    repo.set_status(tenant.id, "SUSPENDED", actor="test", reason="compliance hold")
    session.commit()

    response = onprem["client"].get("/api/v1/systems")
    assert response.status_code == 423
    assert repo.membership(tenant.id, "analyst") is None


def _production(**overrides):
    from api.config.settings import APISettings

    values = dict(
        ENVIRONMENT="production",
        SECRET_KEY="n" * 40,
        ADMIN_PASSWORD="",
        ADMIN_PASSWORD_HASH="pbkdf2_sha256$600000$c2FsdA==$aGFzaA==",
        GITHUB_WEBHOOK_SECRET="x" * 32,
        DATABASE_URL="postgresql://c:c@postgres:5432/c",
        REDIS_URL="rediss://replay:pw@redis:6379/0",
        EVENT_TAILER_SECONDS=2,
        CORS_ORIGINS="https://console.example",
        TRUSTED_HOSTS=["console.example"],
        METRICS_TOKEN="m" * 32,
        REGISTRY_WEBHOOK_SECRET="r" * 32,
        CBOM_SIGNING_SECRET="c" * 32,
        STREAM_SECRET="s" * 32,
        AUDITOR_API_KEY="a" * 32,
        CRYPTOSCAN_DEPLOYMENT_PROFILE="kubernetes-external-services/local-source-v1",
        NEO4J_URI="",
        TRUSTED_PROXY_COUNT=1,
        TRUSTED_PROXY_CIDRS="10.20.0.0/24",
    )
    values.update(overrides)
    return APISettings.model_construct(**values)


@pytest.mark.parametrize(
    "overrides, needle, signup",
    [
        ({"ONPREM_AUTO_MEMBERSHIP_ROLE": "superadmin"}, "must be viewer, member, admin or owner", None),
        ({"ONPREM_AUTO_MEMBERSHIP_ROLE": "admin"}, "requires ONPREM_AUTO_MEMBERSHIP_ADMIN_ACK", None),
        ({}, "cannot be combined with CRYPTOSCAN_SAAS_SIGNUP", "true"),
        ({"ONPREM_DEFAULT_ORG_SLUG": "  "}, "must name the install's organisation", None),
    ],
)
def test_the_gate_refuses_dangerous_combinations(monkeypatch, overrides, needle, signup):
    from api.config.settings import validate_runtime_settings

    if signup is None:
        monkeypatch.delenv("CRYPTOSCAN_SAAS_SIGNUP", raising=False)
    else:
        monkeypatch.setenv("CRYPTOSCAN_SAAS_SIGNUP", signup)
    values = {"ONPREM_SINGLE_ORG": True, **overrides}
    if overrides.get("ONPREM_DEFAULT_ORG_SLUG"):
        values["ONPREM_DEFAULT_ORG_SLUG"] = overrides["ONPREM_DEFAULT_ORG_SLUG"]
    with pytest.raises(RuntimeError) as excinfo:
        validate_runtime_settings(_production(**values))
    assert needle in str(excinfo.value)


def test_an_onprem_production_install_with_viewer_auto_membership_is_accepted(monkeypatch):
    from api.config.settings import validate_runtime_settings

    monkeypatch.delenv("CRYPTOSCAN_SAAS_SIGNUP", raising=False)
    validate_runtime_settings(_production(ONPREM_SINGLE_ORG=True))
