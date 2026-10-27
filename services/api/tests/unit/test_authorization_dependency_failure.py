"""Post-auth role/storage failure boundaries, not an end-to-end login claim.

The isolated test route overrides only the already-authenticated principal and
DB dependency. It exercises the real require_roles/_user_roles implementation
with an actual signed token and fault-injected role storage; no product route
or production permission is introduced.
"""
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

from api import dependencies as deps
from api.security.session_manager import SessionManager
from db.repositories.user_repository import UserRepository
from test_software_supply_chain_api import banks as banks

CANARY = "synthetic-authority-password-CANARY-7ef3"


@pytest.fixture
def boundary(monkeypatch):
    def create(production, allowed="admin", token_roles=None):
        monkeypatch.setattr(deps, "_get_settings", lambda: SimpleNamespace(is_production=production))
        token = SessionManager().create_session("synthetic-reader", roles=token_roles or ["readonly"])
        app, effects, db = FastAPI(), [], Mock()
        app.dependency_overrides[deps.get_current_user] = lambda: "synthetic-reader"
        app.dependency_overrides[deps.get_db_session] = lambda: db

        @app.post("/guarded-test-action")
        def action(user=Depends(deps.require_roles(allowed))):
            effects.append(user)
            return {"executed": True}

        return TestClient(app, headers={"Authorization": "Bearer " + token}), effects, db
    return create


def unavailable(*_args, **_kwargs):
    raise RuntimeError("postgresql://user:" + CANARY + "@private-db/identity; SELECT private_user")


@pytest.mark.parametrize("production", [False, True])
@pytest.mark.parametrize("allowed", ["admin", "auditor", "security_analyst"])
@pytest.mark.parametrize("phase", ["role-query", "legacy-provision-query"])
def test_unreadable_role_storage_never_executes_privileged_action(boundary, monkeypatch, caplog, production, allowed, phase):
    client, effects, _ = boundary(production, allowed)
    monkeypatch.setattr(UserRepository, "get_by_username", unavailable)
    if phase == "legacy-provision-query":
        # An independently empty projection is not evidence that a second
        # unreadable provisioning query affirmatively found a legacy user.
        monkeypatch.setattr(deps, "_user_roles", lambda *_: [])
    with client:
        response = client.post("/guarded-test-action")
    assert response.status_code == 503, response.text
    assert effects == []
    assert CANARY not in response.text and CANARY not in caplog.text
    assert any(getattr(r, "error_type", None) == "RuntimeError" for r in caplog.records)
    assert all(r.exc_info is None for r in caplog.records if r.name == deps.logger.name)


def test_missing_production_user_cannot_use_legacy_admin_fallback(boundary, monkeypatch):
    client, effects, _ = boundary(True)
    monkeypatch.setattr(UserRepository, "get_by_username", lambda *_: None)
    with client:
        response = client.post("/guarded-test-action")
    assert response.status_code == 403, response.text
    assert effects == []
    with pytest.raises(HTTPException) as refused:
        deps._user_roles("synthetic-reader", None, Mock())
    assert refused.value.status_code == 403


def test_affirmatively_missing_nonproduction_legacy_user_remains_compatible(boundary, monkeypatch):
    client, effects, _ = boundary(False)
    monkeypatch.setattr(UserRepository, "get_by_username", lambda *_: None)
    with client:
        assert client.post("/guarded-test-action").status_code == 200
    assert effects == ["synthetic-reader"]


@pytest.mark.parametrize("roles,expected", [(["readonly"], 403), (["unknown-custom-role"], 403), (["admin"], 200)])
def test_current_role_row_wins_over_stale_admin_token(boundary, monkeypatch, roles, expected):
    client, effects, _ = boundary(True, token_roles=["admin"])
    monkeypatch.setattr(UserRepository, "get_by_username", lambda *_: SimpleNamespace(role_list=roles))
    with client:
        response = client.post("/guarded-test-action")
    assert response.status_code == expected, response.text
    assert bool(effects) is (expected == 200)


@pytest.mark.parametrize("production", [False, True])
def test_role_lookup_outage_does_not_reuse_token_claims(boundary, monkeypatch, production):
    _client, _, db = boundary(production)
    token = SessionManager().create_session("synthetic-reader", roles=["admin"])
    monkeypatch.setattr(UserRepository, "get_by_username", unavailable)
    with pytest.raises(HTTPException) as refused:
        deps._user_roles("synthetic-reader", token, db)
    assert refused.value.status_code == 503


def test_scope_role_lookup_failure_logs_category_without_exception_payload(monkeypatch, caplog):
    monkeypatch.setattr(UserRepository, "get_by_username", unavailable)
    request = Request({"type": "http", "headers": []})
    assert deps._principal_roles(request, "synthetic-reader", Mock()) == []
    assert CANARY not in caplog.text
    record = next(r for r in caplog.records if r.message == "principal_roles_lookup_failed")
    assert record.error_type == "RuntimeError" and record.exc_info is None


def test_tenant_resolution_outage_refuses_without_logging_connection_secrets(monkeypatch, caplog):
    monkeypatch.setattr("db.connection.session.SessionLocal", lambda: Mock())
    monkeypatch.setattr(deps, "get_current_user", lambda *_: "synthetic-reader")
    monkeypatch.setattr(deps, "_resolve_tenant_context", unavailable)
    request = Request({"type": "http", "headers": [(b"authorization", b"Bearer synthetic-token")]})
    with pytest.raises(deps.TenantResolutionRefused) as refused:
        deps.resolve_tenant_for_request(request)
    assert refused.value.status_code == 503
    assert CANARY not in refused.value.detail and CANARY not in caplog.text
    record = next(r for r in caplog.records if r.message == "tenant_scope_resolution_failed")
    assert record.error_type == "RuntimeError" and record.exc_info is None


@pytest.mark.parametrize("production", [False, True])
def test_missing_user_is_not_a_production_platform_estate_grant(boundary, monkeypatch, production):
    _client, _, db = boundary(production)
    monkeypatch.setattr(UserRepository, "get_by_username", lambda *_: None)
    monkeypatch.setattr("db.repositories.tenant_repository.TenantRepository.memberships_of", lambda *_: [])
    request = Request({"type": "http", "headers": []})
    if production:
        with pytest.raises(HTTPException) as refused:
            deps._resolve_tenant_context(request, "synthetic-reader", db)
        assert refused.value.status_code == 403
    else:
        context = deps._resolve_tenant_context(request, "synthetic-reader", db)
        assert context.tenant_id is None and context.is_platform_admin is True


@pytest.mark.parametrize("state", ["inactive", "deleted"])
def test_current_disabled_or_deleted_row_cannot_authorize_roles_or_platform_scope(boundary, monkeypatch, state):
    client, effects, db = boundary(True)
    row = SimpleNamespace(role_list=["admin"], is_active=state != "inactive",
                          deleted_at="synthetic-tombstone" if state == "deleted" else None)
    monkeypatch.setattr(UserRepository, "get_by_username", lambda *_: row)
    with client:
        response = client.post("/guarded-test-action")
    assert response.status_code == 403, response.text
    assert effects == []
    with pytest.raises(HTTPException) as refused:
        deps._user_roles("synthetic-reader", None, db)
    assert refused.value.status_code == 403
    request = Request({"type": "http", "headers": []})
    assert deps._principal_roles(request, "synthetic-reader", db) == []


@pytest.mark.parametrize("production", [False, True])
@pytest.mark.parametrize("username", ["reader_a", "bank_a"])
def test_authenticated_artifact_write_refuses_role_store_failure_after_login(banks, monkeypatch, caplog, production, username):
    from db.models.software_supply_chain import SoftwareArtifact
    from test_software_supply_chain_api import PREFIX, EVIDENCE, DIGEST

    clients, db, _ = banks
    monkeypatch.setattr(deps, "_get_settings", lambda: SimpleNamespace(is_production=production))
    lookup, roles = UserRepository.get_by_username, deps._user_roles
    state = {"role_stage": False}

    def fail_at_role_stage(repo, user):
        if state["role_stage"]:
            unavailable()
        return lookup(repo, user)

    def enter_role_stage(*args, **kwargs):
        # Normal durable session and tenant checks run first. Inject the
        # dependency failure only when the privileged role gate is reached.
        state["role_stage"] = True
        return roles(*args, **kwargs)

    monkeypatch.setattr(UserRepository, "get_by_username", fail_at_role_stage)
    monkeypatch.setattr(deps, "_user_roles", enter_role_stage)
    before = db.query(SoftwareArtifact).count()
    response = clients[username].post(PREFIX + "/artifacts", json={"digest": DIGEST, **EVIDENCE})
    assert state["role_stage"] is True  # not a refusal by an unrelated earlier gate
    assert response.status_code == 503, response.text
    assert db.query(SoftwareArtifact).count() == before
    assert CANARY not in response.text and CANARY not in caplog.text
