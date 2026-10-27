"""Multi-user auth: bootstrap, login/logout lifecycle, revocation, RBAC, audit."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from api.config.settings import get_settings
from api.security.auth import AuthenticationError, AuthService
from api.security.passwords import hash_password, verify_password
from api.security.session_manager import SessionManager
from db.connection.session import Base, SessionLocal, configure_session
from db.repositories.user_repository import UserRepository
from sqlalchemy import create_engine


@pytest.fixture()
def session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    configure_session(engine)
    s = SessionLocal()
    yield s
    s.close()


def test_bootstrap_creates_admin_once(session, monkeypatch):
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", hash_password("cryptoscan"))
    get_settings.cache_clear()
    service = AuthService(session=session)
    assert service.bootstrap_admin() is True
    user = UserRepository(session).get_by_username("admin")
    # canonical 8-role-catalog name (legacy alias "admin" still maps to superadmin)
    assert user is not None and user.role_list == ["superadmin"]
    assert verify_password("cryptoscan", user.password_hash)
    # Second call is a no-op — existing users are never overwritten.
    assert service.bootstrap_admin() is False


def test_first_login_bootstraps_and_audits(session):
    service = AuthService(session=session)
    user = service.authenticate("admin", "cryptoscan", client_key="127.0.0.1")
    assert user.username == "admin"
    assert user.roles == ["admin"]
    repo = UserRepository(session)
    assert repo.get_by_username("admin") is not None
    events = repo.list_audit(action="auth.bootstrap_admin")
    assert len(events) == 1


def test_wrong_bootstrap_password_rejected_and_audited(session):
    service = AuthService(session=session)
    with pytest.raises(AuthenticationError):
        service.authenticate("admin", "wrong-password", client_key="127.0.0.1")
    repo = UserRepository(session)
    assert repo.count_users() == 0  # no accidental user creation
    assert repo.list_audit(action="auth.login")


def test_lockout_after_max_failures(session):
    settings = get_settings()
    repo = UserRepository(session)
    repo.create_user("mallory", hash_password("correct-horse-battery"))
    service = AuthService(session=session)
    for _ in range(settings.LOGIN_MAX_FAILURES):
        with pytest.raises(AuthenticationError):
            service.authenticate("mallory", "wrong")
    # Now even the correct password is refused while locked.
    with pytest.raises(AuthenticationError, match="locked"):
        service.authenticate("mallory", "correct-horse-battery")
    # Failure counter persisted in DB (not process memory).
    locked_user = repo.get_by_username("mallory")
    assert locked_user.locked_until is not None


def test_disabled_user_cannot_authenticate(session):
    repo = UserRepository(session)
    repo.create_user("nina", hash_password("correct-horse-battery"), roles=["viewer"])
    repo.set_active("nina", False)
    # Disabled/deleted accounts return the same generic message as bad
    # credentials so usernames cannot be enumerated from the login response.
    with pytest.raises(AuthenticationError, match="Invalid username or password"):
        AuthService(session=session).authenticate("nina", "correct-horse-battery")


def test_require_roles_allows_only_permitted(session, monkeypatch):
    from api.dependencies import require_roles

    repo = UserRepository(session)
    repo.create_user("olga", hash_password("correct-horse-battery"), roles=["viewer"])
    manager = SessionManager(secret="test-secret-key-for-sessions-min-32-chars")
    token = manager.create_session("olga", roles=["viewer"])

    dep = require_roles("admin", "auditor")

    class FakeRequest:
        headers = {"Authorization": f"Bearer {token}"}
        cookies = {}
        # _resolve_api_key caches its verdict on request.state. A real Starlette
        # request always has one; this stub did not, so the dependency raised
        # AttributeError before it ever reached the role check and the test
        # asserted 403 against the wrong exception.
        state = SimpleNamespace()

    with pytest.raises(HTTPException) as excinfo:
        dep(FakeRequest(), user="olga", db=session)
    assert excinfo.value.status_code == 403

    # An auditor token passes the same gate.
    repo.set_roles("olga", ["auditor"])
    token2 = manager.create_session("olga", roles=["auditor"])

    class FakeRequest2:
        headers = {"Authorization": f"Bearer {token2}"}
        cookies = {}
        state = SimpleNamespace()

    assert dep(FakeRequest2(), user="olga", db=session) == "olga"
