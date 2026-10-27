"""Users/sessions/audit repository tests (SQLite)."""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine

from db.connection.session import Base, SessionLocal, configure_session
from db.repositories.user_repository import UserRepository


def _utcnow():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).replace(tzinfo=None)
from api.security.passwords import hash_password


@pytest.fixture()
def session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    configure_session(engine)
    s = SessionLocal()
    yield s
    s.close()


def test_create_user_defaults_to_viewer(session):
    repo = UserRepository(session)
    user = repo.create_user("alice", hash_password("supersecret12"))
    assert user.username == "alice"
    assert user.role_list == ["viewer"]
    assert user.is_active is True


def test_create_user_rejects_invalid_roles(session):
    repo = UserRepository(session)
    user = repo.create_user("bob", hash_password("supersecret12"), roles=["admin", "hacker"])
    assert user.role_list == ["admin"]


def test_lockout_persists_across_failures(session):
    repo = UserRepository(session)
    repo.create_user("carol", hash_password("supersecret12"))
    for _ in range(3):
        repo.record_failure("carol", max_failures=3, lockout_seconds=600)
    user = repo.get_by_username("carol")
    assert user.failed_attempts == 0  # reset after lock applied
    assert user.locked_until is not None and user.locked_until > _utcnow()
    # Still locked on next attempt within the window
    assert repo.get_by_username("carol").locked_until > _utcnow()


def test_lockout_expires(session):
    repo = UserRepository(session)
    user = repo.create_user("dave", hash_password("supersecret12"))
    # Simulate an expired lock
    user.locked_until = datetime.now(timezone.utc) - timedelta(seconds=1)
    session.flush()
    fresh = repo.get_by_username("dave")
    assert fresh.locked_until <= datetime.now(timezone.utc)


def test_session_create_revoke(session):
    repo = UserRepository(session)
    repo.create_user("erin", hash_password("supersecret12"))
    repo.create_session("token-abc", "erin", datetime.now(timezone.utc) + timedelta(hours=1))
    row = repo.get_session("token-abc")
    assert row is not None and row.revoked_at is None
    assert repo.revoke_session("token-abc") is True
    assert repo.get_session("token-abc").revoked_at is not None
    assert repo.revoke_session("never-issued") is False


def test_revoke_all_sessions(session):
    repo = UserRepository(session)
    repo.create_user("frank", hash_password("supersecret12"))
    exp = datetime.now(timezone.utc) + timedelta(hours=1)
    for t in ("t1", "t2", "t3"):
        repo.create_session(t, "frank", exp)
    assert repo.revoke_all_sessions("frank") == 3
    assert repo.revoke_all_sessions("frank") == 0


def test_audit_roundtrip(session):
    repo = UserRepository(session)
    repo.audit("admin", "baseline.approve", target_type="scan", target_id="s-1", detail={"env": "prod"})
    repo.audit("admin", "auth.login", outcome="FAILURE", detail="bad password")
    rows = repo.list_audit(action="auth.login")
    assert len(rows) == 1 and rows[0].outcome == "FAILURE"
    rows = repo.list_audit(page_size=10)
    assert len(rows) == 2
