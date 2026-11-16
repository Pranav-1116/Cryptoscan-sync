"""Security bookkeeping that survives a restart (migration 0163).

Two monitors were process-local lists: the suspicious-access window
(``auth_monitor``) and the vault staleness watch (``RESOLUTION_LOG``).
A restart erased both — a probing attacker could clear their flag by
waiting for a deploy, and ``held`` credential ages restarted at zero.
These tests pin the durable side: hydrate rebuilds the exact state, the
fast path stays in-memory, and a database that is down loses
bookkeeping, never behavior.
"""

from __future__ import annotations

import time

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


@pytest.fixture(autouse=True)
def _clean_monitors():
    from api.security import auth_monitor, vault

    auth_monitor._FAILURES.clear()
    vault.RESOLUTION_LOG.records.clear()
    yield
    auth_monitor._FAILURES.clear()
    vault.RESOLUTION_LOG.records.clear()


@pytest.fixture()
def db():
    import db.models  # noqa: F401 - register every model on Base
    from db.connection.session import Base

    engine = sa.create_engine(
        "sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


class TestTheSuspiciousWindowSurvivesARestart:
    def test_five_failures_across_a_restart_are_still_suspicious(self, db):
        from api.security import auth_monitor, security_state_store

        auth_monitor._FAILURES.clear()
        now = time.time()
        for i in range(5):
            stamp = now - 60 + i
            auth_monitor.record_failure("alice", "203.0.113.9", now=stamp)
            security_state_store.persist_auth_failure(
                "alice", "203.0.113.9", occurred_at=stamp, db=db)

        # the deploy: the process-local window is gone
        auth_monitor._FAILURES.clear()
        assert auth_monitor.suspicious(now=now)["suspicious_keys"] == []

        restored = security_state_store.hydrate_auth_monitor(db=db, now=now)
        assert restored == 5
        surface = auth_monitor.suspicious(now=now)
        assert surface["suspicious"] is True
        assert [(k["user"], k["source"]) for k in surface["suspicious_keys"]] == [
            ("alice", "203.0.113.9")]
        assert surface["total_failures_in_window"] == 5

    def test_hydration_restores_the_window_not_the_forensics(self, db):
        from api.security import auth_monitor, security_state_store

        auth_monitor._FAILURES.clear()
        now = time.time()
        # 3 stamps outside the 300s verdict window, 3 inside
        for i in range(3):
            security_state_store.persist_auth_failure(
                "bob", "198.51.100.4", occurred_at=now - 400 + i, db=db)
            security_state_store.persist_auth_failure(
                "bob", "198.51.100.4", occurred_at=now - 60 + i, db=db)

        restored = security_state_store.hydrate_auth_monitor(db=db, now=now)
        assert restored == 3
        state = auth_monitor.suspicious(now=now)
        assert state["total_failures_in_window"] == 3
        # 3 < threshold 5 — history restored, verdict honest
        assert state["suspicious_keys"] == []

    def test_prune_forgets_the_old_stamps_eventually(self, db):
        from api.security import security_state_store

        now = time.time()
        security_state_store.persist_auth_failure(
            "old", "192.0.2.1", occurred_at=now - 3 * 86400, db=db)
        security_state_store.persist_auth_failure(
            "old", "192.0.2.1", occurred_at=now - 10, db=db)
        security_state_store.hydrate_auth_monitor(db=db, now=now)
        from db.models.security_state import SecurityAuthEvent

        remaining = db.query(SecurityAuthEvent).all()
        assert [row.occurred_at for row in remaining] == [now - 10]

    def test_a_database_that_is_down_loses_bookkeeping_not_behavior(self, db):
        from api.security import auth_monitor, security_state_store

        class DownDB:
            def add(self, _row):
                raise RuntimeError("database is down")

        assert security_state_store.persist_auth_failure(
            "carol", "203.0.113.7", db=DownDB()) is False
        state = auth_monitor.record_failure("carol", "203.0.113.7")
        assert state["window_failures"] == 1  # the fast path never depends on it


class TestTheStalenessWatchSurvivesARestart:
    @pytest.fixture(autouse=True)
    def _route_persistence(self, db, monkeypatch):
        """The in-memory log persists through security_state_store — route
        that write at the test database (production routes it at
        SessionLocal the same way)."""
        from api.security import security_state_store, vault

        real = security_state_store.persist_resolution

        def _routed(provider, reference, outcome, *, kind="probe",
                    resolved_at=None, **_ignored):
            return real(provider, reference, outcome, kind=kind,
                        resolved_at=resolved_at, db=db)

        monkeypatch.setattr(security_state_store, "persist_resolution", _routed)
        vault.RESOLUTION_LOG.records.clear()

    def test_held_ages_survive_the_deploy(self, db):
        from api.security import security_state_store, vault

        vault.RESOLUTION_LOG.add_record(vault.ResolutionRecord(
            provider="env", reference="env:DB_URL", resolved_at="2026-09-01T00:00:00+00:00",
            outcome="OK", kind="held"))
        # the deploy: the process-local log is gone
        vault.RESOLUTION_LOG.records.clear()
        assert vault.RESOLUTION_LOG.last_ok("env:DB_URL", kind="held") is None

        restored = security_state_store.hydrate_resolution_log(db=db)
        assert restored == 1
        assert vault.RESOLUTION_LOG.last_ok(
            "env:DB_URL", kind="held") == "2026-09-01T00:00:00+00:00"

    def test_add_persists_and_a_broken_database_never_loses_the_probe(self, db):
        from api.security import security_state_store, vault

        vault.RESOLUTION_LOG.add_record(vault.ResolutionRecord(
            provider="file", reference="file:/run/secret", resolved_at="2026-10-01T00:00:00+00:00",
            outcome="FAILED", kind="probe"))
        from db.models.security_state import VaultResolutionRecord

        stored = db.query(VaultResolutionRecord).all()
        assert len(stored) == 1 and stored[0].outcome == "FAILED"

        # broken durable side: the observation stays in memory regardless
        def _down(*_args, **_kwargs):
            raise RuntimeError("down")

        monkeyed = security_state_store.persist_resolution
        security_state_store.persist_resolution = _down
        try:
            vault.RESOLUTION_LOG.add("env", "env:X", "OK")
        finally:
            security_state_store.persist_resolution = monkeyed
        # the FAILED observation + the one the broken durable side dropped
        assert len(vault.RESOLUTION_LOG.records) == 2
        vault.RESOLUTION_LOG.records.clear()
