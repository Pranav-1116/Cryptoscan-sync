"""Production database startup must be migration-gated, never create-all gated."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, inspect

from db.connection.session import init_db, migration_status


def test_production_database_without_alembic_version_fails_closed(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("DB_WAIT_SECONDS", "1")

    assert migration_status(engine)["status"] == "missing"
    with pytest.raises(RuntimeError, match="migrations"):
        init_db(engine)

    # A production boot check must not leave a partially-created application
    # schema behind for a later process to mistake for a migrated database.
    assert not inspect(engine).has_table("alembic_version")
    assert not inspect(engine).has_table("users")
