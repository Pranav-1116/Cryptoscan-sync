"""Production database startup must be migration-gated, never create-all gated."""

from __future__ import annotations

import os
from pathlib import Path
from tempfile import gettempdir

import pytest
from sqlalchemy import create_engine, inspect, text

from db.connection.schema_ensure import ensure_schema_extensions
from db.connection.session import init_db, migration_status


def test_production_database_without_alembic_version_fails_closed(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("DB_WAIT_SECONDS", "1")

    assert migration_status(engine)["status"] == "missing"
    with pytest.raises(RuntimeError, match="migrations"):
        init_db(engine)
    with pytest.raises(RuntimeError, match="Production schema changes"):
        ensure_schema_extensions(engine)

    # A production boot check must not leave a partially-created application
    # schema behind for a later process to mistake for a migrated database.
    assert not inspect(engine).has_table("alembic_version")
    assert not inspect(engine).has_table("users")


def _stamped_partial_sqlite(revision: str | None):
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"))
        if revision is not None:
            conn.execute(text("INSERT INTO alembic_version (version_num) VALUES (:revision)"), {"revision": revision})
        conn.execute(text("CREATE TABLE systems (id VARCHAR(36) PRIMARY KEY, name VARCHAR(200))"))
    return engine


@pytest.mark.parametrize("entrypoint", [init_db, ensure_schema_extensions])
@pytest.mark.parametrize("revision", ["0068", None], ids=["old-revision", "empty-version-table"])
def test_behind_dev_database_fails_before_any_schema_or_index_mutation(monkeypatch, entrypoint, revision):
    monkeypatch.setenv("ENVIRONMENT", "development")
    engine = _stamped_partial_sqlite(revision)
    assert migration_status(engine)["status"] == "behind"
    before = inspect(engine)
    tables = set(before.get_table_names())
    columns = [
        (col["name"], str(col["type"]), col["nullable"], col["primary_key"]) for col in before.get_columns("systems")
    ]
    indexes = before.get_indexes("systems")

    with pytest.raises(RuntimeError, match="alembic -c services/database/migrations/alembic.ini upgrade head"):
        entrypoint(engine)

    after = inspect(engine)
    assert set(after.get_table_names()) == tables
    assert [
        (col["name"], str(col["type"]), col["nullable"], col["primary_key"]) for col in after.get_columns("systems")
    ] == columns
    assert after.get_indexes("systems") == indexes
    assert not after.has_table("users")


@pytest.mark.parametrize("entrypoint", [init_db, ensure_schema_extensions])
def test_current_dev_database_is_not_reconciled_ahead_of_migrations(monkeypatch, entrypoint):
    monkeypatch.setenv("ENVIRONMENT", "development")
    engine = _stamped_partial_sqlite("0068")
    head = migration_status(engine)["heads"][0]
    with engine.begin() as conn:
        conn.execute(text("UPDATE alembic_version SET version_num = :head"), {"head": head})
    assert migration_status(engine)["status"] == "current"

    entrypoint(engine)

    after = inspect(engine)
    assert set(after.get_table_names()) == {"alembic_version", "systems"}
    assert {col["name"] for col in after.get_columns("systems")} == {"id", "name"}
    assert after.get_indexes("systems") == []


def test_unstamped_sqlite_dev_database_can_bootstrap(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    engine = create_engine("sqlite:///:memory:")
    assert migration_status(engine)["status"] == "missing"

    init_db(engine)

    assert inspect(engine).has_table("users")
    assert not inspect(engine).has_table("alembic_version")


def test_unreadable_migration_status_fails_before_bootstrap(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setattr(
        "db.connection.session.migration_status",
        lambda _engine: {"status": "error", "applied": [], "heads": []},
    )
    engine = create_engine("sqlite:///:memory:")
    with pytest.raises(RuntimeError, match="migration status is error"):
        init_db(engine)
    assert inspect(engine).get_table_names() == []


@pytest.mark.skipif(os.environ.get("CRYPTOSCAN_DISPOSABLE_PG") != "1", reason="requires pg_virtualenv")
def test_disposable_postgres_requires_migrations_and_never_reconciles(monkeypatch):
    """Run with pg_virtualenv and CRYPTOSCAN_DISPOSABLE_PG=1, never on an existing cluster."""
    monkeypatch.setenv("ENVIRONMENT", "development")
    engine = create_engine("postgresql+psycopg2:///postgres")
    # Refuse writes unless the server itself confirms a disposable cluster.
    with engine.connect() as conn:
        data_directory = Path(conn.execute(text("SHOW data_directory")).scalar_one())
    assert data_directory.is_relative_to(Path(gettempdir()))
    assert any(part.startswith("pg_virtualenv.") for part in data_directory.parts)
    assert migration_status(engine)["status"] == "missing"

    with pytest.raises(RuntimeError, match="alembic -c services/database/migrations/alembic.ini upgrade head"):
        init_db(engine)
    assert not inspect(engine).has_table("users")

    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"))
        conn.execute(text("INSERT INTO alembic_version (version_num) VALUES ('0068')"))
        conn.execute(text("CREATE TABLE systems (id VARCHAR(36) PRIMARY KEY, name VARCHAR(200))"))
    assert migration_status(engine)["status"] == "behind"
    with pytest.raises(RuntimeError, match="alembic -c services/database/migrations/alembic.ini upgrade head"):
        init_db(engine)
    assert set(inspect(engine).get_table_names()) == {"alembic_version", "systems"}
    assert {col["name"] for col in inspect(engine).get_columns("systems")} == {"id", "name"}
    assert inspect(engine).get_indexes("systems") == []

    head = migration_status(engine)["heads"][0]
    with engine.begin() as conn:
        conn.execute(text("UPDATE alembic_version SET version_num = :head"), {"head": head})
    init_db(engine)
    assert set(inspect(engine).get_table_names()) == {"alembic_version", "systems"}
    assert {col["name"] for col in inspect(engine).get_columns("systems")} == {"id", "name"}
    assert inspect(engine).get_indexes("systems") == []
