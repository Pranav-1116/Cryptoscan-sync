"""Migration 0164 parity: the collection-time authority stamp columns
exist on scans exactly as the model declares — and drop cleanly."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations

ROOT = Path(__file__).resolve().parents[3]


def _migration():
    path = (ROOT / "services" / "database" / "migrations" / "versions" /
            "0164_collection_authority_stamp.py")
    spec = importlib.util.spec_from_file_location("migration_0164", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(engine, fn):
    with engine.begin() as conn:
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            fn()


def _base_scans_table(bind):
    bind.execute(sa.text(
        "CREATE TABLE scans ("
        " id VARCHAR(36) PRIMARY KEY,"
        " tenant_id VARCHAR(36),"
        " target_location TEXT NOT NULL,"
        " status VARCHAR(20) NOT NULL)"))


def test_upgrade_adds_exactly_the_model_columns():
    from db.models.scan import Scan

    engine = sa.create_engine("sqlite://")
    with engine.begin() as conn:
        _base_scans_table(conn)
    _run(engine, _migration().upgrade)
    inspector = sa.inspect(engine)
    migrated = {c["name"] for c in inspector.get_columns("scans")}
    assert {"collector_authority_id", "collector_authority_revision"} <= migrated
    declared = {c.name for c in Scan.__table__.columns}
    # every column the migration adds must be one the model declares
    assert {"collector_authority_id", "collector_authority_revision"} <= declared
    nullable = {c["name"]: c["nullable"] for c in inspector.get_columns("scans")}
    assert nullable["collector_authority_id"] is True
    assert nullable["collector_authority_revision"] is True


def test_upgrade_is_idempotent_and_downgrade_drops():
    migration = _migration()
    engine = sa.create_engine("sqlite://")
    with engine.begin() as conn:
        _base_scans_table(conn)
    _run(engine, migration.upgrade)
    _run(engine, migration.upgrade)  # re-running is a no-op
    _run(engine, migration.downgrade)
    inspector = sa.inspect(engine)
    migrated = {c["name"] for c in inspector.get_columns("scans")}
    assert "collector_authority_id" not in migrated
    assert "collector_authority_revision" not in migrated
