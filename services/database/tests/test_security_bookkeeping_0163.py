"""Migration 0163 parity: the durable security-bookkeeping tables are
exactly what the models declare — and they downgrade cleanly."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations

ROOT = Path(__file__).resolve().parents[3]


def _migration():
    path = (ROOT / "services" / "database" / "migrations" / "versions" /
            "0163_security_bookkeeping_durability.py")
    spec = importlib.util.spec_from_file_location("migration_0163", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(engine, fn):
    with engine.begin() as conn:
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            fn()


def test_upgrade_creates_exactly_the_models_tables_and_columns():
    from db.models.security_state import SecurityAuthEvent, VaultResolutionRecord

    engine = sa.create_engine("sqlite://")
    _run(engine, _migration().upgrade)
    inspector = sa.inspect(engine)
    assert {"security_auth_events", "vault_resolution_records"} <= set(
        inspector.get_table_names())
    for model in (SecurityAuthEvent, VaultResolutionRecord):
        migrated = {c["name"] for c in inspector.get_columns(model.__tablename__)}
        declared = {c.name for c in model.__table__.columns}
        assert migrated == declared, (
            f"{model.__tablename__}: only-migration {sorted(migrated - declared)}, "
            f"only-model {sorted(declared - migrated)}")
        migrated_ix = {ix["name"] for ix in inspector.get_indexes(model.__tablename__)}
        declared_ix = {ix.name for ix in model.__table__.indexes}
        assert declared_ix <= migrated_ix


def test_upgrade_is_idempotent_and_downgrade_drops():
    migration = _migration()
    engine = sa.create_engine("sqlite://")
    _run(engine, migration.upgrade)
    _run(engine, migration.upgrade)  # re-running is a no-op
    _run(engine, migration.downgrade)
    inspector = sa.inspect(engine)
    assert "security_auth_events" not in inspector.get_table_names()
    assert "vault_resolution_records" not in inspector.get_table_names()
