"""Migration 0137 parity (docs/cryptolog/01_PRODUCT_SPEC.md).

The migration creates exactly the tables and columns the models declare —
and drops them on downgrade. Models without migrations are schemas that
production never receives; this test keeps the two honest.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations

ROOT = Path(__file__).resolve().parents[3]


def _migration():
    path = (ROOT / "services" / "database" / "migrations" / "versions" /
            "0137_cryptolog_tables.py")
    spec = importlib.util.spec_from_file_location("migration_0137", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(engine, fn):
    with engine.begin() as conn:
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            fn()


def test_upgrade_creates_exactly_the_models_tables_and_columns():
    from db.models.cryptolog import (
        CryptoLogAlert, CryptoLogCheckpoint, CryptoLogCorrection, CryptoLogEvent,
    )
    engine = sa.create_engine("sqlite://")
    _run(engine, _migration().upgrade)
    inspector = sa.inspect(engine)
    tables = {"cryptolog_events", "cryptolog_event_corrections",
              "cryptolog_alerts", "cryptolog_checkpoints"}
    assert tables <= set(inspector.get_table_names())
    for model in (CryptoLogEvent, CryptoLogCorrection,
                  CryptoLogAlert, CryptoLogCheckpoint):
        migrated = {c["name"] for c in inspector.get_columns(model.__tablename__)}
        declared = {c.name for c in model.__table__.columns}
        assert migrated == declared, \
            f"{model.__tablename__}: migration and model disagree: " \
            f"only-migration {sorted(migrated - declared)}, " \
            f"only-model {sorted(declared - migrated)}"
    unique = {ix["name"]: ix for ix in
              inspector.get_indexes("cryptolog_events")}
    assert unique["ix_cryptolog_events_event_id"]["unique"], \
        "event identity is unique at the schema level"


def test_downgrade_drops_the_tables():
    engine = sa.create_engine("sqlite://")
    module = _migration()
    _run(engine, module.upgrade)
    _run(engine, module.downgrade)
    inspector = sa.inspect(engine)
    remaining = {"cryptolog_events", "cryptolog_event_corrections",
                 "cryptolog_alerts", "cryptolog_checkpoints"}
    assert remaining & set(inspector.get_table_names()) == set()
