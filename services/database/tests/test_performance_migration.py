"""Migration 0138 parity (docs/performance/01_PRODUCT_SPEC.md, §5).

Models without migrations are schemas production never receives — this
test keeps the performance tables and the performance models identical,
both up and down.
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
            "0138_performance_tables.py")
    spec = importlib.util.spec_from_file_location("migration_0138", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(engine, fn):
    with engine.begin() as conn:
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            fn()


def test_upgrade_creates_exactly_the_performance_tables_and_columns():
    from db.models.performance import (
        PerformanceCollectorHealth, PerformanceMetric,
        PerformanceMetricDefinition,
    )
    engine = sa.create_engine("sqlite://")
    _run(engine, _migration().upgrade)
    inspector = sa.inspect(engine)
    tables = {"performance_metrics", "performance_metric_definitions",
              "performance_collector_health"}
    assert tables <= set(inspector.get_table_names())
    for model in (PerformanceMetric, PerformanceMetricDefinition,
                  PerformanceCollectorHealth):
        migrated = {c["name"] for c in inspector.get_columns(model.__tablename__)}
        declared = {c.name for c in model.__table__.columns}
        assert migrated == declared, \
            f"{model.__tablename__}: migration and model disagree: " \
            f"only-migration {sorted(migrated - declared)}, " \
            f"only-model {sorted(declared - migrated)}"
    unique = {ix["name"]: ix for ix in
              inspector.get_indexes("performance_metrics")}
    assert unique["ix_performance_metrics_metric_id"]["unique"], \
        "metric identity is unique at the schema level — idempotent " \
        "ingestion is a schema fact, not just an API behaviour"


def test_downgrade_drops_the_tables():
    engine = sa.create_engine("sqlite://")
    module = _migration()
    _run(engine, module.upgrade)
    _run(engine, module.downgrade)
    inspector = sa.inspect(engine)
    remaining = {"performance_metrics", "performance_metric_definitions",
                 "performance_collector_health"}
    assert remaining & set(inspector.get_table_names()) == set()
