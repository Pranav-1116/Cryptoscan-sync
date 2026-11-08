"""Migration 0139 parity (docs/performance/01_PRODUCT_SPEC.md, §5).

The eight engine tables the model layer declares must be exactly what
the migration creates — and the downgrade drops them clean.
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
            "0139_performance_engine_tables.py")
    spec = importlib.util.spec_from_file_location("migration_0139", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(engine, fn):
    with engine.begin() as conn:
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            fn()


def test_upgrade_creates_exactly_the_engine_tables_and_columns():
    from db.models.performance import (
        PerformanceAggregate, PerformanceAlert, PerformanceAsset,
        PerformanceBaseline, PerformanceBenchmarkRun,
        PerformanceCapacityForecast, PerformanceIncident,
        PerformanceSloPolicy,
    )
    engine = sa.create_engine("sqlite://")
    _run(engine, _migration().upgrade)
    inspector = sa.inspect(engine)
    models = (PerformanceAsset, PerformanceAggregate, PerformanceBaseline,
              PerformanceAlert, PerformanceIncident, PerformanceSloPolicy,
              PerformanceCapacityForecast, PerformanceBenchmarkRun)
    for model in models:
        migrated = {c["name"] for c in inspector.get_columns(model.__tablename__)}
        declared = {c.name for c in model.__table__.columns}
        assert migrated == declared, \
            f"{model.__tablename__}: only-migration {sorted(migrated - declared)}, " \
            f"only-model {sorted(declared - migrated)}"
    unique = {ix["name"]: ix for ix in
              inspector.get_indexes("performance_benchmark_runs")}
    assert unique["ix_performance_benchmark_runs_run_id"]["unique"], \
        "a benchmark run identity is unique at the schema level"


def test_downgrade_drops_the_tables():
    engine = sa.create_engine("sqlite://")
    module = _migration()
    _run(engine, module.upgrade)
    _run(engine, module.downgrade)
    inspector = sa.inspect(engine)
    names = {"performance_assets", "performance_aggregates",
             "performance_baselines", "performance_alerts",
             "performance_incidents", "performance_slo_policies",
             "performance_capacity_forecasts", "performance_benchmark_runs"}
    assert names & set(inspector.get_table_names()) == set()
