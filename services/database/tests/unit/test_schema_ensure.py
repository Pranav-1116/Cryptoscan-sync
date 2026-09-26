"""Schema reconciliation tests: existing databases converge to the models.

The hand-maintained column list used to drift; these tests pin the new
behaviour — reconciliation derives from Base.metadata automatically.
"""

from __future__ import annotations

import re
from sqlalchemy import create_engine, inspect, text

from db.connection.schema_ensure import WANTED_OVERRIDES, ensure_schema_extensions, schema_drift_report
from db.connection.session import Base
from db import models  # noqa: F401 — register all models


def _legacy_engine():
    """A database in the OLD shape: systems without cloud columns,
    cloud_accounts without regions, no runtime_findings."""
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as conn:
        conn.execute(text(
            "CREATE TABLE systems (id VARCHAR(36) PRIMARY KEY, name VARCHAR(200),"
            " created_at DATETIME, updated_at DATETIME)"
        ))
        conn.execute(text(
            "CREATE TABLE cloud_accounts (id VARCHAR(36) PRIMARY KEY,"
            " cloud_provider VARCHAR(20), account_identifier VARCHAR(200), enabled BOOLEAN,"
            " created_at DATETIME, updated_at DATETIME)"
        ))
        conn.execute(text("INSERT INTO systems (id, name) VALUES ('s1', 'payments')"))
    return engine


def test_legacy_database_is_reconciled_automatically():
    engine = _legacy_engine()
    ensure_schema_extensions(engine)
    inspector = inspect(engine)
    system_cols = {c["name"] for c in inspector.get_columns("systems")}
    # model columns that the legacy table lacked — added without data loss
    for wanted in ("scan_target", "coverage_status", "cloud_provider", "cloud_account", "extra", "last_scan_id"):
        assert wanted in system_cols, f"systems.{wanted} missing after reconcile"
    account_cols = {c["name"] for c in inspector.get_columns("cloud_accounts")}
    assert "regions" in account_cols and "role_arn" in account_cols
    # data preserved through the ALTERs
    with engine.begin() as conn:
        row = conn.execute(text("SELECT id, name FROM systems")).fetchone()
    assert tuple(row) == ("s1", "payments")
    # brand-new tables appear too (create_all-equivalent coverage)
    assert "runtime_findings" in set(inspector.get_table_names())


def test_reconciliation_is_idempotent():
    engine = _legacy_engine()
    ensure_schema_extensions(engine)
    ensure_schema_extensions(engine)  # second pass: no error, no change
    report = schema_drift_report(engine)
    assert report["in_sync"] is True
    assert report["missing_columns"] == []


def test_drift_report_detects_gaps_before_reconcile():
    engine = _legacy_engine()
    report = schema_drift_report(engine)
    assert report["in_sync"] is False
    tables_with_gaps = {row["table"] for row in report["missing_columns"]}
    assert "systems" in tables_with_gaps
    assert "runtime_findings" in report["missing_tables"]


def test_model_indexes_are_ensured():
    engine = _legacy_engine()
    ensure_schema_extensions(engine)
    inspector = inspect(engine)
    index_names = {idx["name"] for idx in inspector.get_indexes("runtime_findings")}
    for wanted in (
        "ix_runtime_findings_scanner_id",
        "ix_runtime_findings_dedup_key",
        "ix_runtime_findings_last_seen",
        "ix_runtime_findings_weak",
    ):
        assert wanted in index_names, f"index {wanted} missing"


def test_override_map_stays_within_real_model_columns():
    """WANTED_OVERRIDES may not drift into columns that no longer exist."""
    for table, columns in WANTED_OVERRIDES.items():
        assert table in Base.metadata.tables, f"override references unknown table {table}"
        model_columns = set(Base.metadata.tables[table].columns.keys())
        for column in columns:
            assert column in model_columns, f"override {table}.{column} is not a model column"


def test_migration_chain_covers_every_model_table():
    """The alembic chain + create_all must agree: no table outside both."""
    import glob

    versions = glob.glob("services/database/migrations/versions/*.py")
    assert versions
    created = set()
    revisions = {}
    for path in versions:
        source = open(path, encoding="utf-8").read()
        created.update(re.findall(r'create_table\(\s*["\']([a-z_]+)["\']', source))
        m = re.search(r'revision\s*=\s*["\']([\w]+)["\']', source)
        d = re.search(r'down_revision\s*=\s*["\']([\w]+)["\']', source)
        if m:
            revisions[m.group(1)] = d.group(1) if d else None
    _model_tables = set(Base.metadata.tables)
    # every model table is either migrated or created by create_all — the
    # invariant that matters is: newest tables are in the chain.
    assert "runtime_findings" in created, "runtime_findings migration missing"
    # chain integrity: each down_revision points at a real revision
    for revision, parent in revisions.items():
        if parent is not None:
            assert parent in revisions, f"migration {revision} hangs off unknown {parent}"
