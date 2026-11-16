"""Migration 0162 evidence: the indexes change the plan, not just the schema.

The 50k-asset scale receipt recorded two EXPLAIN seq scans with candidate
indexes named. This test replays exactly those two shapes on a seeded
``evidence_records`` table and pins the receipt's claim end to end:

* **before** the migration the planner seq-scans (and temp-b-trees the
  findings page ordering);
* **after** 0162 the planner searches ``ix_evidence_tenant_algorithm`` /
  ``ix_evidence_tenant_hardcoded_created`` and needs no sort.

The model/migration parity pin keeps the two declared names identical.
"""

from __future__ import annotations

import importlib.util
import sqlite3
from pathlib import Path

import sqlalchemy as sa

ROOT = Path(__file__).resolve().parents[3]

AGGREGATE_SQL = (
    "SELECT algorithm, COUNT(*) FROM evidence_records "
    "WHERE tenant_id = 'tenant-03' GROUP BY algorithm"
)
PAGE_SQL = (
    "SELECT * FROM evidence_records "
    "WHERE tenant_id = 'tenant-03' AND is_hardcoded_key = 1 "
    "AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 50"
)


def _migration():
    path = (ROOT / "services" / "database" / "migrations" / "versions" /
            "0162_evidence_query_indexes.py")
    spec = importlib.util.spec_from_file_location("migration_0162", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _seeded_engine():
    """Table as 0161 left it (old indexes only) + 8k rows across 10 tenants."""
    engine = sa.create_engine("sqlite://")
    with engine.begin() as conn:
        conn.execute(sa.text(
            "CREATE TABLE evidence_records ("
            " id INTEGER PRIMARY KEY,"
            " tenant_id VARCHAR(64) NOT NULL,"
            " scan_id VARCHAR(64),"
            " algorithm VARCHAR(80) NOT NULL,"
            " is_hardcoded_key BOOLEAN NOT NULL DEFAULT 0,"
            " compliance_status VARCHAR(40),"
            " chain_position INTEGER,"
            " created_at DATETIME,"
            " deleted_at DATETIME)"
        ))
        conn.execute(sa.text(
            "CREATE INDEX ix_evidence_scan_chain ON evidence_records"
            " (scan_id, chain_position)"))
        conn.execute(sa.text(
            "CREATE INDEX ix_evidence_scan_status ON evidence_records"
            " (scan_id, compliance_status)"))
        rows = []
        for i in range(8000):
            rows.append({
                "tenant": f"tenant-{i % 10:02d}",
                "algo": ("AES", "RSA", "SHA", "ECC")[i % 4],
                "hard": 1 if i % 7 == 0 else 0,
                "created": f"2026-{(i % 9) + 1:02d}-{(i % 27) + 1:02d}"
                          f" {i % 24:02d}:{i % 60:02d}:00",
            })
        conn.execute(sa.text(
            "INSERT INTO evidence_records"
            " (tenant_id, scan_id, algorithm, is_hardcoded_key,"
            "  compliance_status, chain_position, created_at, deleted_at)"
            " VALUES (:tenant, 's1', :algo, :hard, 'PASS', 1, :created, NULL)"),
            rows)
        conn.execute(sa.text("ANALYZE"))
    return engine


def _plan(conn, sql: str) -> str:
    result = conn.execute(
        sa.text(f"EXPLAIN QUERY PLAN {sql}")).fetchall()
    return " | ".join(str(row[-1]) for row in result)


def test_migration_indexes_declared_by_the_model():
    from db.models.evidence_record import EvidenceRecord

    migration = _migration()
    declared = {
        ix.name: tuple(col.name for col in ix.columns)
        for ix in EvidenceRecord.__table__.indexes
    }
    for name, cols in migration.INDEXES:
        assert name in declared, f"{name} missing from the model's declarations"
        assert declared[name] == tuple(cols), (
            f"{name}: model columns {declared[name]} != migration {tuple(cols)}")


def test_explain_plans_move_from_seq_scan_to_index_search():
    engine = _seeded_engine()
    with engine.begin() as conn:
        agg_before = _plan(conn, AGGREGATE_SQL)
        page_before = _plan(conn, PAGE_SQL)

    # Before: no usable index — the receipt's honest starting point.
    assert "SCAN evidence_records" in agg_before, agg_before
    assert "TEMP B-TREE" in page_before, page_before

    migration = _migration()
    with engine.begin() as conn:
        from alembic.migration import MigrationContext
        from alembic.operations import Operations
        mctx = MigrationContext.configure(conn)
        with Operations.context(mctx):
            migration.upgrade()
        conn.execute(sa.text("ANALYZE"))

    with engine.begin() as conn:
        agg_after = _plan(conn, AGGREGATE_SQL)
        page_after = _plan(conn, PAGE_SQL)
        index_names = {
            row[1] for row in conn.execute(sa.text(
                "SELECT * FROM sqlite_master WHERE type = 'index'"))
        }

    assert "ix_evidence_tenant_algorithm" in index_names
    assert "ix_evidence_tenant_hardcoded_created" in index_names
    # After: the aggregate is a covering index search on the tenant's slice.
    assert "ix_evidence_tenant_algorithm" in agg_after, agg_after
    assert "SCAN evidence_records" not in agg_after.replace(
        "SCAN evidence_records USING COVERING INDEX", ""), agg_after
    # After: the findings page is an index search with no sort step at all.
    assert "ix_evidence_tenant_hardcoded_created" in page_after, page_after
    assert "TEMP B-TREE" not in page_after, page_after
