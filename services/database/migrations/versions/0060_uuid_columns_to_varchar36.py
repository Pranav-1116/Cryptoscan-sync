"""Align legacy UUID columns with the ORM's String(36) ids.

Migrations 0001–0009 created the first tables with ``postgresql.UUID`` primary
and foreign keys. Every ORM model declares ``String(36)`` (``BaseModel.id``),
and every later table was created that way. 0029 renamed the columns to ``id``
but left the type — so on a *migrated* PostgreSQL database, 15 columns come
back from the driver as ``uuid.UUID`` objects while the code expects strings.

Observed on the first real Postgres staging run (2026-09-23): every scan failed
at the policy stage with ``Object of type UUID is not JSON serializable``, and
0011 could not even be applied to a fresh database because its FK typed
``VARCHAR`` against a ``UUID`` target. Dev and tests never saw it because they
build the schema with ``create_all`` from the models.

This migration converts those columns to ``VARCHAR(36)`` in place. Values are
the canonical hyphenated text form, which is what the application already
writes elsewhere, so nothing is re-keyed. Foreign keys are dropped and
recreated around the type change (PostgreSQL will not alter a referenced
column's type while the constraint exists). SQLite has no column types to
change and is a no-op.

Revision ID: 0060
Revises: 0059
Create Date: 2026-09-23
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0060"
down_revision = "0059"
branch_labels = None
depends_on = None

#: table -> columns that must be VARCHAR(36) to match the ORM
TARGETS: dict[str, tuple[str, ...]] = {
    "scans": ("id",),
    "evidence_records": ("id", "scan_id"),
    "verification_log": ("id", "scan_id"),
    "baselines": ("id", "approved_scan_id"),
    "drift_events": ("id", "baseline_id", "current_scan_id"),
    "scan_jobs": ("id", "scan_id"),
    "repo_configurations": ("id", "baseline_scan_id"),
    "crypto_asset_evidence": ("evidence_id",),
}


def _is_postgres() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def _uuid_columns() -> list[tuple[str, str]]:
    """(table, column) pairs from TARGETS that are still typed uuid."""
    inspector = sa.inspect(op.get_bind())
    existing = set(inspector.get_table_names())
    out: list[tuple[str, str]] = []
    for table, columns in TARGETS.items():
        if table not in existing:
            continue
        types = {c["name"]: str(c["type"]).upper() for c in inspector.get_columns(table)}
        for column in columns:
            if column in types and "UUID" in types[column]:
                out.append((table, column))
    return out


def _foreign_keys_touching(pairs: set[tuple[str, str]]) -> list[dict]:
    """Every FK whose source *or* target column is one being retyped."""
    inspector = sa.inspect(op.get_bind())
    found: list[dict] = []
    for table in inspector.get_table_names():
        for fk in inspector.get_foreign_keys(table):
            src = {(table, c) for c in fk["constrained_columns"]}
            dst = {(fk["referred_table"], c) for c in fk["referred_columns"]}
            if (src | dst) & pairs:
                found.append({"table": table, **fk})
    return found


def upgrade() -> None:
    if not _is_postgres():
        return
    pairs = _uuid_columns()
    if not pairs:
        return
    pair_set = set(pairs)
    fks = _foreign_keys_touching(pair_set)
    for fk in fks:
        op.drop_constraint(fk["name"], fk["table"], type_="foreignkey")
    for table, column in pairs:
        op.execute(
            f'ALTER TABLE "{table}" ALTER COLUMN "{column}" '
            f'TYPE VARCHAR(36) USING "{column}"::text'
        )
    for fk in fks:
        op.create_foreign_key(
            fk["name"], fk["table"], fk["referred_table"],
            fk["constrained_columns"], fk["referred_columns"],
            ondelete=(fk.get("options") or {}).get("ondelete"),
            onupdate=(fk.get("options") or {}).get("onupdate"),
        )


def downgrade() -> None:
    """Back to uuid. Only safe if every value is a well-formed UUID (they are:
    the application writes ``str(uuid.uuid4())``)."""
    if not _is_postgres():
        return
    inspector = sa.inspect(op.get_bind())
    existing = set(inspector.get_table_names())
    pairs = [(t, c) for t, cols in TARGETS.items() if t in existing for c in cols
             if c in {col["name"] for col in inspector.get_columns(t)}]
    fks = _foreign_keys_touching(set(pairs))
    for fk in fks:
        op.drop_constraint(fk["name"], fk["table"], type_="foreignkey")
    for table, column in pairs:
        op.execute(f'ALTER TABLE "{table}" ALTER COLUMN "{column}" TYPE UUID USING "{column}"::uuid')
    for fk in fks:
        op.create_foreign_key(
            fk["name"], fk["table"], fk["referred_table"],
            fk["constrained_columns"], fk["referred_columns"],
            ondelete=(fk.get("options") or {}).get("ondelete"),
            onupdate=(fk.get("options") or {}).get("onupdate"),
        )
