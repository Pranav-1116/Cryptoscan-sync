"""Reconcile migrated schemas with the ORM models.

A column-level diff (create_all metadata vs alembic head) showed ten tables
where old migrations and the models had drifted apart: legacy primary-key
names (scan_id/evidence_id/job_id/... vs the models' ``id``), missing
``created_at``/``updated_at`` timestamps, and ``systems``/``scans``/``scan_jobs``
columns the models rely on. Every ORM query against a fully-migrated database
hit "no such column" — tests never saw it because dev/test build schemas with
``create_all``. This migration brings the migrated schema to exactly what the
models declare, so both paths produce the same database.

Revision ID: 0029
Revises: 0028
Create Date: 2026-08-29
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = "0029"
down_revision = "0028"
branch_labels = None
depends_on = None

# table -> (old PK column to rename to "id", columns to add)
RENAMES = {
    "scans": "scan_id",
    "evidence_records": "evidence_id",
    "scan_jobs": "job_id",
    "baselines": "baseline_id",
    "drift_events": "drift_id",
    "repo_configurations": "config_id",
    "verification_log": "verification_id",
}

ADDITIONS = {
    "baselines": [
        ("updated_at", sa.DateTime(timezone=True), False),
    ],
    "drift_events": [
        ("created_at", sa.DateTime(timezone=True), False),
        ("updated_at", sa.DateTime(timezone=True), False),
    ],
    "gate_evaluations": [
        ("updated_at", sa.DateTime(timezone=True), False),
    ],
    "mfa_recovery_codes": [
        ("updated_at", sa.DateTime(timezone=True), False),
    ],
    "scan_jobs": [
        ("progress", sa.JSON(), True),
        ("system_id", sa.String(36), True),
        ("updated_at", sa.DateTime(timezone=True), False),
    ],
    "scans": [
        ("error_message", sa.Text(), True),
        ("updated_at", sa.DateTime(timezone=True), False),
    ],
    "verification_log": [
        ("updated_at", sa.DateTime(timezone=True), False),
    ],
    "systems": [
        ("scan_target", sa.Text(), True),
        ("scan_branch", sa.String(200), True),
        ("last_scan_id", sa.String(36), True),
        ("last_scanned_at", sa.DateTime(timezone=True), True),
        ("coverage_status", sa.String(20), True),
        ("business_unit", sa.String(100), True),
        ("criticality", sa.String(20), True),
        ("cloud_provider", sa.String(20), True),
        ("cloud_account", sa.String(200), True),
    ],
}

_TS_DEFAULT = sa.text("CURRENT_TIMESTAMP")


def _existing_columns(table: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    return {column["name"] for column in inspector.get_columns(table)}


def upgrade() -> None:
    for table, old_pk in RENAMES.items():
        if old_pk in _existing_columns(table):
            op.execute(f'ALTER TABLE {table} RENAME COLUMN "{old_pk}" TO "id"')
    for table, columns in ADDITIONS.items():
        existing = _existing_columns(table)
        for name, type_, nullable in columns:
            if name in existing:
                continue
            if nullable:
                op.add_column(table, sa.Column(name, type_, nullable=True))
            else:  # NOT NULL via server default (backfills existing rows; sqlite-safe)
                op.add_column(
                    table, sa.Column(name, type_, nullable=False, server_default=_TS_DEFAULT)
                )


def downgrade() -> None:
    for table, columns in ADDITIONS.items():
        existing = _existing_columns(table)
        for name, _type_, _nullable in reversed(columns):
            if name in existing:
                op.drop_column(table, name)
    for table, old_pk in RENAMES.items():
        if "id" in _existing_columns(table):
            op.execute(f'ALTER TABLE {table} RENAME COLUMN "id" TO "{old_pk}"')
