"""Enforce the uniqueness the models have always declared.

Revision ID: 0153
Revises: 0152

Migration 0078 documented the class and promised its parity test: indexes and
constraints the ORM models declare are created by ``Base.metadata.create_all``
(tests, SQLite installs) but were never created by the migration chain — so
every alembic-migrated PostgreSQL deployment silently ran without them. The
parity test (``test_model_migration_index_parity``) found the four remaining
gaps, all uniqueness the models PROMISE:

    business_owners.email                       one owner per email
    vendors.name                                one vendor per name
    system_vendors (system_id, vendor_id)       uq_system_vendor
    system_business_process_map (system_id, process_id)   uq_system_process

A missing unique constraint is not a slow query — it is duplicate business
data the model says cannot exist. This migration refuses to run on a database
that already holds such duplicates: the operator resolves the data, and no
migration ever deletes business rows on its own (0107's rule).

Transactional DDL with a bounded lock wait (0107's discipline); the downgrade
drops only enforcement and deletes nothing.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0153"
down_revision = "0152"
branch_labels = None
depends_on = None

# (table, name, columns) — names match the models' declarations where the
# models name their constraint; column-unique=True entries follow the
# repo's uq_<table>_<column> convention.
UNIQUENESS = [
    ("business_owners", "uq_business_owners_email", ["email"]),
    ("vendors", "uq_vendors_name", ["name"]),
    ("system_vendors", "uq_system_vendor", ["system_id", "vendor_id"]),
    ("system_business_process_map", "uq_system_process",
     ["system_id", "process_id"]),
]


def _lock_timeout() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("SET LOCAL lock_timeout = '5s'")


def upgrade() -> None:
    _lock_timeout()
    for table, name, columns in UNIQUENESS:
        cols = ", ".join(columns)
        # NULLs never collide under a unique index, so they are not duplicates.
        not_null = " AND ".join(f"{c} IS NOT NULL" for c in columns)
        duplicate = op.get_bind().execute(sa.text(
            f"SELECT {cols} FROM {table} WHERE {not_null} "
            f"GROUP BY {cols} HAVING count(*) > 1 LIMIT 1")).first()
        if duplicate is not None:
            raise RuntimeError(
                f"{table} already holds duplicate ({cols}) values — resolve "
                "the data before enforcing the uniqueness the model declares; "
                "this migration never deletes business rows")
        op.create_index(name, table, columns, unique=True)


def downgrade() -> None:
    _lock_timeout()
    # Dropping enforcement deletes nothing; the pre-upgrade schema returns.
    for table, name, _columns in reversed(UNIQUENESS):
        op.drop_index(name, table_name=table)
