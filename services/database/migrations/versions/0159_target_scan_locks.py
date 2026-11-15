"""Target-scoped scan locks: prevent conflicting jobs on one target (§10).

Revision ID: 0159
Revises: 0158

Two workers scanning the same target duplicate findings and race on
shared state. This table is the coordination: one lock row per (tenant,
target), acquired by compare-and-set, stealable when the holder's lease
expired (a worker that died mid-scan must not wedge its target), released
after the run. A conflicting job is deferred — retryable, told who holds
the lock and until when — never silently dropped.

The tenant is part of the identity on purpose: two tenants scanning the
same target string are independent estates and never contend. RLS +
grants follow 0151/0152/0157's pattern: a new tenant table must not
start its life unprotected.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0159"
down_revision = "0158"
branch_labels = None
depends_on = None

TABLE = "target_scan_locks"


def upgrade() -> None:
    op.create_table(
        TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=True),
        sa.Column("target_key", sa.String(200), nullable=False),
        sa.Column("owner", sa.String(100), nullable=False),
        sa.Column("acquired_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("uq_target_scan_locks_tenant_target", TABLE,
                    ["tenant_id", "target_key"], unique=True)
    if op.get_bind().dialect.name == "postgresql":
        op.execute(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {TABLE} FORCE ROW LEVEL SECURITY")
        own = ("(tenant_id::text = cryptoscan_current_tenant() OR "
               "cryptoscan_current_tenant() = '*')")
        op.execute(f"CREATE POLICY tenant_isolation_select ON {TABLE} "
                   f"FOR SELECT USING {own}")
        op.execute(f"CREATE POLICY tenant_isolation_insert ON {TABLE} "
                   f"FOR INSERT WITH CHECK {own}")
        op.execute(f"CREATE POLICY tenant_isolation_update ON {TABLE} "
                   f"FOR UPDATE USING {own} WITH CHECK {own}")
        op.execute(f"CREATE POLICY tenant_isolation_delete ON {TABLE} "
                   f"FOR DELETE USING {own}")
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {TABLE} "
                   "TO cryptoscan_tenant, cryptoscan_platform")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation_select ON {TABLE}")
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation_insert ON {TABLE}")
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation_update ON {TABLE}")
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation_delete ON {TABLE}")
    op.drop_index("uq_target_scan_locks_tenant_target", table_name=TABLE)
    op.drop_table(TABLE)
