"""Scope snapshots: named revisions of the authorized scope (scope diff).

Revision ID: 0151
Revises: 0150
"""

import sqlalchemy as sa
from alembic import op

revision = "0151"
down_revision = "0150"
branch_labels = None
depends_on = None

TABLE = "scope_snapshots"


def upgrade() -> None:
    op.create_table(
        TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("label", sa.String(120)),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("entries", sa.JSON(), nullable=False),
        sa.Column("envelope", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(100)),
    )
    op.create_index("ix_scope_snapshots_tenant", TABLE, ["tenant_id"])
    op.create_index("ix_scope_snapshots_org", TABLE, ["org_id"])
    op.create_index("ix_scope_snapshots_hash", TABLE, ["content_hash"])
    if op.get_bind().dialect.name == "postgresql":
        # 0147 applies policies only to tables that existed at its revision.
        # A new tenant table must not start its life unprotected in production.
        op.execute(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {TABLE} FORCE ROW LEVEL SECURITY")
        own = "(tenant_id::text = cryptoscan_current_tenant() OR cryptoscan_current_tenant() = '*')"
        op.execute(f"CREATE POLICY tenant_isolation_select ON {TABLE} FOR SELECT "
                   "USING (tenant_id IS NULL OR tenant_id::text = cryptoscan_current_tenant() "
                   "OR cryptoscan_current_tenant() = '*')")
        op.execute(f"CREATE POLICY tenant_isolation_insert ON {TABLE} FOR INSERT "
                   f"WITH CHECK {own}")
        op.execute(f"CREATE POLICY tenant_isolation_update ON {TABLE} FOR UPDATE "
                   f"USING {own} WITH CHECK {own}")
        op.execute(f"CREATE POLICY tenant_isolation_delete ON {TABLE} FOR DELETE "
                   f"USING {own}")
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {TABLE} "
                   "TO cryptoscan_tenant, cryptoscan_platform")


def downgrade() -> None:
    if op.get_bind().execute(sa.text(
            f"SELECT count(*) FROM {TABLE}")).scalar():
        raise RuntimeError("downgrade blocked: retained scope snapshots would be deleted")
    if op.get_bind().dialect.name == "postgresql":
        for name in ("tenant_isolation_select", "tenant_isolation_insert",
                     "tenant_isolation_update", "tenant_isolation_delete"):
            op.execute(f"DROP POLICY {name} ON {TABLE}")
        op.execute(f"ALTER TABLE {TABLE} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {TABLE} DISABLE ROW LEVEL SECURITY")
    op.drop_index("ix_scope_snapshots_hash", table_name=TABLE)
    op.drop_index("ix_scope_snapshots_org", table_name=TABLE)
    op.drop_index("ix_scope_snapshots_tenant", table_name=TABLE)
    op.drop_table(TABLE)
