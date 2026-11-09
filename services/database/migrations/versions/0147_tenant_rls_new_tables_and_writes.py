"""Extend forced tenant RLS to newer tables and separate read/write policy.

Revision ID: 0147
Revises: 0146

0132 protected the tables existing at that revision. Later migrations added
new tenant tables without policies. The old all-command policy also allowed
scoped roles to write or delete NULL (platform-estate) rows. Keep platform
rows readable to tenants, but only the explicit platform scope may mutate
those rows; a tenant may write only its own rows.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0147"
down_revision = "0146"
branch_labels = None
depends_on = None


_POLICIES = (
    "tenant_isolation",
    "tenant_isolation_select",
    "tenant_isolation_insert",
    "tenant_isolation_update",
    "tenant_isolation_delete",
)


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "postgresql":
        return  # SQLite has no RLS; the ORM tenant guard remains required.

    quote = connection.dialect.identifier_preparer.quote
    tables = connection.execute(sa.text(
        "SELECT table_name FROM information_schema.columns "
        "WHERE table_schema = current_schema() AND column_name = 'tenant_id' "
        "AND table_name NOT LIKE 'pg_%' ORDER BY table_name"
    )).scalars().all()
    for name in tables:
        table = quote(name)
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        for policy in _POLICIES:
            op.execute(f"DROP POLICY IF EXISTS {policy} ON {table}")
        op.execute(f"""
            CREATE POLICY tenant_isolation_select ON {table} FOR SELECT
            USING (tenant_id IS NULL
                   OR tenant_id::text = cryptoscan_current_tenant()
                   OR cryptoscan_current_tenant() = '*')
        """)
        own_or_platform = (
            "(tenant_id::text = cryptoscan_current_tenant() "
            "OR cryptoscan_current_tenant() = '*')"
        )
        op.execute(f"CREATE POLICY tenant_isolation_insert ON {table} "
                   f"FOR INSERT WITH CHECK {own_or_platform}")
        op.execute(f"CREATE POLICY tenant_isolation_update ON {table} "
                   f"FOR UPDATE USING {own_or_platform} "
                   f"WITH CHECK {own_or_platform}")
        op.execute(f"CREATE POLICY tenant_isolation_delete ON {table} "
                   f"FOR DELETE USING {own_or_platform}")
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} "
                   "TO cryptoscan_tenant, cryptoscan_platform")


def downgrade() -> None:
    # A downgrade may lower the schema revision, but never remove tenant
    # isolation or restore the 0132 policy that allowed writes to shared rows.
    # Re-upgrading reapplies the same policies idempotently.
    pass
