"""Bank-signed Performance capture receipts without raw exporter bytes.

Revision ID: 0150
Revises: 0149
"""

import sqlalchemy as sa
from alembic import op

revision = "0150"
down_revision = "0149"
branch_labels = None
depends_on = None

TABLE = "performance_capture_receipts"


def upgrade() -> None:
    op.create_table(
        TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=True),
        sa.Column("receipt_id", sa.String(64), nullable=False),
        sa.Column("asset_ref", sa.String(120), nullable=False),
        sa.Column("source_id", sa.String(120), nullable=False),
        sa.Column("source_type", sa.String(32), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("previous_observed_at", sa.DateTime(timezone=True)),
        sa.Column("payload_sha256", sa.String(64), nullable=False),
        sa.Column("previous_sha256", sa.String(64)),
        sa.Column("authorization_ref", sa.String(120), nullable=False),
        sa.Column("provenance_state", sa.String(40), nullable=False),
        sa.Column("key_id", sa.String(120)),
        sa.Column("issuer", sa.String(120)),
        sa.Column("signature", sa.String(128)),
        sa.Column("accepted_count", sa.Integer(), nullable=False),
        sa.Column("duplicate_count", sa.Integer(), nullable=False),
        sa.Column("rejected_count", sa.Integer(), nullable=False),
    )
    op.create_index("uq_performance_capture_tenant_receipt", TABLE,
                    ["tenant_id", "receipt_id"], unique=True)
    op.create_index("uq_performance_capture_platform_receipt", TABLE,
                    ["receipt_id"], unique=True,
                    postgresql_where=sa.text("tenant_id IS NULL"),
                    sqlite_where=sa.text("tenant_id IS NULL"))
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
        raise RuntimeError("downgrade blocked: retained Performance capture receipts would be deleted")
    if op.get_bind().dialect.name == "postgresql":
        for name in ("tenant_isolation_select", "tenant_isolation_insert",
                     "tenant_isolation_update", "tenant_isolation_delete"):
            op.execute(f"DROP POLICY {name} ON {TABLE}")
        op.execute(f"ALTER TABLE {TABLE} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {TABLE} DISABLE ROW LEVEL SECURITY")
    op.drop_index("uq_performance_capture_platform_receipt", table_name=TABLE)
    op.drop_index("uq_performance_capture_tenant_receipt", table_name=TABLE)
    op.drop_table(TABLE)
