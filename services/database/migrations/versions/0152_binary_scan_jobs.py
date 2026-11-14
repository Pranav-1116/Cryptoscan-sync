"""Durable binary scan jobs: the database-backed artifact handoff.

Revision ID: 0152
Revises: 0151

A job row carries the bounded artifact bytes, so an acknowledged async scan
survives an API restart and any replica's worker can claim it. Claims are
lease-based (``claimed_by`` + ``lease_expires_at``) with an optimistic
``version`` counter; expired leases are requeued by the recovery path and
exhausted retries become terminal DEAD rows.
"""

import sqlalchemy as sa
from alembic import op

revision = "0152"
down_revision = "0151"
branch_labels = None
depends_on = None

TABLE = "binary_scan_jobs"


def upgrade() -> None:
    op.create_table(
        TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("job_id", sa.String(40), nullable=False, unique=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("artifact_bytes", sa.LargeBinary(), nullable=False),
        sa.Column("artifact_sha256", sa.String(64), nullable=False),
        sa.Column("original_filename", sa.String(255), nullable=False),
        sa.Column("source_type", sa.String(40), nullable=False),
        sa.Column("source_location", sa.String(512), nullable=True),
        sa.Column("uploaded_by", sa.String(100), nullable=False),
        sa.Column("profile", sa.String(40), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("claimed_by", sa.String(120), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
    )
    op.create_index("ix_binary_scan_jobs_claim", TABLE,
                    ["status", "lease_expires_at"])
    op.create_index("ix_binary_scan_jobs_tenant_page", TABLE,
                    ["tenant_id", "created_at", "id"])
    op.create_index("ix_binary_scan_jobs_tenant_id", TABLE, ["tenant_id"])
    if op.get_bind().dialect.name == "postgresql":
        # A new tenant table must not start its life unprotected in production.
        op.execute(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {TABLE} FORCE ROW LEVEL SECURITY")
        own = "(tenant_id::text = cryptoscan_current_tenant() OR cryptoscan_current_tenant() = '*')"
        op.execute(f"CREATE POLICY tenant_isolation_select ON {TABLE} FOR SELECT "
                   f"USING {own}")
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
            f"SELECT count(*) FROM {TABLE} WHERE status NOT IN ('DEAD')")).scalar():
        raise RuntimeError(
            "downgrade blocked: live binary scan jobs would lose their artifact handoff")
    if op.get_bind().dialect.name == "postgresql":
        for name in ("tenant_isolation_select", "tenant_isolation_insert",
                     "tenant_isolation_update", "tenant_isolation_delete"):
            op.execute(f"DROP POLICY IF EXISTS {name} ON {TABLE}")
    op.drop_index("ix_binary_scan_jobs_tenant_id", table_name=TABLE)
    op.drop_index("ix_binary_scan_jobs_tenant_page", table_name=TABLE)
    op.drop_index("ix_binary_scan_jobs_claim", table_name=TABLE)
    op.drop_table(TABLE)
