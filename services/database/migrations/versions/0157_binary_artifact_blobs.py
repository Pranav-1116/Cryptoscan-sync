"""Content-addressed artifact blobs: evidence bytes stored once.

Revision ID: 0157
Revises: 0156

Continuous collection resubmits the same artifacts; each submission used
to store its bytes again. This table is the deduplication: (tenant_id,
sha256) is unique and the bytes live here exactly once, envelope-encrypted
and tenant-bound (db/encryption). Job rows reference the content by hash.

The tenant is part of the identity on purpose: two tenants uploading the
same file store two blobs. Deduplication never becomes a cross-tenant side
channel. ref_count counts referencing jobs; the retention sweep drops a
blob only at 0 and records the deletion through db/privileged_ops.

RLS + grants follow 0151/0152's pattern: a new tenant table must not
start its life unprotected.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0157"
down_revision = "0156"
branch_labels = None
depends_on = None

TABLE = "binary_artifact_blobs"


def upgrade() -> None:
    op.create_table(
        TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("bytes_size", sa.BigInteger(), nullable=False),
        sa.Column("ref_count", sa.BigInteger(), nullable=False),
    )
    op.create_index("uq_binary_artifact_blobs_tenant_sha", TABLE,
                    ["tenant_id", "sha256"], unique=True)
    op.create_index("ix_binary_artifact_blobs_tenant_id", TABLE, ["tenant_id"])
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
    if op.get_bind().execute(sa.text(
            f"SELECT count(*) FROM {TABLE} WHERE ref_count > 0")).scalar():
        raise RuntimeError(
            "downgrade blocked: live blobs still referenced by jobs")
    if op.get_bind().dialect.name == "postgresql":
        for name in ("tenant_isolation_select", "tenant_isolation_insert",
                     "tenant_isolation_update", "tenant_isolation_delete"):
            op.execute(f"DROP POLICY IF EXISTS {name} ON {TABLE}")
    op.drop_index("ix_binary_artifact_blobs_tenant_id", table_name=TABLE)
    op.drop_index("uq_binary_artifact_blobs_tenant_sha", table_name=TABLE)
    op.drop_table(TABLE)
