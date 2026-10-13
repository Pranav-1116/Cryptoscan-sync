"""Persisted, content-addressed CBOM snapshots (§4.4, round 45).

One deterministic rendering of a scan's CBOM, stored verbatim and
content-addressed (SHA-256 over the exact serialized document). Serves
GET /cbom/snapshots/{id} without regeneration, keeps pipeline BOMs durable
instead of ephemeral, and gives exports a pinned version traceable to the
exact scan and its evidence. Identical renderings collapse to one row via
the (scan_id, content_hash) unique constraint.
"""

from alembic import op
import sqlalchemy as sa

revision = "0090"
down_revision = "0089"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cbom_snapshots",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scan_id", sa.String(36),
                  sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("format", sa.String(10), nullable=False, server_default="json"),
        sa.Column("signed", sa.String(10), nullable=False, server_default="none"),
        sa.Column("generator", sa.String(30), nullable=False, server_default="api"),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("component_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_by", sa.String(120), nullable=False),
        sa.Column("snapshotted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("tenant_id", sa.String(36), nullable=True),
        sa.UniqueConstraint("scan_id", "content_hash", name="uq_cbom_snapshot_scan_hash"),
    )
    op.create_index("ix_cbom_snapshots_scan_id", "cbom_snapshots", ["scan_id"])
    op.create_index("ix_cbom_snapshots_content_hash", "cbom_snapshots", ["content_hash"])
    op.create_index("ix_cbom_snapshots_tenant_id", "cbom_snapshots", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_cbom_snapshots_tenant_id", table_name="cbom_snapshots")
    op.drop_index("ix_cbom_snapshots_content_hash", table_name="cbom_snapshots")
    op.drop_index("ix_cbom_snapshots_scan_id", table_name="cbom_snapshots")
    op.drop_table("cbom_snapshots")
