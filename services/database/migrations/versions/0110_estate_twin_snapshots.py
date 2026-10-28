"""Digital Twin snapshot table (spec 94 §14, §19).

Revision 0110. Creates ``estate_twin_snapshots``: one row per distinct evidence
state, keyed by ``(tenant_id, projection_id)`` so identical evidence is one
snapshot with an observation counter rather than N rows that imply change.

The payload is stored whole on purpose — a comparison must not depend on the scan
runs still being in retention, nor on the code that produced them.
"""
from alembic import op
import sqlalchemy as sa

revision = "0110"
down_revision = "0109"
branch_labels = depends_on = None


def base():
    return [sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False)]


def upgrade():
    op.create_table(
        "estate_twin_snapshots", *base(),
        sa.Column("tenant_id", sa.String(36)),
        sa.Column("estate", sa.String(160)),
        sa.Column("scope", sa.String(160)),
        sa.Column("snapshot_id", sa.String(96), nullable=False),
        sa.Column("projection_id", sa.String(64), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("counts", sa.JSON()),
        sa.Column("collector_versions", sa.JSON()),
        sa.Column("assets", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("evidence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("relationships", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("unresolved_relationships", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("completeness_percent", sa.Float()),
        sa.Column("observations", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True)),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("source_run_id", sa.String(36)),
        sa.Column("captured_by", sa.String(160)),
        sa.Column("note", sa.Text()),
    )
    op.create_index("ix_estate_twin_snapshots_tenant_id", "estate_twin_snapshots", ["tenant_id"])
    op.create_index("ix_estate_twin_snapshots_projection_id", "estate_twin_snapshots", ["projection_id"])
    op.create_index(
        "ix_estate_twin_snapshots_tenant_projection",
        "estate_twin_snapshots",
        ["tenant_id", "projection_id"],
        unique=True,
    )
    op.create_index("ix_estate_twin_snapshots_last_seen", "estate_twin_snapshots", ["last_seen_at"])


def downgrade():
    op.drop_index("ix_estate_twin_snapshots_last_seen", table_name="estate_twin_snapshots")
    op.drop_index("ix_estate_twin_snapshots_tenant_projection", table_name="estate_twin_snapshots")
    op.drop_index("ix_estate_twin_snapshots_projection_id", table_name="estate_twin_snapshots")
    op.drop_index("ix_estate_twin_snapshots_tenant_id", table_name="estate_twin_snapshots")
    op.drop_table("estate_twin_snapshots")
