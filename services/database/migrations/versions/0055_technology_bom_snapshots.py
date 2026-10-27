""":class:`technology_bom_snapshots` — immutable content-addressed unified BOM versions.

Revision ID: 0055
Revises: 0054
Create Date: 2026-09-09

Adds the deterministic Technology BOM version table that backs the "Live Asset
Intelligence" view (SBOM/CBOM/HBOM/Vendor materialized from ONE asset model).
A snapshot records the real materialized BOM component set at a point in time,
an immutable snapshot id (TECHBOM-YYYYMMDD-HHMMSS) the customer can reference in
an export, and the diff vs the previous version. It never invents state.

Mirrors the ``TechnologyBomSnapshot`` ORM model exactly (see schema-parity test).
"""
import sqlalchemy as sa
from alembic import op

revision = "0055"
down_revision = "0054"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "technology_bom_snapshots",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("parent_fingerprint", sa.String(64), nullable=True),
        sa.Column("snapshot_id", sa.String(32), nullable=False),
        sa.Column("environment", sa.String(100), nullable=False, server_default="default"),
        sa.Column("total_components", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("components_by_layer", sa.JSON(), nullable=True),
        sa.Column("state", sa.JSON(), nullable=True),
        sa.Column("diff", sa.JSON(), nullable=True),
        sa.Column("created_by", sa.String(100), nullable=False, server_default="system"),
    )
    op.create_index("ix_technology_bom_snapshots_version", "technology_bom_snapshots", ["version"], unique=True)
    op.create_index("ix_technology_bom_snapshots_fingerprint", "technology_bom_snapshots", ["fingerprint"])
    op.create_index("ix_technology_bom_snapshots_snapshot_id", "technology_bom_snapshots", ["snapshot_id"])


def downgrade() -> None:
    op.drop_index("ix_technology_bom_snapshots_snapshot_id", table_name="technology_bom_snapshots")
    op.drop_index("ix_technology_bom_snapshots_fingerprint", table_name="technology_bom_snapshots")
    op.drop_index("ix_technology_bom_snapshots_version", table_name="technology_bom_snapshots")
    op.drop_table("technology_bom_snapshots")
