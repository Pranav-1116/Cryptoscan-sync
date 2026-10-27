"""Cascade stack completion: edge provenance, declared linkage, twin snapshots, watches.

Revision ID: 0070
Revises: 0069
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0070"
down_revision = "0069"
branch_labels = None
depends_on = None


def _base_columns():
    return [
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=True),
    ]


def upgrade() -> None:
    # edge provenance: where an edge came from and who vouches for it
    op.add_column("system_dependencies", sa.Column("source", sa.String(20), nullable=False, server_default="manual"))
    op.add_column("system_dependencies", sa.Column("created_by", sa.String(100), nullable=True))
    op.add_column("system_dependencies", sa.Column("confidence", sa.Float(), nullable=True))
    op.add_column("system_dependencies", sa.Column("last_verified", sa.DateTime(timezone=True), nullable=True))

    # declared crypto↔hardware linkage (operator-declared, never inferred)
    op.create_table(
        "crypto_hardware_links",
        *_base_columns(),
        sa.Column("asset_id", sa.String(36), sa.ForeignKey("crypto_assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("hardware_asset_id", sa.String(200), nullable=False),
        sa.Column("declared_by", sa.String(100), nullable=True),
        sa.Column("note", sa.String(500), nullable=True),
        sa.UniqueConstraint("asset_id", "hardware_asset_id", name="uq_crypto_hardware_link"),
    )
    op.create_index("ix_crypto_hardware_links_tenant_id", "crypto_hardware_links", ["tenant_id"])
    op.create_index("ix_crypto_hardware_links_asset_id", "crypto_hardware_links", ["asset_id"])

    # vendor-of-vendor (sub-tier supply chain) edges
    op.create_table(
        "vendor_dependencies",
        *_base_columns(),
        sa.Column("parent_vendor_id", sa.String(36), sa.ForeignKey("vendors.id", ondelete="CASCADE"), nullable=False),
        sa.Column("child_vendor_id", sa.String(36), sa.ForeignKey("vendors.id", ondelete="CASCADE"), nullable=False),
        sa.Column("relation", sa.String(80), nullable=True),
        sa.Column("declared_by", sa.String(100), nullable=True),
        sa.UniqueConstraint("parent_vendor_id", "child_vendor_id", name="uq_vendor_dependency"),
    )
    op.create_index("ix_vendor_dependencies_tenant_id", "vendor_dependencies", ["tenant_id"])
    op.create_index("ix_vendor_dependencies_parent_vendor_id", "vendor_dependencies", ["parent_vendor_id"])

    # versioned, content-addressed twin snapshots (point-in-time cascade replay)
    op.create_table(
        "twin_snapshots",
        *_base_columns(),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("parent_fingerprint", sa.String(64), nullable=True),
        sa.Column("state", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(100), nullable=True),
        sa.UniqueConstraint("version", name="uq_twin_snapshot_version"),
    )
    op.create_index("ix_twin_snapshots_tenant_id", "twin_snapshots", ["tenant_id"])
    op.create_index("ix_twin_snapshots_fingerprint", "twin_snapshots", ["fingerprint"])

    # saved cascade targets: re-run on demand, diff, alert on change
    op.create_table(
        "cascade_watches",
        *_base_columns(),
        sa.Column("target", sa.String(500), nullable=False),
        sa.Column("target_kind", sa.String(30), nullable=True),
        sa.Column("max_depth", sa.Integer(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_run_id", sa.String(36), nullable=True),
        sa.Column("created_by", sa.String(100), nullable=True),
    )
    op.create_index("ix_cascade_watches_tenant_id", "cascade_watches", ["tenant_id"])
    op.create_index("ix_cascade_watches_target", "cascade_watches", ["target"])


def downgrade() -> None:
    op.drop_index("ix_cascade_watches_target", table_name="cascade_watches")
    op.drop_index("ix_cascade_watches_tenant_id", table_name="cascade_watches")
    op.drop_table("cascade_watches")
    op.drop_index("ix_twin_snapshots_fingerprint", table_name="twin_snapshots")
    op.drop_index("ix_twin_snapshots_tenant_id", table_name="twin_snapshots")
    op.drop_table("twin_snapshots")
    op.drop_index("ix_vendor_dependencies_parent_vendor_id", table_name="vendor_dependencies")
    op.drop_index("ix_vendor_dependencies_tenant_id", table_name="vendor_dependencies")
    op.drop_table("vendor_dependencies")
    op.drop_index("ix_crypto_hardware_links_asset_id", table_name="crypto_hardware_links")
    op.drop_index("ix_crypto_hardware_links_tenant_id", table_name="crypto_hardware_links")
    op.drop_table("crypto_hardware_links")
    op.drop_column("system_dependencies", "last_verified")
    op.drop_column("system_dependencies", "confidence")
    op.drop_column("system_dependencies", "created_by")
    op.drop_column("system_dependencies", "source")
