"""OS & Kernel digital-twin relationship edges
(docs/os-kernel-intelligence/01_PRODUCT_SPEC.md §8).

Revision ID: 0143
Revises: 0142
Create Date: 2026-10-16

os_twin_edges — evidence-backed relationship edges derived from OS
collections. Predicates are provides/contains/anchors ONLY: never
'uses' (no runtime-usage evidence exists from read-only collection)
and never a predicate for an indicator. Same-host co-location never
creates an edge — a relationship needs evidence of its own.
"""

import sqlalchemy as sa
from alembic import op

revision = "0143"
down_revision = "0142"
branch_labels = None
depends_on = None

_COMMON = (
    sa.Column("tenant_id", sa.String(120), nullable=True),
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
)


def upgrade() -> None:
    op.create_table(
        "os_twin_edges",
        sa.Column("edge_id", sa.String(80), nullable=False),
        sa.Column("run_id", sa.String(80), nullable=False),
        sa.Column("asset_id", sa.String(80), nullable=False),
        sa.Column("source", sa.String(160), nullable=False),
        sa.Column("predicate", sa.String(40), nullable=False),
        sa.Column("target", sa.String(160), nullable=False),
        sa.Column("provenance", sa.String(40), nullable=False),
        sa.Column("evidence_class", sa.String(30), nullable=False),
        sa.Column("evidence_source", sa.String(200), nullable=True),
        sa.Column("limitations", sa.JSON, nullable=True),
        *_COMMON,
    )
    op.create_index("uq_os_twin_edges_tenant_edge", "os_twin_edges",
                    ["tenant_id", "edge_id"], unique=True)
    op.create_index("ix_os_twin_edges_tenant_asset", "os_twin_edges",
                    ["tenant_id", "asset_id"])
    op.create_index("ix_os_twin_edges_run_id", "os_twin_edges", ["run_id"])


def downgrade() -> None:
    op.drop_table("os_twin_edges")
