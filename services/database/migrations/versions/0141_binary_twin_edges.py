"""Binary Digital Twin relationship edges (docs/binary-intelligence/
01_PRODUCT_SPEC.md §8) — every edge carries its provenance and the
evidence class that supports it; an indicator edge has NO twin
predicate.

Revision ID: 0141
Revises: 0140
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0141"
down_revision = "0140"
branch_labels = None
depends_on = None

_COMMON = (
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("tenant_id", sa.String(64), nullable=True, index=True),
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
)


def _table(name, *columns):
    op.create_table(name, *columns, *_COMMON)


def upgrade() -> None:
    _table(
        "binary_twin_edges",
        sa.Column("edge_id", sa.String(80), nullable=False),
        sa.Column("run_id", sa.String(80), nullable=False, index=True),
        sa.Column("artifact_id", sa.String(80), nullable=False),
        sa.Column("artifact_sha256", sa.String(64), nullable=False),
        sa.Column("subject", sa.String(200), nullable=False),
        sa.Column("relationship_type", sa.String(40), nullable=False),
        sa.Column("twin_predicate", sa.String(40), nullable=True),
        sa.Column("object", sa.String(200), nullable=False),
        sa.Column("provenance", sa.String(40), nullable=False),
        sa.Column("evidence_class", sa.String(40), nullable=False),
        sa.Column("limitations", sa.JSON(), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_binary_twin_edges_tenant_artifact",
                    "binary_twin_edges", ["tenant_id", "artifact_id"])
    op.create_index("uq_binary_twin_edges_tenant_edge",
                    "binary_twin_edges", ["tenant_id", "edge_id"],
                    unique=True)


def downgrade() -> None:
    op.drop_index("uq_binary_twin_edges_tenant_edge", "binary_twin_edges")
    op.drop_index("ix_binary_twin_edges_tenant_artifact",
                  "binary_twin_edges")
    op.drop_table("binary_twin_edges")
