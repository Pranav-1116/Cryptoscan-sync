""":class:`graph_snapshots` — immutable content-addressed dependency-graph versions.

Revision ID: 0054
Revises: 0053
Create Date: 2026-09-08

Adds the deterministic graph-version table that backs the Dependency Graph's
"Graph timeline + CBOM version compare" view. A snapshot records the real
canonicalized node/edge set at a point in time (plus the diff vs the previous
version and any newly present quantum-vulnerable risk). It never invents state.

Mirrors the ``GraphSnapshot`` ORM model exactly (see the schema-parity test).
"""
import sqlalchemy as sa
from alembic import op

revision = "0054"
down_revision = "0053"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "graph_snapshots",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("parent_fingerprint", sa.String(64), nullable=True),
        sa.Column("node_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("edge_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("nodes_by_kind", sa.JSON(), nullable=True),
        sa.Column("edges_by_relation", sa.JSON(), nullable=True),
        sa.Column("nodes", sa.JSON(), nullable=True),
        sa.Column("edges", sa.JSON(), nullable=True),
        sa.Column("added_nodes", sa.JSON(), nullable=True),
        sa.Column("removed_nodes", sa.JSON(), nullable=True),
        sa.Column("added_edges", sa.JSON(), nullable=True),
        sa.Column("removed_edges", sa.JSON(), nullable=True),
        sa.Column("new_quantum_vulnerable", sa.JSON(), nullable=True),
        sa.Column("created_by", sa.String(100), nullable=False, server_default="system"),
    )
    op.create_index("ix_graph_snapshots_version", "graph_snapshots", ["version"], unique=True)
    op.create_index("ix_graph_snapshots_fingerprint", "graph_snapshots", ["fingerprint"])


def downgrade() -> None:
    op.drop_index("ix_graph_snapshots_fingerprint", table_name="graph_snapshots")
    op.drop_index("ix_graph_snapshots_version", table_name="graph_snapshots")
    op.drop_table("graph_snapshots")
