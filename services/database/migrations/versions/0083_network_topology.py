"""Declared network topology (advanced/58 P0#1–2, round 31).

Two tables: topology_nodes (declared dns/cdn/waf/lb/k8s hops with their
system links) and topology_edges (RESOLVES_TO/PROXIES_TO/ROUTES_TO/
PEERS_WITH between them). Every row carries source="declared" — this is
operator-declared topology, not a scanned surface.
"""

from alembic import op
import sqlalchemy as sa

revision = "0083"
down_revision = "0082"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "topology_nodes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("kind", sa.String(40), nullable=False),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("attrs", sa.JSON(), nullable=True),
        sa.Column("system_ids", sa.JSON(), nullable=True),
        sa.Column("system_relation", sa.String(20), nullable=False,
                  server_default="TERMINATES_AT"),
        sa.Column("source", sa.String(20), nullable=False,
                  server_default="declared"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "name", name="uq_topology_node_name"),
    )
    op.create_index("ix_topology_nodes_kind", "topology_nodes", ["kind"])

    op.create_table(
        "topology_edges",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("from_name", sa.String(300), nullable=False),
        sa.Column("to_name", sa.String(300), nullable=False),
        sa.Column("relation", sa.String(40), nullable=False),
        sa.Column("attrs", sa.JSON(), nullable=True),
        sa.Column("source", sa.String(20), nullable=False,
                  server_default="declared"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "from_name", "to_name", "relation",
                            name="uq_topology_edge"),
    )
    op.create_index("ix_topology_edges_from", "topology_edges", ["from_name"])


def downgrade() -> None:
    op.drop_index("ix_topology_edges_from", table_name="topology_edges")
    op.drop_table("topology_edges")
    op.drop_index("ix_topology_nodes_kind", table_name="topology_nodes")
    op.drop_table("topology_nodes")
