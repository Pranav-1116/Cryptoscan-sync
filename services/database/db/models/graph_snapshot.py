"""Immutable, content-addressed dependency-graph version (deterministic).

A graph snapshot captures the *real* graph node/edge set at a point in time and
is stored only when the canonicalized set changed (same state -> same version).
Comparing two versions yields genuinely-diffed added/removed nodes and
relationships plus any newly present quantum-vulnerable risk.

This is the engine behind the Dependency Graph's "Graph timeline + CBOM version
compare" view — it never invents state; it records what the graph actually was.
"""

from __future__ import annotations

from sqlalchemy import DateTime, JSON, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class GraphSnapshot(BaseModel, TenantScoped):
    __tablename__ = "graph_snapshots"
    __table_args__ = (UniqueConstraint("tenant_id", "version",
                                       name="uq_graph_snapshots_tenant_version"),)

    #: monotonic version number (1..n), unique per snapshot.
    version: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    # per-tenant numbering (migration 0071): each tenant numbers its own
    # snapshot history from 1

    #: sha256 over the canonicalized node+edge set.
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    parent_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)

    node_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    edge_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    nodes_by_kind: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    edges_by_relation: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    #: canonical node/edge arrays (JSON) so the snapshot is self-contained.
    nodes: Mapped[list | None] = mapped_column(JSON, nullable=True)
    edges: Mapped[list | None] = mapped_column(JSON, nullable=True)

    #: diff vs the previous version (node+edge keys).
    added_nodes: Mapped[list | None] = mapped_column(JSON, nullable=True)
    removed_nodes: Mapped[list | None] = mapped_column(JSON, nullable=True)
    added_edges: Mapped[list | None] = mapped_column(JSON, nullable=True)
    removed_edges: Mapped[list | None] = mapped_column(JSON, nullable=True)
    #: newly present quantum-vulnerable crypto assets in this version.
    new_quantum_vulnerable: Mapped[list | None] = mapped_column(JSON, nullable=True)

    relationship_policy: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    lifecycle_as_of: Mapped[object | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_by: Mapped[str] = mapped_column(String(100), nullable=False, default="system")

    def to_dict(self) -> dict:
        return {
            "id": self.id, "version": self.version, "fingerprint": self.fingerprint,
            "parent_fingerprint": self.parent_fingerprint,
            "relationship_policy": self.relationship_policy,
            "lifecycle_as_of": self.lifecycle_as_of.isoformat() if self.lifecycle_as_of else None,
            "node_count": self.node_count, "edge_count": self.edge_count,
            "nodes_by_kind": self.nodes_by_kind or {},
            "edges_by_relation": self.edges_by_relation or {},
            "added_nodes": self.added_nodes or [], "removed_nodes": self.removed_nodes or [],
            "added_edges": self.added_edges or [], "removed_edges": self.removed_edges or [],
            "new_quantum_vulnerable": self.new_quantum_vulnerable or [],
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
