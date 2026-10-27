"""Persistence for declared network topology (advanced/58, round 31)."""

from __future__ import annotations

from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from db.models.network_topology import TopologyEdge, TopologyNode


class TopologyRepository:
    def __init__(self, session: Session):
        self.session = session

    def replace_all(self, document: dict[str, Any]) -> dict[str, int]:
        """Idempotent full replace: the document IS the declared topology.

        Validation happened before this call (db.topology), so the
        swap is safe: delete nodes+edges, insert the new set, one flush.
        """
        self.session.execute(delete(TopologyEdge))
        self.session.execute(delete(TopologyNode))
        for node in document["nodes"]:
            self.session.add(TopologyNode(
                kind=node["kind"], name=node["name"], attrs=node.get("attrs"),
                system_ids=node.get("system_ids") or [],
                system_relation=node.get("system_relation") or "TERMINATES_AT",
                source=node.get("source") or "declared",
            ))
        for edge in document["edges"]:
            self.session.add(TopologyEdge(
                from_name=edge["from"], to_name=edge["to"],
                relation=edge["relation"], attrs=edge.get("attrs"),
                source=edge.get("source") or "declared",
            ))
        self.session.flush()
        return {"nodes": len(document["nodes"]), "edges": len(document["edges"])}

    def list_nodes(self) -> list[TopologyNode]:
        return list(
            self.session.execute(
                select(TopologyNode).order_by(TopologyNode.kind, TopologyNode.name)
            ).scalars()
        )

    def list_edges(self) -> list[TopologyEdge]:
        return list(
            self.session.execute(
                select(TopologyEdge).order_by(TopologyEdge.from_name, TopologyEdge.to_name)
            ).scalars()
        )

    def nodes_for_system(self, system_id: str) -> list[TopologyNode]:
        rows = self.list_nodes()
        return [
            row for row in rows
            if system_id in [str(s) for s in (row.system_ids or [])]
        ]

    def graph_payload(self) -> dict[str, list[dict[str, Any]]]:
        """Shape consumed by the graph builder + engine (declared only)."""
        nodes = [
            {
                "id": row.id,
                "kind": row.kind,
                "name": row.name,
                "attrs": row.attrs or {},
                "system_ids": [str(s) for s in (row.system_ids or [])],
                "system_relation": row.system_relation,
                "source": row.source,
            }
            for row in self.list_nodes()
        ]
        edges = [
            {"from": row.from_name, "to": row.to_name, "relation": row.relation,
             "source": row.source}
            for row in self.list_edges()
        ]
        return {"nodes": nodes, "edges": edges}
