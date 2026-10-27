"""Create/MERGE graph relationships."""

from __future__ import annotations

from typing import Any, Iterable

from graph_engine.builders import payload
from graph_engine.core.engine import GraphEngine


class RelationshipBuilder:
    def __init__(self, engine: GraphEngine | None = None) -> None:
        self.engine = engine or GraphEngine()

    def uses(self, system_id: str, asset_id: str, usage_type: str = "DISCOVERED") -> None:
        self.engine.add_edge(f"system:{system_id}", f"asset:{asset_id}", "USES")
        node = self.engine.nodes.get(f"asset:{asset_id}") or {}
        node["usage_type"] = usage_type
        if f"asset:{asset_id}" in self.engine.nodes:
            self.engine.nodes[f"asset:{asset_id}"] = node

    def _system_edge(self, parent_id: str, child_id: str, relation: str) -> None:
        if f"system:{child_id}" not in self.engine.nodes:
            self.engine.add_node(f"system:{child_id}", kind="System", name=child_id)
        if f"system:{parent_id}" not in self.engine.nodes:
            self.engine.add_node(f"system:{parent_id}", kind="System", name=parent_id)
        self.engine.add_edge(f"system:{parent_id}", f"system:{child_id}", relation)

    def calls(self, parent_id: str, child_id: str, protocol: str = "CALLS") -> None:
        # A transport argument is not a relation label. Retain this signature
        # for callers, but CALLS remains CALLS even for HTTP/mesh transports.
        self._system_edge(parent_id, child_id, "CALLS")

    def supports(self, system_id: str, process_id: str) -> None:
        self.engine.add_edge(f"system:{system_id}", f"process:{process_id}", "SUPPORTS")

    def owned_by(self, system_id: str, owner_id: str) -> None:
        self.engine.add_edge(f"system:{system_id}", f"owner:{owner_id}", "OWNED_BY")

    def must_comply_with(self, system_id: str, scope: str) -> None:
        self.engine.add_node(f"scope:{scope}", kind="ComplianceScope", name=scope, standard_name=scope)
        self.engine.add_edge(f"system:{system_id}", f"scope:{scope}", "MUST_COMPLY_WITH")

    def secured_by(self, system_id: str, cert_id: str) -> None:
        self.engine.add_edge(f"system:{system_id}", f"cert:{cert_id}", "SECURED_BY")

    def deployed_on(self, system_id: str, resource_id: str) -> None:
        self.engine.add_edge(f"system:{system_id}", f"cloud:{resource_id}", "DEPLOYED_ON")

    def depends_on_vendor(self, system_id: str, vendor_id: str) -> None:
        self.engine.add_edge(f"system:{system_id}", f"vendor:{vendor_id}", "DEPENDS_ON_VENDOR")

    def apply_calls(self, edges: Iterable[dict[str, Any]]) -> None:
        for row in payload.call_rows(edges):
            self._system_edge(row["parent_id"], row["child_id"], row["relation"])
