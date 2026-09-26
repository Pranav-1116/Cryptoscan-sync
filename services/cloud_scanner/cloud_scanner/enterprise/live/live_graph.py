"""ZELNX Live Cloud Intelligence Engine — live cloud crypto dependency
graph (§16).

The dependency graph updates automatically when cloud events occur:

    AWS WORKLOAD ──USES_KEY──▶ AWS KMS ─┐
    AWS WORKLOAD ──USES_CERTIFICATE──▶ ACM │
    AZURE API ──USES_KEY──▶ KEY VAULT ──▶ (cross-provider edges)
    GCP SERVICE ──USES_KEY──▶ CLOUD KMS ─┘

Edges are typed and mutable (upsert / delete on events) and resolve to a
static graph for posture / simulation reuse.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cloud_scanner.enterprise.dependency_graph import CloudDependencyGraph
from cloud_scanner.enterprise.live.event_schema import CloudEvent

RELATION_KINDS = ("RUNS_ON", "USES_KEY", "USES_CERTIFICATE", "EXPOSED_BY",
                  "TERMINATES_TLS", "STORED_IN", "CONNECTS_TO", "DEPENDS_ON")

EVENT_RELATION_HINTS = {
    "KEY_": "USES_KEY",
    "CERTIFICATE": "USES_CERTIFICATE",
    "TLS_TERMINATION_CHANGE": "TERMINATES_TLS",
    "LOAD_BALANCER_CHANGE": "EXPOSED_BY",
    "VPN_CHANGE": "CONNECTS_TO",
    "ROUTE_CHANGE": "CONNECTS_TO",
    "NETWORK_PEERING_CHANGE": "CONNECTS_TO",
    "CROSS_CLOUD_CONNECTION": "CONNECTS_TO",
    "DEPENDENCY_CHANGED": "DEPENDS_ON",
}


@dataclass
class LiveEdge:
    """One typed, mutable edge in the live graph."""

    source: str
    target: str
    relation: str
    provider: str = ""
    account: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "relation": self.relation,
            "provider": self.provider,
            "account": self.account,
            "metadata": dict(self.metadata),
        }


class LiveCloudDependencyGraph:
    """Mutable multi-cloud dependency graph updated by events."""

    def __init__(self) -> None:
        self._edges: dict[tuple[str, str, str], LiveEdge] = {}

    def upsert(self, source: str, target: str, relation: str, *,
               provider: str = "", account: str = "",
               metadata: dict[str, Any] | None = None) -> None:
        if not source or not target or not source.strip() or not target.strip():
            return
        if relation not in RELATION_KINDS:
            relation = "DEPENDS_ON"
        self._edges[(source, target, relation)] = LiveEdge(
            source=source, target=target, relation=relation,
            provider=provider, account=account,
            metadata=dict(metadata or {}),
        )

    def delete(self, source: str, target: str, relation: str) -> bool:
        key = (source, target, relation)
        if key in self._edges:
            del self._edges[key]
            return True
        return False

    def delete_all(self, node: str) -> int:
        removed = [key for key in self._edges
                   if key[0] == node or key[1] == node]
        for key in removed:
            del self._edges[key]
        return len(removed)

    def apply_event(self, event: CloudEvent, *, target: str = "",
                    relation: str | None = None) -> str | None:
        """Auto-wire an edge from an event (source = resource_id)."""
        if not event.resource_id:
            return None
        if not target:
            meta = event.provider_metadata
            target = str(meta.get("depends_on")
                         or (meta.get("metadata") or {}).get("depends_on")
                         or meta.get("uses_certificate")
                         or (meta.get("metadata") or {}).get("uses_certificate")
                         or "")
        if not target:
            return None
        relation = relation or relation_for_event(event.event_type)
        if event.event_type in ("RESOURCE_REMOVED", "KEY_SCHEDULED_FOR_DELETION",
                                "CERTIFICATE_REVOKED", "CERTIFICATE_EXPIRED"):
            self.delete(event.resource_id, target, relation)
            return None
        self.upsert(event.resource_id, target, relation,
                    provider=event.provider, account=event.account_id)
        return relation

    def edges(self) -> list[LiveEdge]:
        return list(self._edges.values())

    def to_dicts(self) -> list[dict[str, Any]]:
        return [edge.to_dict() for edge in self.edges()]

    def by_relation(self, relation: str) -> list[LiveEdge]:
        return [edge for edge in self._edges.values() if edge.relation == relation]

    def dependents(self, node: str, *, transitive: bool = True) -> list[str]:
        result: list[str] = []
        seen: set[str] = set()
        frontier = [edge.source for edge in self._edges.values() if edge.target == node]
        while frontier:
            current = frontier.pop(0)
            if current in seen or current == node:
                continue
            seen.add(current)
            result.append(current)
            if transitive:
                frontier.extend(edge.source for edge in self._edges.values()
                                if edge.target == current)
        return result

    def count(self) -> int:
        return len(self._edges)

    def to_static(self) -> CloudDependencyGraph:
        static = CloudDependencyGraph()
        for edge in self._edges.values():
            static.add_edge(edge.source, edge.target, edge.relation,
                            provider=edge.provider, account=edge.account,
                            metadata=edge.metadata)
        return static

    def summary(self) -> dict[str, Any]:
        return {
            "edges": len(self._edges),
            "by_relation": {
                relation: len(self.by_relation(relation)) for relation in RELATION_KINDS
            },
            "by_provider": {
                provider: sum(1 for e in self._edges.values() if e.provider == provider)
                for provider in ("aws", "azure", "gcp")
            },
        }


def relation_for_event(event_type: str) -> str:
    for hint, relation in EVENT_RELATION_HINTS.items():
        if hint in str(event_type or ""):
            return relation
    return "DEPENDS_ON"
