"""Network topology + cryptographic dependency graph.

The graph answers the questions the migration simulator needs:

- if a certificate changes, which endpoints break?
- if a VPN crypto profile changes, which branches are affected?
- if a CA rotates, which devices are affected?
- if a TLS policy changes, which applications are affected?

Relationship vocabulary (directed edges):

CONNECTED_TO, ROUTES_TO, PROTECTS, TERMINATES_TLS_FOR, DEPENDS_ON,
AUTHENTICATES_TO, USES_CERTIFICATE, USES_VPN, USES_IPSEC, USES_TLS
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

RELATIONSHIPS = (
    "CONNECTED_TO", "ROUTES_TO", "PROTECTS", "TERMINATES_TLS_FOR", "DEPENDS_ON",
    "AUTHENTICATES_TO", "USES_CERTIFICATE", "USES_VPN", "USES_IPSEC", "USES_TLS",
)


@dataclass
class GraphEdge:
    source: str
    target: str
    relationship: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.relationship not in RELATIONSHIPS:
            raise ValueError(f"unknown relationship '{self.relationship}' (choose from {RELATIONSHIPS})")

    def to_dict(self) -> dict[str, Any]:
        return {"source": self.source, "target": self.target,
                "relationship": self.relationship, "metadata": dict(self.metadata)}


class NetworkGraph:
    """Directed graph with typed edges + traversal helpers."""

    def __init__(self) -> None:
        self._nodes: set[str] = set()
        self._edges: list[GraphEdge] = []
        self._adj: dict[str, list[GraphEdge]] = {}
        self._rev: dict[str, list[GraphEdge]] = {}

    def add_node(self, node: str) -> None:
        self._nodes.add(node)

    def add_edge(self, source: str, target: str, relationship: str,
                 **metadata: Any) -> GraphEdge:
        edge = GraphEdge(source, target, relationship, dict(metadata))
        self._nodes.add(source)
        self._nodes.add(target)
        self._edges.append(edge)
        self._adj.setdefault(source, []).append(edge)
        self._rev.setdefault(target, []).append(edge)
        return edge

    def add_edges(self, edges: Iterable[dict[str, Any]]) -> int:
        count = 0
        for edge in edges:
            self.add_edge(str(edge["from"]), str(edge["to"]),
                          str(edge.get("relationship") or "CONNECTED_TO"),
                          **(edge.get("metadata") or {}))
            count += 1
        return count

    # ------------------------------------------------------------------ queries

    def nodes(self) -> list[str]:
        return sorted(self._nodes)

    def edges(self) -> list[GraphEdge]:
        return list(self._edges)

    def outgoing(self, node: str, relationship: str | None = None) -> list[GraphEdge]:
        edges = self._adj.get(node, [])
        return [e for e in edges if relationship is None or e.relationship == relationship]

    def incoming(self, node: str, relationship: str | None = None) -> list[GraphEdge]:
        edges = self._rev.get(node, [])
        return [e for e in edges if relationship is None or e.relationship == relationship]

    def neighbors(self, node: str) -> list[str]:
        seen: set[str] = set()
        for edge in self._adj.get(node, []):
            seen.add(edge.target)
        for edge in self._rev.get(node, []):
            seen.add(edge.source)
        return sorted(seen)

    def dependents(self, node: str) -> list[str]:
        """Nodes that depend on ``node`` (transitive reverse traversal)."""
        seen: set[str] = set()
        stack = [edge.source for edge in self._rev.get(node, [])]
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            stack.extend(edge.source for edge in self._rev.get(current, []))
        return sorted(seen)

    def dependencies(self, node: str) -> list[str]:
        """Nodes ``node`` depends on (transitive forward traversal)."""
        seen: set[str] = set()
        stack = [edge.target for edge in self._adj.get(node, [])]
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            stack.extend(edge.target for edge in self._adj.get(current, []))
        return sorted(seen)

    def paths(self, start: str, end: str, *, max_depth: int = 6) -> list[list[str]]:
        """All simple paths up to max_depth."""
        found: list[list[str]] = []

        def _walk(current: str, trail: list[str]) -> None:
            if len(trail) > max_depth:
                return
            if current == end and len(trail) > 1:
                found.append(list(trail))
                return
            for edge in self._adj.get(current, []):
                if edge.target not in trail:
                    _walk(edge.target, trail + [edge.target])

        _walk(start, [start])
        return found

    def crypto_path(self, start: str, end: str) -> list[dict[str, Any]]:
        """The complete cryptographic path between two nodes: every edge with
        its relationship + any crypto metadata carried on the edge."""
        path = self.paths(start, end, max_depth=8)
        if not path:
            return []
        chosen = path[0]
        return [
            {
                "from": chosen[i],
                "to": chosen[i + 1],
                "relationship": next(
                    (e.relationship for e in self._adj.get(chosen[i], []) if e.target == chosen[i + 1]),
                    "CONNECTED_TO",
                ),
                "crypto": next(
                    (e.metadata.get("crypto") for e in self._adj.get(chosen[i], [])
                     if e.target == chosen[i + 1] and e.metadata.get("crypto")),
                    {},
                ),
            }
            for i in range(len(chosen) - 1)
        ]

    # ------------------------------------------------------------------ export

    def to_dict(self) -> dict[str, Any]:
        return {"nodes": self.nodes(), "edges": [e.to_dict() for e in self._edges]}

    def to_neo4j_cypher(self) -> str:
        """Cypher to load this graph into Neo4j."""
        statements = []
        for node in self.nodes():
            safe = node.replace("\\", "\\\\").replace('"', '\\"')
            statements.append(f'MERGE (n:NetworkAsset {{identity: "{safe}"}});')
        for edge in self._edges:
            safe_s = edge.source.replace("\\", "\\\\").replace('"', '\\"')
            safe_t = edge.target.replace("\\", "\\\\").replace('"', '\\"')
            statements.append(
                f'MATCH (a:NetworkAsset {{identity: "{safe_s}"}}), '
                f'(b:NetworkAsset {{identity: "{safe_t}"}}) '
                f'MERGE (a)-[:{edge.relationship}]->(b);'
            )
        return "\n".join(statements)

    def edge_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for edge in self._edges:
            counts[edge.relationship] = counts.get(edge.relationship, 0) + 1
        return counts
