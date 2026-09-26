"""ZELNX Cloud Discovery Engine — cloud dependency graph (spec §13).

One relationship model that works identically across AWS, Azure and GCP:

    Application ── RUNS_ON ── Compute
    Application ── USES_KEY ── KMS / Key Vault / Cloud KMS
    Application ── USES_CERTIFICATE ── Certificate
    Application ── EXPOSED_BY ── Load Balancer ── TERMINATES_TLS

Edges are directional and typed; the graph supports reachability queries
(``dependents``, ``dependencies``) used by posture, blast-radius analysis
and migration simulation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

RELATION_KINDS = ("RUNS_ON", "USES_KEY", "USES_CERTIFICATE", "EXPOSED_BY",
                  "TERMINATES_TLS", "STORED_IN", "CONNECTS_TO")


@dataclass
class GraphEdge:
    """One typed relationship between two cloud resources."""

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


class CloudDependencyGraph:
    """Typed multi-cloud dependency graph."""

    def __init__(self, edges: Iterable[GraphEdge] | None = None) -> None:
        self._edges: list[GraphEdge] = list(edges or [])

    # ------------------------------------------------------------------ build

    def add_edge(self, source: str, target: str, relation: str, *,
                 provider: str = "", account: str = "",
                 metadata: dict[str, Any] | None = None) -> None:
        if not source or not target or not source.strip() or not target.strip():
            return
        self._edges.append(GraphEdge(
            source=source, target=target, relation=relation,
            provider=provider, account=account,
            metadata=dict(metadata or {}),
        ))

    def build_from_rows(self, rows: Iterable[dict[str, Any]]) -> None:
        """Add edges from injected rows: {source, target, relation, ...}."""
        for row in rows:
            source = str(row.get("source") or "")
            target = str(row.get("target") or "")
            relation = str(row.get("relation") or "")
            if relation not in RELATION_KINDS:
                continue
            self.add_edge(
                source, target, relation,
                provider=str(row.get("provider") or ""),
                account=str(row.get("account") or ""),
                metadata=row.get("metadata") if isinstance(row.get("metadata"), dict) else None,
            )

    def build_from_workloads(self, workloads: list[Any],
                             keys: list[Any] | None = None,
                             certificates: list[Any] | None = None,
                             endpoints: list[Any] | None = None) -> None:
        """Derive RUNS_ON / USES_KEY / USES_CERTIFICATE / EXPOSED_BY edges
        from the normalized discovery models."""
        workloads = workloads or []
        keys = keys or []
        certificates = certificates or []
        endpoints = endpoints or []
        app_index: dict[str, list[Any]] = {}
        for workload in workloads:
            app = str(getattr(workload, "application", "") or workload.workload_id)
            app_index.setdefault(app, []).append(workload)
            self.add_edge(
                workload.workload_id, app, "RUNS_ON",
                provider=workload.cloud_provider, account=workload.account,
            )
        {key.key_id: key for key in keys}
        {cert.certificate_id: cert for cert in certificates}
        for workload in workloads:
            for key_ref in workload.key_dependencies:
                self.add_edge(
                    workload.workload_id, key_ref, "USES_KEY",
                    provider=workload.cloud_provider, account=workload.account,
                )
            for cert_ref in workload.certificate_usage:
                self.add_edge(
                    workload.workload_id, cert_ref, "USES_CERTIFICATE",
                    provider=workload.cloud_provider, account=workload.account,
                )
        for endpoint in endpoints:
            app = str(getattr(endpoint, "application", "") or "")
            if app:
                self.add_edge(
                    app, endpoint.endpoint, "EXPOSED_BY",
                    provider=endpoint.provider, account=endpoint.account,
                )
            cert_id = str(getattr(endpoint, "certificate_id", "") or "")
            if cert_id:
                self.add_edge(
                    endpoint.endpoint, cert_id, "TERMINATES_TLS",
                    provider=endpoint.provider, account=endpoint.account,
                )

    # ------------------------------------------------------------------ query

    def edges(self) -> list[GraphEdge]:
        return list(self._edges)

    def to_dicts(self) -> list[dict[str, Any]]:
        return [edge.to_dict() for edge in self._edges]

    def nodes(self) -> list[str]:
        seen: list[str] = []
        for edge in self._edges:
            for node in (edge.source, edge.target):
                if node not in seen:
                    seen.append(node)
        return seen

    def outgoing(self, node: str, relation: str | None = None) -> list[GraphEdge]:
        return [e for e in self._edges
                if e.source == node and (relation is None or e.relation == relation)]

    def incoming(self, node: str, relation: str | None = None) -> list[GraphEdge]:
        return [e for e in self._edges
                if e.target == node and (relation is None or e.relation == relation)]

    def dependents(self, node: str, *, transitive: bool = True) -> list[str]:
        """Nodes that depend on ``node`` (edges pointing at it)."""
        result: list[str] = []
        seen: set[str] = set()
        frontier = [edge.source for edge in self.incoming(node)]
        while frontier:
            current = frontier.pop(0)
            if current in seen or current == node:
                continue
            seen.add(current)
            result.append(current)
            if transitive:
                frontier.extend(edge.source for edge in self.incoming(current))
        return result

    def dependencies(self, node: str, *, transitive: bool = True) -> list[str]:
        """Nodes that ``node`` depends on (edges leaving it)."""
        result: list[str] = []
        seen: set[str] = set()
        frontier = [edge.target for edge in self.outgoing(node)]
        while frontier:
            current = frontier.pop(0)
            if current in seen or current == node:
                continue
            seen.add(current)
            result.append(current)
            if transitive:
                frontier.extend(edge.target for edge in self.outgoing(current))
        return result

    def edges_between(self, node_a: str, node_b: str) -> list[GraphEdge]:
        return [e for e in self._edges
                if {e.source, e.target} == {node_a, node_b}]

    def by_relation(self, relation: str) -> list[GraphEdge]:
        return [e for e in self._edges if e.relation == relation]

    def summary(self) -> dict[str, Any]:
        return {
            "nodes": len(self.nodes()),
            "edges": len(self._edges),
            "by_relation": {
                relation: len(self.by_relation(relation)) for relation in RELATION_KINDS
            },
            "by_provider": {
                provider: sum(1 for e in self._edges if e.provider == provider)
                for provider in ("aws", "azure", "gcp")
            },
        }
