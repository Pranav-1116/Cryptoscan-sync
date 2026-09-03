"""Deterministic blast-radius / business-impact analysis (no AI/ML).

Given a changed asset (e.g. an HSM, certificate, crypto library) and a
dependency graph, compute the set of reachable downstream nodes by BFS and
tally them into the layers operators care about — certificates, applications,
APIs, business services — with depth and the highest criticality reached. This
is pure graph traversal over explicit edges: the same graph and change always
produce the same blast radius.

The graph is supplied as an adjacency mapping (``node_id -> [downstream_ids]``)
or edges ``[(source, target), ...]`` plus optional node metadata (type and
criticality). When a live graph store is available the caller can materialize
edges from it; the analysis itself makes no network calls and needs no Neo4j.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

#: node type keywords -> impact layer (ordered by business proximity).
LAYER_ORDER = (
    "business_service",
    "api",
    "application",
    "certificate",
    "library",
    "asset",
    "system",
    "device",
)

_CRIT_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "VERY_HIGH": 4,
              "MISSION_CRITICAL": 5, "CRITICAL": 5, "SAFETY": 5}


def _node_type(meta: dict[str, Any] | None) -> str:
    if not meta:
        return "asset"
    return str(meta.get("type") or meta.get("node_type")
               or meta.get("kind") or "asset").strip().lower()


def _node_crit(meta: dict[str, Any] | None) -> str:
    if not meta:
        return "MEDIUM"
    return str(meta.get("criticality") or meta.get("tier") or "MEDIUM").strip().upper()


def _layer_for(node_type: str) -> str:
    nt = node_type.lower()
    for layer in LAYER_ORDER:
        if layer in nt or (layer == "api" and "api" in nt) \
                or (layer == "business_service" and "service" in nt):
            return layer
    return "asset"


@dataclass
class BlastRadius:
    origin: str
    reachable: int
    max_depth: int
    layers: dict[str, int]
    highest_criticality: str
    affected: list[dict[str, Any]] = field(default_factory=list)
    business_services: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "origin": self.origin,
            "reachable_nodes": self.reachable,
            "max_depth": self.max_depth,
            "impact_layers": self.layers,
            "highest_criticality": self.highest_criticality,
            "business_services_affected": self.business_services,
            "summary": (
                f"{self.layers.get('certificate', 0)} certificates, "
                f"{self.layers.get('application', 0)} applications, "
                f"{self.layers.get('api', 0)} APIs, "
                f"{self.layers.get('business_service', 0)} business services"
            ),
            "affected": self.affected,
        }


def _adjacency(edges: Iterable[tuple[str, str]] | Mapping[str, Iterable[str]]) -> dict[str, list[str]]:
    adj: dict[str, list[str]] = {}
    if isinstance(edges, Mapping):
        for k, v in edges.items():
            adj.setdefault(str(k), []).extend(str(x) for x in v)
        return adj
    for src, dst in edges:
        adj.setdefault(str(src), []).append(str(dst))
        adj.setdefault(str(dst), adj.get(str(dst), []))
    return adj


def analyze_blast_radius(
    origin: str,
    edges: Iterable[tuple[str, str]] | Mapping[str, Iterable[str]],
    *,
    nodes: Mapping[str, Mapping[str, Any]] | None = None,
    max_hops: int = 12,
) -> BlastRadius:
    """BFS downstream from ``origin`` and tally impact layers deterministically."""
    adj = _adjacency(edges)
    nodes = nodes or {}
    origin = str(origin)

    seen: dict[str, int] = {}
    order: list[str] = []
    queue: deque[tuple[str, int]] = deque([(origin, 0)])
    while queue:
        node, depth = queue.popleft()
        if depth > max_hops:
            continue
        if node in seen:
            # record the shortest depth, keep traversal minimal
            seen[node] = min(seen[node], depth)
            continue
        seen[node] = depth
        if node != origin:
            order.append(node)
        for nxt in adj.get(node, []):
            if nxt not in seen:
                queue.append((nxt, depth + 1))

    layers: dict[str, int] = {layer: 0 for layer in LAYER_ORDER}
    # seed with the origin node's criticality (the change source matters)
    origin_crit = _node_crit(dict(nodes.get(origin) or {}))
    highest = _CRIT_RANK.get(origin_crit, 2)
    highest_label = origin_crit
    affected: list[dict[str, Any]] = []
    business: list[str] = []
    for node in sorted(order, key=lambda n: (seen[n], n)):
        meta = nodes.get(node) or {}
        ntype = _node_type(dict(meta) if meta else None)
        layer = _layer_for(ntype)
        layers[layer] = layers.get(layer, 0) + 1
        crit = _node_crit(dict(meta) if meta else None)
        rank = _CRIT_RANK.get(crit, 2)
        if rank > highest:
            highest = rank
            highest_label = crit
        affected.append({
            "id": node,
            "name": str(meta.get("name") or node),
            "type": ntype, "layer": layer, "hops": seen[node],
            "criticality": crit,
        })
        if layer == "business_service":
            business.append(str(meta.get("name") or node))

    return BlastRadius(
        origin=origin,
        reachable=len(order),
        max_depth=max(seen.values(), default=0),
        layers={k: v for k, v in layers.items() if v},
        highest_criticality=highest_label,
        affected=affected,
        business_services=sorted(business),
    )
