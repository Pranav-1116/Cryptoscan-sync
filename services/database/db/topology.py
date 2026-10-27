"""Pure validation for declared topology documents (advanced/58, round 31).

Document shape (``zelnx-topology/v1``)::

    {
      "format": "zelnx-topology/v1",
      "nodes": [
        {"kind": "dns", "name": "api.bank.example", "attrs": {"record": "A"}},
        {"kind": "load_balancer", "name": "alb-public",
         "system_ids": ["sys-pay"], "system_relation": "TERMINATES_AT"}
      ],
      "edges": [
        {"from": "api.bank.example", "to": "alb-public", "relation": "RESOLVES_TO"}
      ]
    }

Validation is total: kinds, relations, duplicate names, dangling edge
endpoints, self-edges, and cycles are all rejected BEFORE anything is
persisted, so a rejected document leaves the stored topology untouched.
"""

from __future__ import annotations

from typing import Any, Mapping

from db.models.network_topology import EDGE_RELATIONS, NODE_KINDS, NODE_SYSTEM_RELATIONS

TOPOLOGY_FORMAT = "zelnx-topology/v1"


class TopologyError(ValueError):
    """Invalid topology document — the stored topology stays untouched."""


def validate_topology_document(doc: Any) -> dict[str, Any]:
    if not isinstance(doc, dict):
        raise TopologyError("topology document must be an object")
    if doc.get("format") not in (None, TOPOLOGY_FORMAT):
        raise TopologyError(f"unsupported topology format {doc.get('format')!r}")
    nodes = doc.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        raise TopologyError("topology document needs a non-empty nodes list")
    edges = doc.get("edges") or []
    if not isinstance(edges, list):
        raise TopologyError("edges must be a list")

    names: set[str] = set()
    normalized_nodes: list[dict[str, Any]] = []
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            raise TopologyError(f"node #{index} must be an object")
        kind = str(node.get("kind") or "").strip()
        if kind not in NODE_KINDS:
            raise TopologyError(
                f"node #{index} kind '{kind}' unknown (one of {sorted(NODE_KINDS)})")
        name = str(node.get("name") or "").strip()
        if not name:
            raise TopologyError(f"node #{index} needs a name")
        if name in names:
            raise TopologyError(f"duplicate node name '{name}'")
        names.add(name)
        system_ids = node.get("system_ids") or []
        if not isinstance(system_ids, list):
            raise TopologyError(f"node '{name}' system_ids must be a list")
        system_relation = str(node.get("system_relation") or "TERMINATES_AT")
        if system_relation not in NODE_SYSTEM_RELATIONS:
            raise TopologyError(
                f"node '{name}' system_relation must be one of {sorted(NODE_SYSTEM_RELATIONS)}")
        attrs = node.get("attrs") or {}
        if not isinstance(attrs, dict):
            raise TopologyError(f"node '{name}' attrs must be an object")
        normalized_nodes.append({
            "kind": kind, "name": name, "attrs": attrs,
            "system_ids": [str(s) for s in system_ids],
            "system_relation": system_relation,
            "source": "declared",
        })

    normalized_edges: list[dict[str, Any]] = []
    for index, edge in enumerate(edges):
        if not isinstance(edge, dict):
            raise TopologyError(f"edge #{index} must be an object")
        src = str(edge.get("from") or "").strip()
        dst = str(edge.get("to") or "").strip()
        relation = str(edge.get("relation") or "").strip()
        if not src or not dst:
            raise TopologyError(f"edge #{index} needs from and to")
        if src not in names:
            raise TopologyError(f"edge #{index} references unknown node '{src}'")
        if dst not in names:
            raise TopologyError(f"edge #{index} references unknown node '{dst}'")
        if src == dst:
            raise TopologyError(f"edge #{index} is a self-edge on '{src}'")
        if relation not in EDGE_RELATIONS:
            raise TopologyError(
                f"edge #{index} relation '{relation}' unknown "
                f"(one of {sorted(EDGE_RELATIONS)})")
        attrs = edge.get("attrs") or {}
        if not isinstance(attrs, dict):
            raise TopologyError(f"edge #{index} attrs must be an object")
        normalized_edges.append({
            "from": src, "to": dst, "relation": relation, "attrs": attrs,
            "source": "declared",
        })

    _reject_cycles(names, normalized_edges)
    return {"format": TOPOLOGY_FORMAT, "nodes": normalized_nodes,
            "edges": normalized_edges}


def _reject_cycles(names: set[str], edges: list[dict[str, Any]]) -> None:
    """A declared chain must be a DAG — a cycle is a modeling error."""
    adjacency: dict[str, list[str]] = {name: [] for name in names}
    for edge in edges:
        adjacency[edge["from"]].append(edge["to"])

    WHITE, GRAY, BLACK = 0, 1, 2
    color = {name: WHITE for name in names}
    stack: list[str] = []

    def visit(node: str) -> list[str] | None:
        color[node] = GRAY
        stack.append(node)
        for nxt in adjacency[node]:
            if color[nxt] == GRAY:
                return stack[stack.index(nxt):] + [nxt]
            if color[nxt] == WHITE:
                found = visit(nxt)
                if found:
                    return found
        stack.pop()
        color[node] = BLACK
        return None

    for name in sorted(names):
        if color[name] == WHITE:
            cycle = visit(name)
            if cycle:
                raise TopologyError(
                    "topology edges form a cycle: " + " -> ".join(cycle))


def declared_chains_to_system(
    nodes: list[Mapping[str, Any]],
    edges: list[Mapping[str, Any]],
    system_id: str,
) -> list[list[dict[str, Any]]]:
    """All declared chains ending at a node linked to ``system_id``.

    Returns lists of {node, relation} steps from the outermost declared
    hop (dns/cdn/ip_range) down to the node that fronts the system.
    Bounded by chain length 10 — a declared chain longer than that is a
    modeling error, not a deep internet path.
    """
    by_name = {str(n.get("name")): n for n in nodes}
    incoming: dict[str, list[tuple[str, str]]] = {}
    for edge in edges:
        incoming.setdefault(str(edge.get("to")), []).append(
            (str(edge.get("from")), str(edge.get("relation"))))

    frontier_nodes = [
        n for n in nodes
        if system_id in [str(s) for s in (n.get("system_ids") or [])]
    ]
    chains: list[list[dict[str, Any]]] = []
    for start in frontier_nodes:
        start_name = str(start.get("name"))
        stack: list[tuple[str, list[dict[str, Any]]]] = [
            (start_name, [{"node": start, "relation": start.get("system_relation") or "TERMINATES_AT"}])
        ]
        seen_chains: set[tuple[str, ...]] = set()
        while stack:
            current, chain = stack.pop()
            if len(chain) >= 10:
                continue
            upstream = incoming.get(current, [])
            if not upstream:
                key = tuple(step["node"]["name"] for step in chain)  # type: ignore[index]
                if key not in seen_chains:
                    seen_chains.add(key)
                    chains.append(list(reversed(chain)))
                continue
            for parent, relation in upstream:
                if any(step["node"]["name"] == parent for step in chain):  # type: ignore[index]
                    continue  # defensive: cycles rejected at validation
                stack.append((parent, chain + [{"node": by_name[parent],
                                                "relation": relation}]))
    return chains
