"""Whole-graph analytics as pure functions over the vis export.

Both backends (memory GraphEngine and Neo4jGraphStore) produce the same
vis shape — {"nodes": [{id, label, group/kind, ...props}],
"edges": [{from, to, label}]} — so every analytic here works identically
against either one, and the FakeDriver exercises the Neo4j code path.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Mapping

from shared_models.dependency_semantics import propagates

AT_RISK_PREFIXES = ("EXPIRING",)
AT_RISK_STATUSES = ("EXPIRED",)


def _nodes_by_id(vis: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(node.get("id")): node for node in vis.get("nodes") or []}


def _edges(vis: Mapping[str, Any]) -> list[tuple[str, str, str]]:
    return [
        (str(edge.get("from")), str(edge.get("to")), str(edge.get("label") or "RELATED"))
        for edge in vis.get("edges") or []
    ]


def _kind(node: Mapping[str, Any]) -> str:
    return str(node.get("kind") or node.get("group") or "Node")


def _display(node: Mapping[str, Any], node_id: str) -> str:
    return str(node.get("label") or node.get("name") or node_id.split(":", 1)[-1])


# --------------------------------------------------------------------------- #
# dependency cycles (Tarjan SCC, iterative)
# --------------------------------------------------------------------------- #

def find_cycles(vis: Mapping[str, Any]) -> dict[str, Any]:
    """Strongly-connected components of size >1 (plus self-calls) in the
    System CALLS subgraph. Cycles block independent migration waves."""
    nodes = _nodes_by_id(vis)
    system_ids = {nid for nid, node in nodes.items() if _kind(node) == "System"}
    adjacency: dict[str, list[str]] = defaultdict(list)
    self_loops: set[str] = set()
    for src, dst, rel in _edges(vis):
        if not propagates(rel) or src not in system_ids or dst not in system_ids:
            continue
        if src == dst:
            self_loops.add(src)
            continue
        adjacency[src].append(dst)

    index_counter = [0]
    indices: dict[str, int] = {}
    lowlink: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    components: list[list[str]] = []

    for root in sorted(system_ids):
        if root in indices:
            continue
        work = [(root, iter(adjacency[root]))]
        indices[root] = lowlink[root] = index_counter[0]
        index_counter[0] += 1
        stack.append(root)
        on_stack.add(root)
        while work:
            node, neighbours = work[-1]
            advanced = False
            for nxt in neighbours:
                if nxt not in indices:
                    indices[nxt] = lowlink[nxt] = index_counter[0]
                    index_counter[0] += 1
                    stack.append(nxt)
                    on_stack.add(nxt)
                    work.append((nxt, iter(adjacency[nxt])))
                    advanced = True
                    break
                if nxt in on_stack:
                    lowlink[node] = min(lowlink[node], indices[nxt])
            if advanced:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                lowlink[parent] = min(lowlink[parent], lowlink[node])
            if lowlink[node] == indices[node]:
                component = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    component.append(member)
                    if member == node:
                        break
                components.append(component)

    cycles = []
    members_seen: set[str] = set()
    for component in components:
        if len(component) < 2:
            continue
        members = sorted(component)
        members_seen.update(members)
        cycles.append(
            {
                "members": members,
                "member_names": [_display(nodes[m], m) for m in members],
                "size": len(members),
                "self_loop": False,
            }
        )
    for nid in sorted(self_loops):
        members_seen.add(nid)
        cycles.append(
            {
                "members": [nid],
                "member_names": [_display(nodes[nid], nid)],
                "size": 1,
                "self_loop": True,
            }
        )
    cycles.sort(key=lambda row: (tuple(row["members"])))
    return {
        "cycles": cycles,
        "count": len(cycles),
        "systems_in_cycles": sorted(members_seen),
        "note": "systems in a cycle must be migration-sequenced together, not as independent waves",
    }


# --------------------------------------------------------------------------- #
# certificate expiry exposure
# --------------------------------------------------------------------------- #

def _is_at_risk(status: str | None) -> bool:
    token = str(status or "").upper()
    if not token or token in {"VALID", "OK", "NONE"}:
        return False
    return token.startswith(AT_RISK_PREFIXES) or token in AT_RISK_STATUSES


def certificate_exposure(vis: Mapping[str, Any]) -> dict[str, Any]:
    """Expiring / expired certificates mapped to the systems and process
    revenue they protect (via SECURED_BY + SUPPORTS edges)."""
    nodes = _nodes_by_id(vis)
    edges = _edges(vis)

    process_revenue: dict[str, float] = {}
    process_customers: dict[str, int] = {}
    for nid, node in nodes.items():
        if _kind(node) == "BusinessProcess":
            process_revenue[nid] = float(node.get("revenue_daily") or 0)
            process_customers[nid] = int(node.get("customer_count") or 0)

    supporters: dict[str, list[str]] = defaultdict(list)  # process -> systems
    systems_of_cert: dict[str, list[str]] = defaultdict(list)  # cert -> systems
    for src, dst, rel in edges:
        if rel == "SUPPORTS":
            supporters[dst].append(src)
        elif rel == "SECURED_BY":
            systems_of_cert[dst].append(src)

    def _system_impact(system_ids: list[str]) -> tuple[float, int]:
        revenue = 0.0
        customers = 0
        for process_id, system_list in supporters.items():
            if any(system in system_ids for system in system_list):
                revenue += process_revenue.get(process_id, 0.0)
                customers += process_customers.get(process_id, 0)
        return revenue, customers

    at_risk = []
    by_status: Counter[str] = Counter()
    unknown = 0
    healthy = 0
    affected: set[str] = set()
    total_revenue = 0.0
    total_customers = 0
    for nid, node in nodes.items():
        if _kind(node) != "Certificate":
            continue
        status = node.get("expiry_status")
        if status:
            by_status[str(status).upper()] += 1
        if not status:
            unknown += 1
            continue
        if not _is_at_risk(str(status)):
            healthy += 1
            continue
        system_ids = sorted(set(systems_of_cert.get(nid, [])))
        affected.update(system_ids)
        revenue, customers = _system_impact(system_ids)
        total_revenue += revenue
        total_customers += customers
        at_risk.append(
            {
                "cert_id": node.get("cert_id") or nid.split(":", 1)[-1],
                "subject": node.get("subject") or node.get("label"),
                "expiry_status": status,
                "not_after": node.get("not_after"),
                "systems": [
                    {"id": sid.split(":", 1)[-1], "name": _display(nodes[sid], sid), "criticality": nodes[sid].get("criticality")}
                    for sid in system_ids
                ],
                "revenue_daily_at_risk": revenue,
                "customers_at_risk": customers,
            }
        )
    at_risk.sort(key=lambda row: (-row["revenue_daily_at_risk"], str(row["cert_id"])))
    return {
        "at_risk": at_risk,
        "totals": {
            "certs_at_risk": len(at_risk),
            "healthy_certs": healthy,
            "certs_unknown_status": unknown,
            "systems_affected": len(affected),
            "revenue_daily_at_risk": total_revenue,
            "customers_at_risk": total_customers,
            "by_status": dict(sorted(by_status.items())),
        },
    }


# --------------------------------------------------------------------------- #
# graph summary stats
# --------------------------------------------------------------------------- #

def graph_stats(vis: Mapping[str, Any]) -> dict[str, Any]:
    """Node/edge composition plus graph-hygiene flags (orphan systems,
    unlinked crypto assets)."""
    nodes = _nodes_by_id(vis)
    edges = _edges(vis)
    nodes_by_kind: Counter[str] = Counter(_kind(node) for node in nodes.values())
    edges_by_relation: Counter[str] = Counter(rel for _s, _d, rel in edges)

    out_degree: Counter[str] = Counter()
    in_degree: Counter[str] = Counter()
    uses_out: set[str] = set()
    calls: set[tuple[str, str]] = set()
    for src, dst, rel in edges:
        out_degree[src] += 1
        in_degree[dst] += 1
        if rel == "USES":
            uses_out.add(src)
        elif propagates(rel) and src in nodes and dst in nodes and _kind(nodes[src]) == _kind(nodes[dst]) == "System":
            calls.add((src, dst))

    orphan_systems = []
    unlinked_assets = []
    for nid, node in nodes.items():
        kind = _kind(node)
        if kind == "System":
            has_calls = any(src == nid or dst == nid for src, dst in calls)
            if not has_calls and nid not in uses_out:
                orphan_systems.append(nid)
        elif kind == "CryptoAsset" and in_degree[nid] == 0:
            unlinked_assets.append(nid)

    busiest = max(out_degree, key=lambda nid: out_degree[nid]) if out_degree else None
    return {
        "nodes": len(nodes),
        "edges": len(edges),
        "nodes_by_kind": dict(sorted(nodes_by_kind.items())),
        "edges_by_relation": dict(sorted(edges_by_relation.items())),
        "systems": nodes_by_kind.get("System", 0),
        "orphan_system_count": len(orphan_systems),
        "orphan_systems": sorted(orphan_systems),
        "unlinked_asset_count": len(unlinked_assets),
        "unlinked_assets": sorted(unlinked_assets),
        "max_out_degree": (
            {"id": busiest, "label": _display(nodes[busiest], busiest), "degree": out_degree[busiest]}
            if busiest
            else None
        ),
        "hygiene_note": "orphan systems have no calls and no crypto; unlinked assets have no owning system in the graph",
    }
