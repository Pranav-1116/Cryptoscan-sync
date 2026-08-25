"""Directed system / asset / process graph with blast-radius queries."""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any, Iterable


class GraphEngine:
    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.out: dict[str, list[tuple[str, str]]] = defaultdict(list)
        self.incoming: dict[str, list[tuple[str, str]]] = defaultdict(list)

    def add_node(self, node_id: str, *, kind: str, **props: Any) -> None:
        current = self.nodes.get(node_id, {"id": node_id, "kind": kind})
        current.update(props)
        current["kind"] = kind
        current["id"] = node_id
        self.nodes[node_id] = current

    def add_edge(self, src: str, dst: str, relation: str = "CALLS") -> None:
        if (dst, relation) not in self.out[src]:
            self.out[src].append((dst, relation))
        if (src, relation) not in self.incoming[dst]:
            self.incoming[dst].append((src, relation))

    def build(
        self,
        *,
        systems: Iterable[dict[str, Any]] = (),
        assets: Iterable[dict[str, Any]] = (),
        edges: Iterable[dict[str, Any]] = (),
        processes: Iterable[dict[str, Any]] = (),
        owners: Iterable[dict[str, Any]] = (),
        vendors: Iterable[dict[str, Any]] = (),
        certificates: Iterable[dict[str, Any]] = (),
    ) -> "GraphEngine":
        for system in systems:
            sid = str(system.get("id") or system.get("system_id") or system.get("name"))
            self.add_node(
                f"system:{sid}",
                kind="System",
                name=system.get("name"),
                environment=system.get("environment"),
                owner=system.get("owner"),
                criticality=system.get("criticality") or (system.get("extra") or {}).get("criticality"),
                compliance_scopes=system.get("compliance_scopes") or [],
            )
        for asset in assets:
            aid = str(asset.get("id") or asset.get("asset_id"))
            self.add_node(
                f"asset:{aid}",
                kind="CryptoAsset",
                algorithm=asset.get("algorithm"),
                purpose=asset.get("purpose"),
                confidence=asset.get("confidence"),
                file_path=asset.get("file_path"),
            )
            system_id = asset.get("system_id")
            if system_id:
                self.add_edge(f"system:{system_id}", f"asset:{aid}", "USES")
        for edge in edges:
            parent = edge.get("parent_id") or edge.get("from")
            child = edge.get("child_id") or edge.get("to")
            if parent and child:
                self.add_edge(f"system:{parent}", f"system:{child}", edge.get("relation") or "CALLS")
        for process in processes:
            pid = str(process.get("id") or process.get("process_id") or process.get("name"))
            self.add_node(
                f"process:{pid}",
                kind="BusinessProcess",
                name=process.get("name") or process.get("process_name"),
                revenue_daily=float(process.get("revenue_daily") or 0),
                customer_count=int(process.get("customer_count") or 0),
            )
            for system_id in process.get("system_ids") or []:
                self.add_edge(f"system:{system_id}", f"process:{pid}", "SUPPORTS")
        for owner in owners:
            oid = str(owner.get("id") or owner.get("email") or owner.get("name"))
            self.add_node(f"owner:{oid}", kind="BusinessOwner", name=owner.get("name"), email=owner.get("email"))
            for system_id in owner.get("system_ids") or []:
                self.add_edge(f"system:{system_id}", f"owner:{oid}", "OWNED_BY")
        for vendor in vendors:
            vid = str(vendor.get("id") or vendor.get("name"))
            self.add_node(f"vendor:{vid}", kind="Vendor", name=vendor.get("name"), criticality=vendor.get("criticality"))
            for system_id in vendor.get("system_ids") or []:
                self.add_edge(f"system:{system_id}", f"vendor:{vid}", "DEPENDS_ON_VENDOR")
        for cert in certificates:
            cid = str(cert.get("id") or cert.get("fingerprint_sha256") or cert.get("subject"))
            self.add_node(
                f"cert:{cid}",
                kind="Certificate",
                subject=cert.get("subject"),
                expiry_status=cert.get("expiry_status"),
            )
        return self

    def blast_radius(self, start_id: str, *, hops: int = 5) -> dict[str, Any]:
        start = self._resolve(start_id)
        if start is None:
            return {"start": start_id, "systems": [], "hops": 0}
        seen: dict[str, int] = {start: 0}
        queue = deque([start])
        while queue:
            node = queue.popleft()
            depth = seen[node]
            if depth >= hops:
                continue
            for nxt, _rel in self.out.get(node, []):
                if nxt not in seen:
                    seen[nxt] = depth + 1
                    queue.append(nxt)
        systems = []
        for node_id, depth in seen.items():
            node = self.nodes.get(node_id) or {}
            if node.get("kind") == "System" and node_id != start:
                systems.append(
                    {
                        "id": node_id.split(":", 1)[-1],
                        "name": node.get("name"),
                        "criticality": node.get("criticality"),
                        "hops": depth,
                    }
                )
        systems.sort(key=lambda row: (row["hops"], row.get("name") or ""))
        return {"start": start.split(":", 1)[-1], "systems": systems, "hops": hops, "nodes_visited": len(seen)}

    def business_impact(self, start_id: str, *, hops: int = 5) -> dict[str, Any]:
        radius = self.blast_radius(start_id, hops=hops)
        seed = self._resolve(start_id)
        system_ids = {f"system:{row['id']}" for row in radius["systems"]}
        if seed:
            system_ids.add(seed)
        revenue = 0.0
        customers = 0
        processes: list[str] = []
        owners: list[str] = []
        scopes: set[str] = set()
        for node_id, node in self.nodes.items():
            if node.get("kind") == "BusinessProcess":
                supporters = [src for src, rel in self.incoming.get(node_id, []) if rel == "SUPPORTS"]
                if any(src in system_ids for src in supporters):
                    revenue += float(node.get("revenue_daily") or 0)
                    customers += int(node.get("customer_count") or 0)
                    if node.get("name"):
                        processes.append(node["name"])
            if node.get("kind") == "BusinessOwner":
                if any(src in system_ids for src, rel in self.incoming.get(node_id, []) if rel == "OWNED_BY"):
                    if node.get("name"):
                        owners.append(node["name"])
        for sid in system_ids:
            scopes.update((self.nodes.get(sid) or {}).get("compliance_scopes") or [])
        return {
            "start": radius["start"],
            "total_revenue_at_risk": revenue,
            "total_customers_at_risk": customers,
            "affected_processes": processes,
            "business_owners": owners,
            "compliance_scopes": sorted(scopes),
            "systems": radius["systems"],
        }

    def to_vis(self) -> dict[str, Any]:
        nodes = [
            {"id": node_id, "label": node.get("name") or node_id, "group": node.get("kind"), **{k: v for k, v in node.items() if k not in {"id"}}}
            for node_id, node in self.nodes.items()
        ]
        edges = []
        for src, items in self.out.items():
            for dst, rel in items:
                edges.append({"from": src, "to": dst, "label": rel})
        return {"nodes": nodes, "edges": edges}

    def _resolve(self, raw: str) -> str | None:
        if raw in self.nodes:
            return raw
        for prefix in ("system:", "asset:", "process:", "cert:", "vendor:"):
            if f"{prefix}{raw}" in self.nodes:
                return f"{prefix}{raw}"
        for node_id, node in self.nodes.items():
            if node.get("name") == raw:
                return node_id
        return None
