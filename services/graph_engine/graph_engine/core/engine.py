"""Directed system / asset / process graph with blast-radius queries."""

from __future__ import annotations

import re
from collections import defaultdict, deque
from typing import Any, Iterable

# Word-boundary tokens: kept for backward compatibility (token-level matching).
# New code must use shared_models.quantum_classify.is_shor_vulnerable — the
# registry-backed single classifier (better: JOSE/TLS-suite/curve aware).
QUANTUM_VULNERABLE_RE = re.compile(
    r"\b(rsa|ec|ecc|ecdh|ecdsa|dsa|dh|x25519|ed25519|ed448|diffie|hellman|secp[a-z0-9]*|elliptic)\b",
    re.IGNORECASE,
)


def _is_shor_vulnerable(algorithm: str | None) -> bool:
    try:
        from shared_models.quantum_classify import is_shor_vulnerable
    except Exception:  # shared_models not on path: fall back to the token matcher
        return bool(algorithm and QUANTUM_VULNERABLE_RE.search(str(algorithm)))
    return is_shor_vulnerable(algorithm)


class GraphEngine:
    backend = "memory"

    @classmethod
    def from_vis(cls, vis: dict[str, Any]) -> "GraphEngine":
        """Load a graph from any backend's vis export (nodes + edges)."""
        engine = cls()
        for node in vis.get("nodes") or []:
            node_id = str(node.get("id") or "")
            if not node_id:
                continue
            props = {k: v for k, v in node.items() if k not in {"id", "group", "kind", "label"}}
            engine.add_node(node_id, kind=str(node.get("kind") or node.get("group") or "Node"), **props)
        for edge in vis.get("edges") or []:
            engine.add_edge(str(edge.get("from") or ""), str(edge.get("to") or ""), str(edge.get("label") or "RELATED"))
        return engine

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
        cloud_resources: Iterable[dict[str, Any]] = (),
        network_resources: Iterable[dict[str, Any]] = (),
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
                **({"source": system["source"]} if system.get("source") else {}),
                **({"code_cascade": system["code_cascade"]} if system.get("code_cascade") else {}),
            )
            for scope in system.get("compliance_scopes") or []:
                self.add_node(f"scope:{scope}", kind="ComplianceScope", name=scope, standard_name=scope)
                self.add_edge(f"system:{sid}", f"scope:{scope}", "MUST_COMPLY_WITH")
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
                name=cert.get("subject"),
                subject=cert.get("subject"),
                expiry_status=cert.get("expiry_status"),
            )
            for system_id in cert.get("system_ids") or []:
                self.add_edge(f"system:{system_id}", f"cert:{cid}", "SECURED_BY")
        for resource in cloud_resources:
            rid = str(resource.get("id") or resource.get("resource_id") or resource.get("account_identifier") or "")
            if not rid:
                continue
            self.add_node(
                f"cloud:{rid}",
                kind="CloudResource",
                name=resource.get("name") or resource.get("account_identifier"),
                cloud_provider=resource.get("cloud_provider"),
            )
            for system_id in resource.get("system_ids") or []:
                self.add_edge(f"system:{system_id}", f"cloud:{rid}", "DEPLOYED_ON")
        for resource in network_resources:
            rid = str(resource.get("id") or resource.get("endpoint") or resource.get("resource_id") or "")
            if not rid:
                continue
            self.add_node(
                f"network:{rid}",
                kind="NetworkResource",
                name=resource.get("name") or resource.get("endpoint"),
                endpoint=resource.get("endpoint"),
                resource_type=resource.get("resource_type") or "TLS_ENDPOINT",
            )
            for system_id in resource.get("system_ids") or []:
                self.add_edge(f"system:{system_id}", f"network:{rid}", "CONNECTS_TO")
        return self

    def blast_radius(self, start_id: str, *, hops: int = 5) -> dict[str, Any]:
        start = self._resolve(start_id)
        if start is None:
            return {"start": start_id, "systems": [], "hops": hops, "nodes_visited": 0, "backend": self.backend}
        if (self.nodes.get(start) or {}).get("kind") == "CryptoAsset":
            users = [src for src, rel in self.incoming.get(start, []) if rel == "USES"]
            start = users[0] if users else start
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
        return {
            "start": start.split(":", 1)[-1],
            "systems": systems,
            "hops": hops,
            "nodes_visited": len(seen),
            "backend": self.backend,
        }

    def business_impact(self, start_id: str, *, hops: int = 5) -> dict[str, Any]:
        radius = self.blast_radius(start_id, hops=hops)
        seed = self._resolve(radius["start"] or start_id)
        system_ids = {f"system:{row['id']}" for row in radius["systems"]}
        if seed and (self.nodes.get(seed) or {}).get("kind") == "System":
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
            "backend": self.backend,
        }

    def compliance_inheritance(self, start_id: str, *, hops: int = 5) -> dict[str, Any]:
        impact = self.business_impact(start_id, hops=hops)
        return {"start": impact["start"], "scopes": impact["compliance_scopes"], "backend": self.backend}

    def vendor_path(self, start_id: str) -> dict[str, Any]:
        start = self._resolve(start_id)
        if start is None:
            return {"start": start_id, "path": [], "hops": 0, "vendor": None, "backend": self.backend}
        parent: dict[str, str | None] = {start: None}
        queue = deque([start])
        found_vendor = None
        found_at = None
        while queue:
            node = queue.popleft()
            for nxt, rel in self.out.get(node, []):
                if rel == "DEPENDS_ON_VENDOR":
                    found_vendor = nxt
                    found_at = node
                    queue.clear()
                    break
                if rel == "CALLS" and nxt not in parent:
                    parent[nxt] = node
                    queue.append(nxt)
        if not found_vendor:
            return {"start": start.split(":", 1)[-1], "path": [], "hops": 0, "vendor": None, "backend": self.backend}
        chain = [found_at]
        while chain[-1] and parent.get(chain[-1]) is not None:
            chain.append(parent[chain[-1]])
        chain.reverse()
        names = [(self.nodes.get(item) or {}).get("name") or item.split(":", 1)[-1] for item in chain if item]
        vendor = self.nodes.get(found_vendor) or {}
        names.append(vendor.get("name") or found_vendor.split(":", 1)[-1])
        return {
            "start": start.split(":", 1)[-1],
            "path": names,
            "hops": max(0, len(names) - 1),
            "vendor": vendor.get("name"),
            "vendor_id": found_vendor.split(":", 1)[-1],
            "backend": self.backend,
        }

    def vendor_chain(self, start_id: str) -> dict[str, Any]:
        """Vendor → product → assets → crypto chain (downstream).

        Starts at a Vendor node and walks the *real* edges the backend built:
        systems that DEPEND_ON_VENDOR the vendor, the crypto assets those
        systems USES, and (optionally) the business processes those systems
        SUPPORT. Returns nothing but real graph edges — no invented links.
        """
        if (self.nodes.get(start_id) or {}).get("kind") != "Vendor":
            # Allow the caller to pass a bare vendor id or name.
            start_id = self._resolve(start_id) or start_id
            if (self.nodes.get(start_id) or {}).get("kind") != "Vendor":
                return {"start": start_id, "vendor": None, "systems": [], "count": 0, "backend": self.backend}
        vendor_node = self.nodes.get(start_id) or {}
        dependent_systems = [
            src for src, rel in self.incoming.get(start_id, []) if rel == "DEPENDS_ON_VENDOR"
        ]
        systems = []
        seen_systems: set[str] = set()
        for sys_id in dependent_systems:
            if sys_id in seen_systems:
                continue
            seen_systems.add(sys_id)
            node = self.nodes.get(sys_id) or {}
            assets = []
            seen_assets: set[str] = set()
            for nxt, rel in self.out.get(sys_id, []):
                if rel != "USES" or nxt in seen_assets:
                    continue
                seen_assets.add(nxt)
                a = self.nodes.get(nxt) or {}
                assets.append({
                    "id": nxt.split(":", 1)[-1],
                    "algorithm": a.get("algorithm"),
                    "purpose": a.get("purpose"),
                    "confidence": a.get("confidence"),
                    "key_size": a.get("key_size"),
                    "file_path": a.get("file_path"),
                    "risk": "vulnerable" if _is_shor_vulnerable(str(a.get("algorithm"))) else "ready",
                })
            processes = [
                {"id": (self.nodes.get(p) or {}).get("name") or p.split(":", 1)[-1]}
                for p, rel in self.out.get(sys_id, []) if rel == "SUPPORTS"
            ]
            systems.append({
                "id": sys_id.split(":", 1)[-1],
                "name": node.get("name"),
                "criticality": node.get("criticality"),
                "assets": assets,
                "asset_count": len(assets),
                "processes": processes,
            })
        systems.sort(key=lambda row: (-row["asset_count"], row.get("name") or ""))
        return {
            "start": start_id.split(":", 1)[-1],
            "vendor": {"id": start_id.split(":", 1)[-1], "name": vendor_node.get("name")},
            "product": vendor_node.get("name") or start_id.split(":", 1)[-1],
            "systems": systems,
            "count": len(systems),
            "total_assets": sum(s["asset_count"] for s in systems),
            "backend": self.backend,
        }

    def vendor_chains(self, *, limit: int = 100) -> dict[str, Any]:
        """All vendors with their downstream chains (for the chain view)."""
        chains = []
        for node_id, node in self.nodes.items():
            if node.get("kind") != "Vendor":
                continue
            chains.append(self.vendor_chain(node_id))
            if len(chains) >= limit:
                break
        chains.sort(key=lambda c: (-c["total_assets"], c["vendor"]["name"] or ""))
        return {"chains": chains, "count": len(chains), "backend": self.backend}

    def dependents(self, start_id: str, *, hops: int = 5) -> dict[str, Any]:
        """Reverse blast radius: everything upstream that depends on this node."""
        start = self._resolve(start_id)
        if start is None:
            return {"start": start_id, "systems": [], "hops": hops, "nodes_visited": 0, "backend": self.backend}
        if (self.nodes.get(start) or {}).get("kind") == "CryptoAsset":
            users = [src for src, rel in self.incoming.get(start, []) if rel == "USES"]
            start = users[0] if users else start
        seen: dict[str, int] = {start: 0}
        queue = deque([start])
        while queue:
            node = queue.popleft()
            depth = seen[node]
            if depth >= hops:
                continue
            for prev, _rel in self.incoming.get(node, []):
                if prev not in seen:
                    seen[prev] = depth + 1
                    queue.append(prev)
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
        return {
            "start": start.split(":", 1)[-1],
            "systems": systems,
            "hops": hops,
            "nodes_visited": len(seen),
            "backend": self.backend,
        }

    def shortest_path(self, start_id: str, target_id: str, *, direction: str = "downstream") -> dict[str, Any]:
        """Shortest CALLS path between two systems. Honest when unreachable."""
        start = self._resolve(start_id)
        target = self._resolve(target_id)
        resolved_start = start is not None
        resolved_target = target is not None
        names: list[str] = []
        path_hops = None
        if resolved_start and resolved_target:
            adjacency = self.out if direction != "upstream" else self.incoming
            if start == target:
                names = [self._display(start)]
                path_hops = 0
            else:
                parent: dict[str, str | None] = {start: None}
                queue = deque([start])
                found = False
                while queue and not found:
                    node = queue.popleft()
                    for nxt, rel in adjacency.get(node, []):
                        if rel != "CALLS" or nxt in parent:
                            continue
                        parent[nxt] = node
                        if nxt == target:
                            found = True
                            break
                        queue.append(nxt)
                if found:
                    chain = [target]
                    while parent.get(chain[-1]) is not None:
                        chain.append(parent[chain[-1]])  # type: ignore[arg-type]
                    chain.reverse()
                    names = [self._display(item) for item in chain]
                    path_hops = len(names) - 1
        return {
            "start": self._display(start) if resolved_start else start_id,
            "target": self._display(target) if resolved_target else target_id,
            "direction": "upstream" if direction == "upstream" else "downstream",
            "resolved_start": resolved_start,
            "resolved_target": resolved_target,
            "reachable": path_hops is not None,
            "hops": path_hops,
            "path": names,
            "backend": self.backend,
        }

    def crypto_hotspots(self) -> dict[str, Any]:
        """Systems ranked by quantum-vulnerable crypto concentration."""
        rows = []
        for node_id, node in self.nodes.items():
            if node.get("kind") != "System":
                continue
            algorithms = [
                (self.nodes.get(nxt) or {}).get("algorithm")
                for nxt, rel in self.out.get(node_id, [])
                if rel == "USES"
            ]
            algorithms = [algo for algo in algorithms if algo]
            if not algorithms:
                continue
            vulnerable = sorted({str(a) for a in algorithms if _is_shor_vulnerable(str(a))})
            rows.append(
                {
                    "system_id": node_id.split(":", 1)[-1],
                    "name": node.get("name"),
                    "criticality": node.get("criticality"),
                    "total_assets": len(algorithms),
                    "quantum_vulnerable_assets": sum(1 for a in algorithms if _is_shor_vulnerable(str(a))),
                    "vulnerable_algorithms": vulnerable,
                }
            )
        rows.sort(key=lambda row: (-row["quantum_vulnerable_assets"], -row["total_assets"], row.get("name") or ""))
        return {
            "hotspots": rows,
            "count": len(rows),
            "systems_with_assets": len(rows),
            "ranking": "quantum_vulnerable desc, total assets desc, name",
            "backend": self.backend,
        }

    def diff(self, other: "GraphEngine") -> dict[str, Any]:
        """Structural diff self -> other (other is the newer state)."""
        my_nodes = set(self.nodes)
        other_nodes = set(other.nodes)
        my_edges = {(src, dst, rel) for src, items in self.out.items() for dst, rel in items}
        other_edges = {(src, dst, rel) for src, items in other.out.items() for dst, rel in items}
        nodes_added = sorted(other_nodes - my_nodes)
        nodes_removed = sorted(my_nodes - other_nodes)
        edges_added = sorted(other_edges - my_edges)
        edges_removed = sorted(my_edges - other_edges)
        return {
            "nodes_added": nodes_added,
            "nodes_removed": nodes_removed,
            "edges_added": edges_added,
            "edges_removed": edges_removed,
            "counts": {
                "nodes_added": len(nodes_added),
                "nodes_removed": len(nodes_removed),
                "edges_added": len(edges_added),
                "edges_removed": len(edges_removed),
            },
            "changed": bool(nodes_added or nodes_removed or edges_added or edges_removed),
        }

    def _display(self, node_id: str) -> str:
        return str((self.nodes.get(node_id) or {}).get("name") or node_id.split(":", 1)[-1])

    def crypto_for_system(self, start_id: str) -> dict[str, Any]:
        start = self._resolve(start_id)
        assets = []
        if start:
            for nxt, rel in self.out.get(start, []):
                if rel != "USES":
                    continue
                node = self.nodes.get(nxt) or {}
                assets.append(
                    {
                        "id": nxt.split(":", 1)[-1],
                        "algorithm": node.get("algorithm"),
                        "purpose": node.get("purpose"),
                        "confidence": node.get("confidence"),
                        "key_size": node.get("key_size"),
                        "usage_type": "DISCOVERED",
                    }
                )
        return {"start": start_id, "assets": assets, "count": len(assets), "backend": self.backend}

    def find_cycles(self) -> dict[str, Any]:
        from graph_engine.core.analytics import find_cycles

        result = find_cycles(self.to_vis())
        result["backend"] = self.backend
        return result

    def certificate_exposure(self) -> dict[str, Any]:
        from graph_engine.core.analytics import certificate_exposure

        result = certificate_exposure(self.to_vis())
        result["backend"] = self.backend
        return result

    def graph_stats(self) -> dict[str, Any]:
        from graph_engine.core.analytics import graph_stats

        result = graph_stats(self.to_vis())
        result["backend"] = self.backend
        return result

    def counts(self) -> dict[str, int]:
        return {"nodes": len(self.nodes), "edges": sum(len(items) for items in self.out.values())}

    def to_vis(self) -> dict[str, Any]:
        nodes = [
            {"id": node_id, "label": node.get("name") or node_id, "group": node.get("kind"), **{k: v for k, v in node.items() if k not in {"id"}}}
            for node_id, node in self.nodes.items()
        ]
        edges = []
        for src, items in self.out.items():
            for dst, rel in items:
                edges.append({"from": src, "to": dst, "label": rel})
        return {"nodes": nodes, "edges": edges, "backend": self.backend}

    def _resolve(self, raw: str) -> str | None:
        if raw in self.nodes:
            return raw
        for prefix in ("system:", "asset:", "process:", "cert:", "vendor:", "owner:", "scope:", "cloud:"):
            if f"{prefix}{raw}" in self.nodes:
                return f"{prefix}{raw}"
        for node_id, node in self.nodes.items():
            if node.get("name") == raw:
                return node_id
        return None
