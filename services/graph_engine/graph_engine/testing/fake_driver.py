"""In-memory Bolt stand-in that executes this service's Cypher dialect.

Used by unit tests and by the API when Neo4j is not running. The same query
strings go through Neo4jGraphStore either way.
"""

from __future__ import annotations

import re
from collections import deque
from typing import Any, Iterable

from graph_engine.schemas.node_schemas import IDENTITY_PROPERTY, KIND_PREFIX


def query_name(cypher: str) -> str:
    match = re.search(r"cryptoscan\.query=([a-z0-9_]+)", cypher)
    return match.group(1) if match else ""


class FakeRecord(dict):
    def data(self) -> dict[str, Any]:
        return dict(self)

    def get(self, key, default=None):  # noqa: A003
        return dict.get(self, key, default)

    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return dict.__getitem__(self, key)


class FakeResult:
    def __init__(self, rows: Iterable[dict[str, Any]]):
        self._rows = [row if isinstance(row, FakeRecord) else FakeRecord(row) for row in rows]

    def __iter__(self):
        return iter(self._rows)

    def single(self):
        return self._rows[0] if self._rows else None

    def data(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self._rows]

    def consume(self):
        return None


class InMemoryBoltGraph:
    def __init__(self) -> None:
        self.nodes: dict[tuple[str, str], dict[str, Any]] = {}
        self.edges: list[tuple[tuple[str, str], str, tuple[str, str], dict[str, Any]]] = []

    def upsert(self, label: str, key: str, props: dict[str, Any]) -> None:
        ident = IDENTITY_PROPERTY[label]
        value = str(props[ident] if ident in props else key)
        current = self.nodes.get((label, value), {ident: value, "_label": label})
        current.update({k: v for k, v in props.items() if v is not None})
        current["_label"] = label
        current[ident] = value
        self.nodes[(label, value)] = current

    def merge_edge(
        self,
        src_label: str,
        src_key: str,
        rel: str,
        dst_label: str,
        dst_key: str,
        props: dict[str, Any] | None = None,
    ) -> None:
        src = (src_label, str(src_key))
        dst = (dst_label, str(dst_key))
        if src not in self.nodes or dst not in self.nodes:
            return
        for existing_src, existing_rel, existing_dst, existing_props in self.edges:
            if existing_src == src and existing_dst == dst and existing_rel == rel:
                existing_props.update(props or {})
                return
        self.edges.append((src, rel, dst, dict(props or {})))

    def get(self, label: str, key: str) -> dict[str, Any] | None:
        return self.nodes.get((label, str(key)))

    def find_system(self, start: str) -> dict[str, Any] | None:
        node = self.get("System", start)
        if node:
            return node
        for (label, _key), props in self.nodes.items():
            if label == "System" and props.get("name") == start:
                return props
        return None

    def outgoing(self, label: str, key: str, rel: str) -> list[tuple[str, str]]:
        src = (label, str(key))
        return [(dst_label, dst_key) for (s, r, (dst_label, dst_key), _p) in self.edges if s == src and r == rel]

    def incoming(self, label: str, key: str, rel: str) -> list[tuple[str, str]]:
        dst = (label, str(key))
        return [(src_label, src_key) for ((src_label, src_key), r, d, _p) in self.edges if d == dst and r == rel]


class FakeSession:
    def __init__(self, graph: InMemoryBoltGraph):
        self.graph = graph
        self.closed = False
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __enter__(self) -> "FakeSession":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        self.closed = True

    def run(self, query: str, parameters: dict[str, Any] | None = None, **kwargs) -> FakeResult:
        params = dict(parameters or {})
        params.update(kwargs)
        self.calls.append((query_name(query) or query[:40], params))
        name = query_name(query)
        if query.strip().upper().startswith("CREATE CONSTRAINT") or query.strip().upper().startswith("CREATE INDEX"):
            return FakeResult([])
        handler = {
            "merge_systems": self._merge_nodes,
            "merge_assets": self._merge_nodes,
            "merge_processes": self._merge_nodes,
            "merge_owners": self._merge_nodes,
            "merge_scopes": self._merge_nodes,
            "merge_vendors": self._merge_nodes,
            "merge_certs": self._merge_nodes,
            "merge_cloud": self._merge_nodes,
            "merge_uses": self._merge_uses,
            "merge_calls": self._merge_calls,
            "merge_supports": self._merge_supports,
            "merge_owned_by": self._merge_owned,
            "merge_comply": self._merge_comply,
            "merge_vendor_edge": self._merge_vendor,
            "merge_secured_by": self._merge_secured,
            "merge_deployed_on": self._merge_deployed,
            "blast_radius": self._blast,
            "systems_using_asset": self._systems_using_asset,
            "origin_system": self._origin,
            "business_impact": self._impact,
            "compliance_inheritance": self._compliance,
            "vendor_path": self._vendor_path,
            "crypto_inventory": self._crypto,
            "export_vis": self._export,
            "count_nodes": lambda _p: [{"nodes": len(self.graph.nodes)}],
            "count_edges": lambda _p: [{"edges": len(self.graph.edges)}],
            "ping": lambda _p: [{"ok": 1}],
        }.get(name)
        if handler is None:
            if "RETURN 1 AS ok" in query.replace("\n", " "):
                return FakeResult([{"ok": 1}])
            return FakeResult([])
        rows = handler(params)
        return FakeResult(rows or [])

    def _merge_nodes(self, params: dict[str, Any]) -> list:
        rows = params.get("rows") or []
        if not rows:
            return []
        label = self._guess_label(rows[0])
        if not label:
            return []
        ident = IDENTITY_PROPERTY[label]
        for row in rows:
            self.graph.upsert(label, str(row[ident]), row)
        return []

    def _guess_label(self, row: dict[str, Any]) -> str | None:
        for label, ident in IDENTITY_PROPERTY.items():
            if ident in row:
                return label
        return None

    def _merge_uses(self, params):
        for row in params.get("rows") or []:
            self.graph.merge_edge("System", row["system_id"], "USES", "CryptoAsset", row["asset_id"], {"usage_type": row.get("usage_type")})
        return []

    def _merge_calls(self, params):
        for row in params.get("rows") or []:
            self.graph.merge_edge(
                "System",
                row["parent_id"],
                "CALLS",
                "System",
                row["child_id"],
                {"protocol": row.get("protocol"), "frequency": row.get("frequency")},
            )
        return []

    def _merge_supports(self, params):
        for row in params.get("rows") or []:
            self.graph.merge_edge("System", row["system_id"], "SUPPORTS", "BusinessProcess", row["process_id"])
        return []

    def _merge_owned(self, params):
        for row in params.get("rows") or []:
            self.graph.merge_edge("System", row["system_id"], "OWNED_BY", "BusinessOwner", row["owner_id"])
        return []

    def _merge_comply(self, params):
        for row in params.get("rows") or []:
            self.graph.merge_edge("System", row["system_id"], "MUST_COMPLY_WITH", "ComplianceScope", row["standard_name"])
        return []

    def _merge_vendor(self, params):
        for row in params.get("rows") or []:
            self.graph.merge_edge(
                "System",
                row["system_id"],
                "DEPENDS_ON_VENDOR",
                "Vendor",
                row["vendor_id"],
                {"dependency_type": row.get("dependency_type")},
            )
        return []

    def _merge_secured(self, params):
        for row in params.get("rows") or []:
            self.graph.merge_edge(
                "System",
                row["system_id"],
                "SECURED_BY",
                "Certificate",
                row["cert_id"],
                {"endpoint": row.get("endpoint")},
            )
        return []

    def _merge_deployed(self, params):
        for row in params.get("rows") or []:
            self.graph.merge_edge("System", row["system_id"], "DEPLOYED_ON", "CloudResource", row["resource_id"])
        return []

    def _origin(self, params):
        node = self.graph.find_system(str(params.get("start") or ""))
        if not node:
            return []
        return [{"id": node["system_id"], "name": node.get("name")}]

    def _systems_using_asset(self, params):
        start = str(params.get("start") or "")
        rows = []
        for (label, key), props in self.graph.nodes.items():
            if label != "CryptoAsset":
                continue
            if props.get("asset_id") == start or props.get("algorithm") == start:
                for src_label, src_key in self.graph.incoming("CryptoAsset", key, "USES"):
                    system = self.graph.get(src_label, src_key) or {}
                    rows.append({"id": system.get("system_id") or src_key, "name": system.get("name")})
        return rows

    def _blast(self, params):
        start = self.graph.find_system(str(params.get("start") or ""))
        if not start:
            return []
        hops = int(params.get("hops") or 5)
        seen: dict[str, int] = {start["system_id"]: 0}
        queue = deque([start["system_id"]])
        while queue:
            current = queue.popleft()
            depth = seen[current]
            if depth >= hops:
                continue
            for _label, nxt in self.graph.outgoing("System", current, "CALLS"):
                if nxt not in seen:
                    seen[nxt] = depth + 1
                    queue.append(nxt)
        rows = []
        for sid, depth in seen.items():
            if depth == 0:
                continue
            node = self.graph.get("System", sid) or {}
            rows.append(
                {
                    "id": sid,
                    "name": node.get("name"),
                    "criticality": node.get("criticality"),
                    "hops": depth,
                }
            )
        rows.sort(key=lambda row: (row["hops"], row.get("name") or ""))
        return rows

    def _impact(self, params):
        system_ids = [str(item) for item in (params.get("system_ids") or [])]
        processes, revenues, customers, owners, scopes = [], [], [], [], []
        seen_p, seen_o, seen_s = set(), set(), set()
        for sid in system_ids:
            for _label, pid in self.graph.outgoing("System", sid, "SUPPORTS"):
                proc = self.graph.get("BusinessProcess", pid) or {}
                name = proc.get("name")
                if name and name not in seen_p:
                    seen_p.add(name)
                    processes.append(name)
                    revenues.append(float(proc.get("revenue_daily") or 0))
                    customers.append(int(proc.get("customer_count") or 0))
            for _label, oid in self.graph.outgoing("System", sid, "OWNED_BY"):
                owner = self.graph.get("BusinessOwner", oid) or {}
                name = owner.get("name")
                if name and name not in seen_o:
                    seen_o.add(name)
                    owners.append(name)
            for _label, scope in self.graph.outgoing("System", sid, "MUST_COMPLY_WITH"):
                if scope and scope not in seen_s:
                    seen_s.add(scope)
                    scopes.append(scope)
        return [
            {
                "processes": processes,
                "revenues": revenues,
                "customers": customers,
                "owners": owners,
                "scopes": scopes,
            }
        ]

    def _compliance(self, params):
        scopes = []
        seen = set()
        for sid in params.get("system_ids") or []:
            for _label, scope in self.graph.outgoing("System", str(sid), "MUST_COMPLY_WITH"):
                if scope not in seen:
                    seen.add(scope)
                    scopes.append(scope)
        return [{"scopes": scopes}]

    def _vendor_path(self, params):
        start = self.graph.find_system(str(params.get("start") or ""))
        if not start:
            return []
        # BFS along CALLS, then a DEPENDS_ON_VENDOR hop.
        parent: dict[str, str | None] = {start["system_id"]: None}
        queue = deque([start["system_id"]])
        found_vendor = None
        found_sys = None
        while queue:
            current = queue.popleft()
            for _label, vid in self.graph.outgoing("System", current, "DEPENDS_ON_VENDOR"):
                found_vendor = vid
                found_sys = current
                queue.clear()
                break
            else:
                for _label, nxt in self.graph.outgoing("System", current, "CALLS"):
                    if nxt not in parent:
                        parent[nxt] = current
                        queue.append(nxt)
        if not found_vendor:
            return []
        chain = [found_sys]
        while chain[-1] and parent.get(chain[-1]) is not None:
            chain.append(parent[chain[-1]])
        chain.reverse()
        names = []
        for sid in chain:
            node = self.graph.get("System", sid or "") or {}
            names.append(node.get("name") or sid)
        vendor = self.graph.get("Vendor", found_vendor) or {}
        names.append(vendor.get("name") or found_vendor)
        return [
            {
                "names": names,
                "hops": max(0, len(names) - 1),
                "vendor": vendor.get("name"),
                "vendor_id": found_vendor,
            }
        ]

    def _crypto(self, params):
        start = self.graph.find_system(str(params.get("start") or ""))
        if not start:
            return []
        rows = []
        for _label, aid in self.graph.outgoing("System", start["system_id"], "USES"):
            asset = self.graph.get("CryptoAsset", aid) or {}
            rows.append(
                {
                    "id": aid,
                    "algorithm": asset.get("algorithm"),
                    "purpose": asset.get("purpose"),
                    "confidence": asset.get("confidence"),
                    "key_size": asset.get("key_size"),
                    "usage_type": "DISCOVERED",
                }
            )
        return rows

    def _export(self, params):
        rows = []
        emitted = set()
        for (label, key), props in self.graph.nodes.items():
            prefix = KIND_PREFIX.get(label, label.lower())
            node = {"_label": label, **props, "id": f"{prefix}:{key}"}
            emitted.add((label, key))
            related = False
            for (src_label, src_key), rel, (dst_label, dst_key), _p in self.graph.edges:
                if (src_label, src_key) != (label, key):
                    continue
                related = True
                dst = self.graph.get(dst_label, dst_key) or {}
                dst_prefix = KIND_PREFIX.get(dst_label, dst_label.lower())
                rows.append(
                    {
                        "n": node,
                        "r": {"type": rel},
                        "m": {"_label": dst_label, **dst, "id": f"{dst_prefix}:{dst_key}"},
                    }
                )
            if not related:
                rows.append({"n": node, "r": None, "m": None})
        return rows


class FakeDriver:
    def __init__(self) -> None:
        self.graph = InMemoryBoltGraph()
        self.closed = False

    def session(self, database: str | None = None) -> FakeSession:
        return FakeSession(self.graph)

    def verify_connectivity(self) -> bool:
        return True

    def close(self) -> None:
        self.closed = True



