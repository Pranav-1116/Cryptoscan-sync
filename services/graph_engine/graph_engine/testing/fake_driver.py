"""In-memory Bolt test double dispatching tagged queries to Python handlers.

It does not parse/execute Cypher and cannot qualify a real Neo4j deployment.
The adapter sends the same query text and parameters to this double in tests.
"""

from __future__ import annotations
from shared_models.relationship_lifecycle import FIELDS

import re
from collections import deque
from typing import Any, Iterable

from shared_models.dependency_semantics import MAX_SYSTEM_HOPS, normalize_relation

from graph_engine.core.engine import _is_shor_vulnerable
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
        if label == "BusinessProcess":
            for field in ("revenue_daily", "customer_count"):
                if field in props and props[field] is None:
                    current.pop(field, None)
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
                if rel == "CALLS" and existing_props.get("relation") != (props or {}).get("relation"):
                    continue
                if rel == "CALLS" and existing_props.get("lifecycle_revision") is not None and ((props or {}).get("lifecycle_revision") is None or existing_props["lifecycle_revision"] > (props or {})["lifecycle_revision"]):
                    return
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
        if name == "prune_kind":
            match = re.search(r"MATCH \(n:(\w+)\)", query)
            # the keep-set property is the one feeding IN $ids (round 35:
            # tenant predicates come first in the WHERE clause, so anchor
            # on the IN clause, not on the first n.<prop> after MATCH)
            prop_match = re.search(r"n\.(\w+) IN \$ids", query)
            params["_prune_label"] = match.group(1) if match else None
            params["_prune_prop"] = prop_match.group(1) if prop_match else None
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
            "merge_network": self._merge_nodes,
            "merge_containers": self._merge_nodes,
            "merge_uses": self._merge_uses,
            "merge_calls": self._merge_calls,
            "quarantine_legacy_calls": self._quarantine_legacy_calls,
            "merge_supports": self._merge_supports,
            "merge_owned_by": self._merge_owned,
            "merge_comply": self._merge_comply,
            "merge_vendor_edge": self._merge_vendor,
            "merge_secured_by": self._merge_secured,
            "merge_deployed_on": self._merge_deployed,
            "merge_connects_to": self._merge_connects,
            "merge_runs": self._merge_runs,
            "prune_kind": self._prune_kind,
            "domain_links": self._domain_links,
            "witness_downstream": lambda params: self._witness_rows(params, reverse=False),
            "witness_upstream": lambda params: self._witness_rows(params, reverse=True),
            "blast_radius": self._blast,
            "dependents": self._dependents,
            "shortest_path_downstream": self._shortest_path_downstream,
            "shortest_path_upstream": self._shortest_path_upstream,
            "crypto_hotspots": self._crypto_hotspots,
            "systems_using_asset": self._systems_using_asset,
            "origin_system": self._origin,
            "business_impact": self._impact,
            "process_links": self._process_links,
            "compliance_inheritance": self._compliance,
            "vendor_path": self._vendor_path,
            "vendor_list": lambda p: [{"id": k} for label, k in sorted(self.graph.nodes) if label == "Vendor"][:p["limit"]],
            "vendor_neighborhood": self._vendor_neighborhood,
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
            self.graph.merge_edge("System", row["system_id"], "USES", "CryptoAsset", row["asset_id"], {"usage_type": row.get("usage_type"), "provenance": "SCANNER_DERIVED", "source": "crypto_asset inventory (evidence-chained)"})
        return []

    def _quarantine_legacy_calls(self, params):
        count = 0
        for src, rel, dst, properties in self.graph.edges:
            if rel != "CALLS" or properties.get("relation") is not None:
                continue
            if any((self.graph.nodes.get(key, {}).get("tenant_id") or "platform") != params["tenant"] for key in (src, dst)):
                continue
            if any(s == src and d == dst and r == "CALLS" and p.get("relation") is not None and p.get("lifecycle_revision") is not None
                   for s, r, d, p in self.graph.edges):
                properties.update(projection_state="STALE", lifecycle_reason="ambiguous_legacy_projection")
                count += 1
        return [{"quarantined": count}]

    def _merge_calls(self, params):
        for row in params.get("rows") or []:
            self.graph.merge_edge(
                "System",
                row["parent_id"],
                "CALLS",
                "System",
                row["child_id"],
                {"protocol": row.get("protocol"), "relation": row.get("relation"),
                 "frequency": row.get("frequency"), "provenance": row.get("provenance"),
                 "source": row.get("source"), "observed_at": row.get("observed_at"),
                 **{key: row.get(key) for key in (*FIELDS, "valid_until_epoch", "evidence_ref", "evidence_refs_json", "evidence_refs_total", "evidence_refs_truncated", "confidence", "confidence_meaning", "last_verified", "created_by")}},
            )
        return []

    def _merge_supports(self, params):
        for row in params.get("rows") or []:
            self.graph.merge_edge("System", row["system_id"], "SUPPORTS", "BusinessProcess", row["process_id"], dict(row))
        return []

    def _merge_owned(self, params):
        for row in params.get("rows") or []:
            self.graph.merge_edge("System", row["system_id"], "OWNED_BY", "BusinessOwner", row["owner_id"], {"provenance": "DECLARED", "source": "system owner mapping"})
        return []

    def _merge_comply(self, params):
        for row in params.get("rows") or []:
            self.graph.merge_edge("System", row["system_id"], "MUST_COMPLY_WITH", "ComplianceScope", row["standard_name"], {"provenance": "DECLARED", "source": "system compliance_scopes"})
        return []

    def _merge_vendor(self, params):
        for row in params.get("rows") or []:
            self.graph.merge_edge(
                "System",
                row["system_id"],
                "DEPENDS_ON_VENDOR",
                "Vendor",
                row["vendor_id"],
                {"dependency_type": row.get("dependency_type"), "provenance": "DECLARED", "source": "vendor dependency mapping"},
            )
        return []

    def _merge_connects(self, params):
        for row in params.get("rows") or []:
            self.graph.merge_edge(
                "System",
                row["system_id"],
                "CONNECTS_TO",
                "NetworkResource",
                row["network_id"],
                {},
            )
        return []

    def _merge_runs(self, params):
        for row in params.get("rows") or []:
            self.graph.merge_edge(
                "System",
                row["system_id"],
                "RUNS",
                "ContainerImage",
                row["container_id"],
                {},
            )
        return []

    def _prune_kind(self, params):
        # mirror of PRUNE_KIND (tenant-aware, round 35): delete nodes of
        # one kind whose identity is not in the keep list — within the
        # syncing tenant only, plus un-stamped legacy nodes on a
        # platform-scope sync. NOTE: the fake keys nodes by (label, id);
        # per-tenant node *identity* is a real-Neo4j property (the facade
        # never serves this store under a tenant scope), so the fake
        # models tenancy at the property/prune level, exactly as far as
        # its semantics go.
        label = params.get("_prune_label")
        prop = params.get("_prune_prop")
        keep = {str(i) for i in params.get("ids") or []}
        tenant = str(params.get("tenant") or "platform")
        if not label or not prop:
            return []
        doomed = []
        for (node_label, key), node in self.graph.nodes.items():
            if node_label != label:
                continue
            node_tenant = node.get("tenant_id")
            if node_tenant is None:
                if tenant == "platform":
                    doomed.append(key)
            elif str(node_tenant) == tenant and str(node.get(prop) or key) not in keep:
                doomed.append(key)
        for key in doomed:
            del self.graph.nodes[(label, key)]
            self.graph.edges = [
                e for e in self.graph.edges
                if (label, key) not in (e[0], e[2])
            ]
        return [{"pruned": len(doomed)}]

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

    def _system_neighbors(self, node_id, params, *, reverse=False):
        for src, relation, dst, properties in self.graph.edges:
            if relation != "CALLS" or src[0] != "System" or dst[0] != "System":
                continue
            if properties.get("relation") is not None:
                allowed = params.get("dependency_relations") or ["CALLS"]
                label = normalize_relation(properties["relation"])
            else:
                allowed = params.get("legacy_dependency_relations") or ["CALLS"]
                label = normalize_relation(properties.get("protocol"))
            from datetime import datetime, timezone
            from shared_models.relationship_lifecycle import current
            as_of = datetime.fromtimestamp(params.get("lifecycle_as_of", datetime.now(timezone.utc).timestamp()), timezone.utc)
            if not current(properties, now=as_of):
                continue
            if label not in allowed:
                continue
            if not reverse and src[1] == node_id:
                yield dst[1]
            elif reverse and dst[1] == node_id:
                yield src[1]

    def _domain_links(self, params):
        rows = [{"source": src[1], "target": KIND_PREFIX.get(dst[0], dst[0].lower()) + ":" + dst[1],
                 "relation": rel, "properties": dict(props)} for src, rel, dst, props in self.graph.edges
                if src[0] == "System" and src[1] in params["system_ids"] and rel in params["relations"] and (params.get("target_asset") is None or dst == ("CryptoAsset", params["target_asset"]))]
        return sorted(rows, key=lambda r: (r["source"], r["relation"], r["target"]))[:params["domain_limit"]]

    def _witness_rows(self, params, *, reverse=False):
        from datetime import datetime, timezone
        from shared_models.dependency_semantics import stored_relation
        from shared_models.traversal_evidence import walk_paths
        now = datetime.fromtimestamp(params["lifecycle_as_of"], timezone.utc)
        edges = [{**p, "from": src[1], "to": dst[1], "label": stored_relation(p)}
                 for src, rel, dst, p in self.graph.edges if rel == "CALLS" and src[0] == dst[0] == "System"]
        paths = walk_paths(edges, params["starts"], known={key for label, key in self.graph.nodes if label == "System"},
            now=now, hops=params.get("hops", 12), reverse=reverse, targets=params["targets"])
        return [{"id": sid, **self._path_payload(path["nodes"], params, reverse=reverse)} for sid, path in paths.items()]

    def _path_payload(self, nodes, params, *, reverse=False):
        from shared_models.dependency_semantics import stored_relation, propagates
        from shared_models.relationship_lifecycle import current
        from datetime import datetime, timezone
        now = datetime.fromtimestamp(params["lifecycle_as_of"], timezone.utc)
        links = []
        for left, right in zip(nodes, nodes[1:]):
            source, target = (right, left) if reverse else (left, right)
            for src, rel, dst, props in self.graph.edges:
                dst_id = "vendor:" + dst[1] if dst[0] == "Vendor" else dst[1]
                if src[1] == source and dst_id == target and (rel != "CALLS" or propagates(stored_relation(props)) and current(props, now=now)):
                    links.append({"from": source, "to": target, "type": rel, "properties": dict(props)})
                    break
        return {"path_nodes": list(nodes), "path_edges": links}

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
            for nxt in self._system_neighbors(current, params):
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

    def _dependents(self, params):
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
            for prev in self._system_neighbors(current, params, reverse=True):
                if prev not in seen:
                    seen[prev] = depth + 1
                    queue.append(prev)
        rows = []
        for sid, depth in seen.items():
            if depth == 0:
                continue
            node = self.graph.get("System", sid) or {}
            rows.append(
                {"id": sid, "name": node.get("name"), "criticality": node.get("criticality"), "hops": depth}
            )
        rows.sort(key=lambda row: (row["hops"], row.get("name") or ""))
        return rows

    def _shortest_path_downstream(self, params):
        return self._shortest_path(params, upstream=False)

    def _shortest_path_upstream(self, params):
        return self._shortest_path(params, upstream=True)

    def _shortest_path(self, params, *, upstream: bool):
        start = self.graph.find_system(str(params.get("start") or ""))
        target = self.graph.find_system(str(params.get("target") or ""))
        if not start or not target:
            return []
        start_id, target_id = start["system_id"], target["system_id"]
        if start_id == target_id:
            return [{"names": [start.get("name") or start_id], "hops": 0}]
        parent: dict[str, str | None] = {start_id: None}
        queue = deque([start_id])
        found = False
        while queue and not found:
            current = queue.popleft()
            depth = 0
            cursor = current
            while parent.get(cursor) is not None:
                depth += 1
                cursor = parent[cursor]
            if depth >= MAX_SYSTEM_HOPS:
                continue
            for nxt in self._system_neighbors(current, params, reverse=upstream):
                if nxt in parent:
                    continue
                parent[nxt] = current
                if nxt == target_id:
                    found = True
                    break
                queue.append(nxt)
        if not found:
            return []
        chain = [target_id]
        while parent.get(chain[-1]) is not None:
            chain.append(parent[chain[-1]])
        chain.reverse()
        names = []
        for sid in chain:
            node = self.graph.get("System", sid) or {}
            names.append(node.get("name") or sid)
        return [{"names": names, "hops": len(names) - 1, **self._path_payload(chain, params, reverse=upstream)}]

    def _crypto_hotspots(self, _params):
        rows = []
        for (label, key), node in self.graph.nodes.items():
            if label != "System":
                continue
            algorithms = []
            for _label, asset_key in self.graph.outgoing("System", key, "USES"):
                asset = self.graph.get("CryptoAsset", asset_key) or {}
                if asset.get("algorithm"):
                    algorithms.append(str(asset["algorithm"]))
            if not algorithms:
                continue
            vulnerable = sorted({a for a in algorithms if _is_shor_vulnerable(a)})
            rows.append(
                {
                    "system_id": node.get("system_id") or key,
                    "name": node.get("name"),
                    "criticality": node.get("criticality"),
                    "total_assets": len(algorithms),
                    "quantum_vulnerable_assets": len([a for a in algorithms if _is_shor_vulnerable(a)]),
                    "vulnerable_algorithms": vulnerable,
                }
            )
        rows.sort(
            key=lambda row: (-row["quantum_vulnerable_assets"], -row["total_assets"], row.get("name") or "")
        )
        return rows

    def _process_links(self, params):
        rows = []
        for src, rel, dst, props in self.graph.edges:
            if rel == "SUPPORTS" and src[0] == "System" and dst[0] == "BusinessProcess" and src[1] in params["system_ids"]:
                process = self.graph.get(*dst) or {}
                rows.append({"system_id": src[1], "id": dst[1], "name": process.get("name"),
                    "revenue_daily": process.get("revenue_daily"), "customer_count": process.get("customer_count"), "properties": dict(props)})
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

    def _vendor_neighborhood(self, params):
        vendors = {key for (label, key), props in self.graph.nodes.items() if label == "Vendor" and (key == params["start"] or props.get("name") == params["start"])}
        systems = {src[1] for src, rel, dst, props in self.graph.edges if rel == "DEPENDS_ON_VENDOR" and dst[1] in vendors}
        rows = [{"n": {**self.graph.get("Vendor", vid), "_label": "Vendor"}, "r": None, "m": None} for vid in vendors]
        for src, rel, dst, props in self.graph.edges:
            if src[0] == "System" and src[1] in systems and (rel == "DEPENDS_ON_VENDOR" and dst[1] in vendors or rel in {"USES", "SUPPORTS"}):
                rows.append({"n": {**self.graph.get(*src), "_label": src[0]}, "r": {**props, "type": rel}, "m": {**self.graph.get(*dst), "_label": dst[0]}})
        return rows

    def _vendor_path(self, params):
        start = self.graph.find_system(str(params.get("start") or ""))
        if not start:
            return []
        # Policy-filtered system prefix, then one domain-specific vendor hop.
        parent: dict[str, str | None] = {start["system_id"]: None}
        queue = deque([start["system_id"]])
        depths = {start["system_id"]: 0}
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
                for nxt in self._system_neighbors(current, params):
                    if nxt not in parent and depths[current] < MAX_SYSTEM_HOPS:
                        parent[nxt] = current
                        depths[nxt] = depths[current] + 1
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
                **self._path_payload([*chain, "vendor:" + found_vendor], params),
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
                        "r": {"type": rel, **_p},
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



