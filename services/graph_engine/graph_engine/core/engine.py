"""Directed system / asset / process graph with blast-radius queries."""

from __future__ import annotations

from copy import copy

import re
from collections import defaultdict, deque
from typing import Any, Iterable

from shared_models.process_impact import classify_systems, project_processes
from shared_models.traversal_evidence import metadata, walk_paths, envelope, path_evidence, MAX_WITNESSES, edge_evidence

from shared_models.relationship_lifecycle import (
    clock, current, effective_state, lifecycle_payload, summary as lifecycle_summary, edge_changes,
)

from shared_models.dependency_semantics import (
    MAX_SYSTEM_HOPS, edge_relation, normalize_relation, policy_metadata, propagates, system_id as canonical_system_id,
)

from graph_engine.core.edge_provenance import (
    PROVENANCE_DECLARED,
    PROVENANCE_SCANNER_DERIVED,
    edge_meta_payload,
    normalize_provenance,
    provenance_counts,
)

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
    def from_vis(cls, vis: dict[str, Any], *, now=None) -> "GraphEngine":
        """Load a graph from any backend's vis export (nodes + edges)."""
        engine = cls(now=now)
        for node in vis.get("nodes") or []:
            node_id = str(node.get("id") or "")
            if not node_id:
                continue
            props = {k: v for k, v in node.items() if k not in {"id", "group", "kind", "label"}}
            engine.add_node(node_id, kind=str(node.get("kind") or node.get("group") or "Node"), **props)
        for edge in vis.get("edges") or []:
            engine.add_edge(
                str(edge.get("from") or ""),
                str(edge.get("to") or ""),
                str(edge.get("label") or "RELATED"),
                provenance=edge.get("provenance"),
                source=edge.get("source"),
                observed_at=edge.get("observed_at"),
                confidence=edge.get("confidence"),
                evidence_ref=edge.get("evidence_ref"),
                lifecycle=lifecycle_payload(edge), evidence_metadata=metadata(edge),
            )
        return engine

    def __init__(self, *, now=None) -> None:
        self._as_of = now
        self.nodes: dict[str, dict[str, Any]] = {}
        self.out: dict[str, list[tuple[str, str]]] = defaultdict(list)
        self.incoming: dict[str, list[tuple[str, str]]] = defaultdict(list)
        # §4.5 (round 43): per-edge provenance — where the edge came from.
        # Keyed (src, dst, relation); traversal tuples stay untouched so every
        # existing query keeps working. An edge added without a provenance is
        # UNATTRIBUTED and is exported as such — it never silently becomes a
        # "known dependency".
        self.edge_meta: dict[tuple[str, str, str], dict[str, Any]] = {}

    @property
    def as_of(self):
        return self._as_of or clock()

    def add_node(self, node_id: str, *, kind: str, **props: Any) -> None:
        current = self.nodes.get(node_id, {"id": node_id, "kind": kind})
        current.update(props)
        current["kind"] = kind
        current["id"] = node_id
        self.nodes[node_id] = current

    def add_edge(
        self,
        src: str,
        dst: str,
        relation: str = "CALLS",
        *,
        provenance: str | None = None,
        source: str | None = None,
        observed_at: Any = None,
        confidence: Any = None,
        evidence_ref: Any = None,
        lifecycle: dict | None = None,
        evidence_metadata: dict | None = None,
    ) -> None:
        relation = normalize_relation(relation)
        if (dst, relation) not in self.out[src]:
            self.out[src].append((dst, relation))
        if (src, relation) not in self.incoming[dst]:
            self.incoming[dst].append((src, relation))
        key = (src, dst, relation)
        meta = self.edge_meta.get(key) or {}
        previous_revision = meta.get("lifecycle_revision")
        incoming_revision = (lifecycle or {}).get("lifecycle_revision")
        # Unregistered projections cannot overwrite managed tombstones/freshness.
        if previous_revision is not None and (incoming_revision is None or incoming_revision < previous_revision):
            return
        if provenance is not None:
            meta["provenance"] = normalize_provenance(provenance)
        for name, value in (("source", source), ("observed_at", observed_at),
                            ("confidence", confidence), ("evidence_ref", evidence_ref)):
            if value is not None:
                meta[name] = value
        meta.update(evidence_metadata or {})
        meta.update(lifecycle or {})
        self.edge_meta[key] = meta

    def edge_provenance(self, src: str, dst: str, relation: str) -> str:
        """Provenance class of one edge (UNATTRIBUTED when never stated)."""
        return normalize_provenance((self.edge_meta.get((src, dst, relation)) or {}).get("provenance"))

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
        container_images: Iterable[dict[str, Any]] = (),
        topology: dict[str, Any] | None = None,
        collection: dict[str, Any] | None = None,
    ) -> "GraphEngine":
        # `collection` is payload meta from the collector (bounded-walk
        # totals + truncation flags), not a node list — carried, not built.
        self.collection_meta: dict[str, Any] = dict(collection or {})
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
                self.add_edge(f"system:{sid}", f"scope:{scope}", "MUST_COMPLY_WITH",
                              provenance=PROVENANCE_DECLARED, source="system compliance_scopes")
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
                self.add_edge(f"system:{system_id}", f"asset:{aid}", "USES",
                              provenance=PROVENANCE_SCANNER_DERIVED,
                              source="crypto_asset inventory (evidence-chained)")
        for edge in edges:
            parent = canonical_system_id(edge.get("parent_id") or edge.get("from") or edge.get("source"))
            child = canonical_system_id(edge.get("child_id") or edge.get("to") or edge.get("target") or edge.get("destination"))
            if parent and child:
                self.add_edge(f"system:{parent}", f"system:{child}", edge_relation(edge),
                              provenance=edge.get("provenance") or PROVENANCE_DECLARED,
                              source=edge.get("source") or "system_dependencies (operator-declared)",
                              observed_at=edge.get("observed_at"), lifecycle=lifecycle_payload(edge), evidence_metadata=metadata(edge))
        for process in processes:
            pid = str(process.get("id") or process.get("process_id") or process.get("name"))
            self.add_node(
                f"process:{pid}",
                kind="BusinessProcess",
                name=process.get("name") or process.get("process_name"),
                revenue_daily=process.get("revenue_daily"),
                customer_count=process.get("customer_count"),
            )
            links = {link["system_id"]: link for link in process.get("system_links") or []}
            for system_id in process.get("system_ids") or []:
                link = links.get(system_id) or {}
                self.add_edge(f"system:{system_id}", f"process:{pid}", "SUPPORTS",
                              provenance=link.get("provenance") or PROVENANCE_DECLARED, source=link.get("source") or "system_business_process mapping",
                              lifecycle=lifecycle_payload(link), evidence_metadata={**metadata(link), "role": link.get("role")})
        for owner in owners:
            oid = str(owner.get("id") or owner.get("email") or owner.get("name"))
            self.add_node(f"owner:{oid}", kind="BusinessOwner", name=owner.get("name"), email=owner.get("email"))
            for system_id in owner.get("system_ids") or []:
                self.add_edge(f"system:{system_id}", f"owner:{oid}", "OWNED_BY",
                              provenance=PROVENANCE_DECLARED, source="system owner mapping")
        for vendor in vendors:
            vid = str(vendor.get("id") or vendor.get("name"))
            self.add_node(f"vendor:{vid}", kind="Vendor", name=vendor.get("name"), criticality=vendor.get("criticality"))
            for system_id in vendor.get("system_ids") or []:
                self.add_edge(f"system:{system_id}", f"vendor:{vid}", "DEPENDS_ON_VENDOR",
                              provenance=PROVENANCE_DECLARED, source="vendor dependency mapping")
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
                self.add_edge(f"system:{system_id}", f"cert:{cid}", "SECURED_BY",
                              provenance=PROVENANCE_SCANNER_DERIVED, source="certificate inventory")
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
                self.add_edge(f"system:{system_id}", f"cloud:{rid}", "DEPLOYED_ON",
                              provenance=PROVENANCE_DECLARED, source="cloud resource mapping")
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
                self.add_edge(f"system:{system_id}", f"network:{rid}", "CONNECTS_TO",
                              provenance=PROVENANCE_SCANNER_DERIVED, source="network probes")
        # Declared network topology (advanced/58 P0#1–2, round 31): DNS/CDN/
        # WAF/LB hops as first-class nodes with the declared chain edges and
        # honest TERMINATES_AT/HOSTS system links. Every node carries
        # source="declared" so a declared hop is never mistaken for a scan.
        if topology:
            from db.models.network_topology import NODE_KINDS

            node_by_name: dict[str, dict[str, Any]] = {}
            for node in topology.get("nodes") or []:
                name = str(node.get("name") or "")
                if not name:
                    continue
                node_by_name[name] = node
                kind = NODE_KINDS.get(str(node.get("kind") or ""), "NetworkEdge")
                self.add_node(
                    f"edge:{name}", kind=kind, name=name,
                    declared_source=node.get("source") or "declared",
                    **({k: str(v) for k, v in (node.get("attrs") or {}).items()
                        if isinstance(v, (str, int, float, bool))}
                       or {}),
                )
                for system_id in node.get("system_ids") or []:
                    relation = (node.get("system_relation") or "TERMINATES_AT")
                    self.add_edge(f"edge:{name}", f"system:{system_id}", relation,
                                  provenance=PROVENANCE_DECLARED, source="network_topology (declared)")
            for edge in topology.get("edges") or []:
                src, dst = str(edge.get("from") or ""), str(edge.get("to") or "")
                if src in node_by_name and dst in node_by_name:
                    self.add_edge(f"edge:{src}", f"edge:{dst}", edge.get("relation") or "ROUTES_TO",
                                  provenance=PROVENANCE_DECLARED, source="network_topology (declared)")
        for image in container_images:
            cid = str(image.get("id") or image.get("target") or "")
            if not cid:
                continue
            self.add_node(
                f"container:{cid}",
                kind="ContainerImage",
                name=image.get("name") or image.get("target"),
                image=image.get("image") or image.get("target"),
                package_count=image.get("package_count"),
                library_count=image.get("library_count"),
                vuln_count=image.get("vuln_count"),
            )
            for system_id in image.get("system_ids") or []:
                self.add_edge(f"system:{system_id}", f"container:{cid}", "RUNS",
                              provenance=PROVENANCE_SCANNER_DERIVED, source="container image inventory")
        return self

    def _evidence_edges(self):
        return [{"from": src.removeprefix("system:"), "to": dst.removeprefix("system:"), "label": rel,
                 **metadata(self.edge_meta.get((src, dst, rel)) or {}),
                 **lifecycle_payload(self.edge_meta.get((src, dst, rel)) or {})}
                for src, targets in self.out.items() for dst, rel in targets]

    def _witnesses(self, origins, targets, *, hops=12, reverse=False):
        now = self.as_of
        paths = walk_paths(self._evidence_edges(), [s.removeprefix("system:") for s in origins],
            known={s.removeprefix("system:") for s, n in self.nodes.items() if n.get("kind") == "System"},
            now=now, hops=hops, reverse=reverse, targets=targets)
        return envelope(paths, targets, now=now)

    def _domain_links(self, systems, relations, target=None):
        rows = [edge_evidence({"from": src.removeprefix("system:"), "to": dst, "label": rel,
                **metadata(self.edge_meta.get((src, dst, rel)) or {}), **lifecycle_payload(self.edge_meta.get((src, dst, rel)) or {})}, now=self.as_of)
                for src in sorted(set(systems)) for dst, rel in sorted(self.out.get(src, [])) if rel in relations and (target is None or dst == target)]
        return {"edges": rows[:MAX_WITNESSES], "returned_count": min(len(rows), MAX_WITNESSES), "limit": MAX_WITNESSES,
                "truncated": len(rows) > MAX_WITNESSES, "note": "Domain/context links, not additional propagating dependencies."}

    def _dependency_step(self, source: str, target: str, relation: str) -> bool:
        return (propagates(relation)
                and current(self.edge_meta.get((source, target, relation)) or {}, now=self.as_of)
                and (self.nodes.get(source) or {}).get("kind") == "System"
                and (self.nodes.get(target) or {}).get("kind") == "System")

    def _system_origins(self, start_id: str) -> list[str]:
        start = self._resolve(start_id)
        kind = (self.nodes.get(start) or {}).get("kind")
        if kind == "System":
            return [start]
        if kind == "CryptoAsset":
            return sorted({src for src, rel in self.incoming.get(start, [])
                           if rel == "USES" and (self.nodes.get(src) or {}).get("kind") == "System"})
        return []

    def _dependency_walk(self, start_id: str, *, hops: int, reverse: bool) -> dict[str, Any]:
        hops = max(1, min(MAX_SYSTEM_HOPS, hops))
        origins = self._system_origins(start_id)
        seen = {origin: 0 for origin in origins}
        queue = deque(origins)
        followed: list[dict[str, Any]] = []
        adjacency = self.incoming if reverse else self.out
        while queue:
            node = queue.popleft()
            if seen[node] >= hops:
                continue
            for nxt, relation in adjacency.get(node, []):
                if self._dependency_step(nxt if reverse else node, node if reverse else nxt, relation) and nxt not in seen:
                    seen[nxt] = seen[node] + 1
                    queue.append(nxt)
                    src, dst = (nxt, node) if reverse else (node, nxt)
                    followed.append({"from": src, "to": dst, "label": relation,
                                     "provenance": self.edge_provenance(src, dst, relation)})
        systems = [{"id": node_id.split(":", 1)[-1],
                    "name": self.nodes[node_id].get("name"),
                    "criticality": self.nodes[node_id].get("criticality"), "hops": depth}
                   for node_id, depth in seen.items() if depth > 0]
        systems.sort(key=lambda row: (row["hops"], row.get("name") or "", row["id"]))
        return {
            "start": origins[0].split(":", 1)[-1] if origins else start_id,
            "owning_systems": [origin.split(":", 1)[-1] for origin in origins],
            "systems": systems, "hops": hops, "nodes_visited": len(seen),
            "backend": self.backend, "provenance_counts": provenance_counts(followed),
            "traversal_evidence": self._witnesses(origins, [r["id"] for r in systems], hops=hops, reverse=reverse),
            "start_links": self._domain_links(origins, {"USES"}, target=self._resolve(start_id)) if (self.nodes.get(self._resolve(start_id)) or {}).get("kind") == "CryptoAsset" else None,
            "relationship_policy": policy_metadata(),
        }

    def blast_radius(self, start_id: str, *, hops: int = 5) -> dict[str, Any]:
        return self._dependency_walk(start_id, hops=hops, reverse=False)

    def business_impact(self, start_id: str, *, hops: int = 5) -> dict[str, Any]:
        if self._as_of is None:
            view = copy(self)
            view._as_of = clock()
            return view.business_impact(start_id, hops=hops)
        radius = self.blast_radius(start_id, hops=hops)
        reverse = self.dependents(start_id, hops=hops)
        direct = radius.get("owning_systems") or []
        classification = classify_systems(direct, [r["id"] for r in reverse["systems"]], [r["id"] for r in radius["systems"]])
        system_ids = {"system:" + sid for sid in classification["review_systems"]}
        registry = defaultdict(list)
        for sid in sorted(system_ids):
            for target, relation in self.out.get(sid, []):
                process = self.nodes.get(target) or {}
                if relation != "SUPPORTS" or process.get("kind") != "BusinessProcess":
                    continue
                props = self.edge_meta.get((sid, target, relation)) or {}
                registry[sid.removeprefix("system:")].append({**props, "id": target.removeprefix("process:"),
                    "relationship_record_id": props.get("record_id"), "name": process.get("name"),
                    "revenue_daily": process.get("revenue_daily"), "customer_count": process.get("customer_count")})
        explanations = {"direct": [{"system_id": sid} for sid in direct],
            "dependent_consumers": reverse["traversal_evidence"], "supporting_context": radius["traversal_evidence"]}
        projection = project_processes(registry, classification, now=self.as_of, witnesses=explanations)
        owners = sorted({self.nodes[n].get("name") for sid in system_ids for n, rel in self.out.get(sid, [])
                         if rel == "OWNED_BY" and self.nodes.get(n, {}).get("name")})
        scopes = sorted({scope for sid in system_ids for scope in self.nodes.get(sid, {}).get("compliance_scopes") or []})
        rows = {r["id"]: r for r in [*radius["systems"], *reverse["systems"]] if r["id"] not in direct}
        return {"start": radius["start"], "owning_systems": direct,
            "system_classification": classification, "process_impact": projection,
            "process_traversal_evidence": explanations,
            "total_revenue_at_risk": projection["economic_context"]["revenue_daily"]["known_sum"],
            "total_customers_at_risk": projection["economic_context"]["customer_count"]["known_sum"],
            "economic_totals_meaning": "Legacy aliases for declared exposed-process context, not predicted losses or unique people; see process_impact.economic_context.",
            "affected_processes": [p["name"] for p in projection["review_processes"] if p["name"]],
            "business_owners": owners, "compliance_scopes": scopes,
            "systems": sorted(rows.values(), key=lambda r: (r["hops"], r["id"])),
            "traversal_evidence": radius["traversal_evidence"],
            "domain_links": self._domain_links(system_ids, {"SUPPORTS", "OWNED_BY", "MUST_COMPLY_WITH"}), "backend": self.backend}

    def compliance_inheritance(self, start_id: str, *, hops: int = 5) -> dict[str, Any]:
        radius = self.blast_radius(start_id, hops=hops)
        systems = {"system:" + row["id"] for row in radius["systems"]} | set(self._system_origins(start_id))
        scopes = sorted({scope for sid in systems for scope in self.nodes.get(sid, {}).get("compliance_scopes") or []})
        return {"start": radius["start"], "scopes": scopes, "backend": self.backend,
                "traversal_evidence": radius["traversal_evidence"], "domain_links": self._domain_links(systems, {"MUST_COMPLY_WITH"})}

    def vendor_path(self, start_id: str) -> dict[str, Any]:
        start = self._resolve(start_id)
        if start is None or (self.nodes.get(start) or {}).get("kind") != "System":
            return {"start": start_id, "path": [], "hops": 0, "vendor": None, "backend": self.backend, "relationship_policy": policy_metadata(), "traversal_evidence": envelope({}, [], now=self.as_of)}
        parent: dict[str, str | None] = {start: None}
        queue = deque([start])
        depths = {start: 0}
        found_vendor = None
        found_at = None
        while queue:
            node = queue.popleft()
            for nxt, rel in self.out.get(node, []):
                if rel == "DEPENDS_ON_VENDOR" and (self.nodes.get(nxt) or {}).get("kind") == "Vendor":
                    found_vendor = nxt
                    found_at = node
                    queue.clear()
                    break
                if (self._dependency_step(node, nxt, rel) and nxt not in parent
                        and depths[node] < MAX_SYSTEM_HOPS):
                    parent[nxt] = node
                    depths[nxt] = depths[node] + 1
                    queue.append(nxt)
        if not found_vendor:
            return {"start": start.split(":", 1)[-1], "path": [], "hops": 0, "vendor": None, "backend": self.backend, "relationship_policy": policy_metadata(), "traversal_evidence": envelope({}, [], now=self.as_of)}
        chain = [found_at]
        while chain[-1] and parent.get(chain[-1]) is not None:
            chain.append(parent[chain[-1]])
        chain.reverse()
        names = [(self.nodes.get(item) or {}).get("name") or item.split(":", 1)[-1] for item in chain if item]
        vendor = self.nodes.get(found_vendor) or {}
        path_nodes = [node.removeprefix("system:") for node in [*chain, found_vendor]]
        path_edges = []
        for left, right in zip([*chain, found_vendor], [*chain, found_vendor][1:]):
            relation = next(rel for dst, rel in self.out[left] if dst == right and (rel == "DEPENDS_ON_VENDOR" or self._dependency_step(left, right, rel)))
            path_edges.append({"from": left.removeprefix("system:"), "to": right.removeprefix("system:"), "label": relation,
                               **metadata(self.edge_meta.get((left, right, relation)) or {}), **lifecycle_payload(self.edge_meta.get((left, right, relation)) or {})})
        witness = envelope({found_vendor: path_evidence(path_nodes, path_edges, now=self.as_of)}, [found_vendor], now=self.as_of)
        names.append(vendor.get("name") or found_vendor.split(":", 1)[-1])
        return {
            "start": start.split(":", 1)[-1],
            "path": names,
            "hops": max(0, len(names) - 1),
            "vendor": vendor.get("name"),
            "vendor_id": found_vendor.split(":", 1)[-1],
            "traversal_evidence": witness,
            "backend": self.backend, "relationship_policy": policy_metadata(),
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
        witness_count = 0
        seen_systems: set[str] = set()
        for sys_id in dependent_systems:
            if sys_id in seen_systems:
                continue
            seen_systems.add(sys_id)
            node = self.nodes.get(sys_id) or {}
            membership = {"from": sys_id.removeprefix("system:"), "to": start_id, "label": "DEPENDS_ON_VENDOR",
                          **metadata(self.edge_meta.get((sys_id, start_id, "DEPENDS_ON_VENDOR")) or {})}
            assets = []
            seen_assets: set[str] = set()
            for nxt, rel in self.out.get(sys_id, []):
                if rel != "USES" or nxt in seen_assets:
                    continue
                seen_assets.add(nxt)
                a = self.nodes.get(nxt) or {}
                membership_path = None
                if witness_count < MAX_WITNESSES:
                    membership_path = path_evidence([start_id, sys_id.removeprefix("system:"), nxt], [membership,
                        {"from": sys_id.removeprefix("system:"), "to": nxt, "label": "USES", **metadata(self.edge_meta.get((sys_id, nxt, "USES")) or {})}],
                        now=self.as_of, direction="mixed")
                    witness_count += 1
                assets.append({
                    "traversal_evidence": membership_path,
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
            "explanation_limit": MAX_WITNESSES, "explanations_returned": witness_count,
            "explanations_truncated": sum(s["asset_count"] for s in systems) > MAX_WITNESSES,
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
        return self._dependency_walk(start_id, hops=hops, reverse=True)

    def shortest_path(self, start_id: str, target_id: str, *, direction: str = "downstream") -> dict[str, Any]:
        """Shortest policy-permitted system path, bounded at MAX_SYSTEM_HOPS."""
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
                depths = {start: 0}
                found = False
                while queue and not found:
                    node = queue.popleft()
                    for nxt, rel in adjacency.get(node, []):
                        if not self._dependency_step(nxt if direction == "upstream" else node, node if direction == "upstream" else nxt, rel) or nxt in parent:
                            continue
                        if depths[node] >= MAX_SYSTEM_HOPS:
                            continue
                        parent[nxt] = node
                        depths[nxt] = depths[node] + 1
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
        witness = self._witnesses([start] if start else [], [target.removeprefix("system:")] if target and path_hops is not None else [],
                                  reverse=direction == "upstream")
        if witness["paths"] and witness["paths"][0]["available"]:
            names = [self._display("system:" + node) for node in witness["paths"][0]["nodes"]]
        return {
            "traversal_evidence": witness,
            "start": self._display(start) if resolved_start else start_id,
            "target": self._display(target) if resolved_target else target_id,
            "direction": "upstream" if direction == "upstream" else "downstream",
            "resolved_start": resolved_start,
            "resolved_target": resolved_target,
            "reachable": path_hops is not None,
            "hops": path_hops,
            "path": names,
            "relationship_policy": policy_metadata(), "backend": self.backend,
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
        lifecycle_changes = edge_changes(
            [{**e, "effective_state": effective_state(e, now=self.as_of)} for e in self.to_vis()["edges"]],
            [{**e, "effective_state": effective_state(e, now=other.as_of)} for e in other.to_vis()["edges"]])
        return {
            "relationship_lifecycle_changes": lifecycle_changes,
            "eligibility_change_is_not_remediation": True,
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
            "changed": bool(nodes_added or nodes_removed or edges_added or edges_removed or lifecycle_changes),
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
        result["relationship_policy"] = policy_metadata()
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
                edge = {"from": src, "to": dst, "label": rel}
                edge.update(edge_meta_payload(self.edge_meta.get((src, dst, rel))))
                edges.append(edge)
        return {"nodes": nodes, "edges": edges, "backend": self.backend,
                "lifecycle_as_of": self.as_of.isoformat(),
                "relationship_lifecycle": lifecycle_summary(edges, now=self.as_of)}

    def _resolve(self, raw: str) -> str | None:
        if raw in self.nodes:
            return raw
        for prefix in ("system:", "asset:", "process:", "cert:", "vendor:", "owner:", "scope:", "cloud:", "network:", "container:", "edge:"):
            if f"{prefix}{raw}" in self.nodes:
                return f"{prefix}{raw}"
        for node_id, node in self.nodes.items():
            if node.get("name") == raw:
                return node_id
        return None
