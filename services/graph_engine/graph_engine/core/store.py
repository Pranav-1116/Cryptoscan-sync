"""Neo4j-backed graph store. Same query surface as GraphEngine."""

from __future__ import annotations

from copy import copy

import logging
from shared_models.relationship_lifecycle import FIELDS, clock, summary as lifecycle_summary

from typing import Any, Iterable

from shared_models.traversal_evidence import envelope, native_path, path_evidence, metadata, MAX_WITNESSES, METADATA_FIELDS, edge_evidence

from shared_models.dependency_semantics import (
    MAX_SYSTEM_HOPS, normalize_relation, policy_metadata, query_parameters, stored_relation, system_id,
)

from graph_engine.builders import cypher_writes, payload
from graph_engine.config.settings import get_graph_settings
from graph_engine.connection.session_manager import neo4j_session
from graph_engine.migrations.migrator import apply_migrations
from graph_engine.queries.blast_radius import BLAST_RADIUS, ORIGIN_SYSTEM, SYSTEMS_USING_ASSET
from graph_engine.queries.business_impact import IMPACT_FROM_SYSTEMS, PROCESS_LINKS
from shared_models.coverage import analysis_coverage, native_traversal_bound
from shared_models.operational_dependencies import project_operational_dependencies, assertion_from_edge, condition
from graph_engine.queries.operational_dependencies import OPERATIONAL_LINKS, OPERATIONAL_SYSTEMS
from shared_models.process_impact import classify_systems, project_processes
from collections import defaultdict
from graph_engine.queries.compliance_inheritance import COMPLIANCE_INHERITANCE
from graph_engine.queries.crypto_inventory import CRYPTO_FOR_SYSTEM
from graph_engine.queries.dependents import DEPENDENTS, SHORTEST_PATH_DOWNSTREAM, SHORTEST_PATH_UPSTREAM
from graph_engine.queries.hotspots import CRYPTO_HOTSPOTS
from graph_engine.queries.reachability import COUNT_EDGES, COUNT_NODES, EXPORT_VIS, PING
from graph_engine.queries.traversal_evidence import WITNESS_DOWNSTREAM, WITNESS_UPSTREAM, DOMAIN_LINKS
from graph_engine.queries.vendor_dependency import VENDOR_PATH, VENDOR_NEIGHBORHOOD, VENDOR_LIST
from graph_engine.schemas.node_schemas import KIND_PREFIX

logger = logging.getLogger(__name__)




class Neo4jGraphStore:
    backend = "neo4j"

    def __init__(self, driver, database: str | None = None, *, now=None) -> None:
        self._as_of = now
        self.driver = driver
        self.database = database or get_graph_settings().NEO4J_DATABASE

    def _run(self, query: str, **params) -> list[Any]:
        with neo4j_session(self.driver, self.database) as session:
            result = session.run(query, params)
            return list(result)

    def apply_schema(self) -> dict[str, Any]:
        with neo4j_session(self.driver, self.database) as session:
            return apply_migrations(session.run)

    def ping(self) -> bool:
        try:
            rows = self._run(PING)
            record = rows[0] if rows else None
            return bool(record and record.get("ok") == 1)
        except Exception:
            logger.debug("neo4j_ping_failed", exc_info=True)
            return False

    def counts(self) -> dict[str, int]:
        nodes = 0
        edges = 0
        try:
            node_rows = self._run(COUNT_NODES)
            edge_rows = self._run(COUNT_EDGES)
            if node_rows:
                nodes = int(node_rows[0].get("nodes") or 0)
            if edge_rows:
                edges = int(edge_rows[0].get("edges") or 0)
        except Exception:
            logger.debug("neo4j_counts_failed", exc_info=True)
        return {"nodes": nodes, "edges": edges}

    def sync(
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
        collection: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        # `collection` is collector meta (bounded-walk totals/truncation
        # flags); carried into the result, not synced as a node kind.
        collection_meta = dict(collection or {})
        self.collection_meta = collection_meta
        # Per-tenant node identity (round 35): every row — nodes and edges —
        # carries the syncing tenant, so MERGE identities and prune scopes
        # are tenant-partitioned. One stamping point, every batch flows
        # through it. Standalone graph-engine deployments (no tenant plane)
        # stamp 'platform'.
        tenant = self._sync_tenant()
        systems = [dict(r, tenant_id=tenant) for r in systems]
        assets = [dict(r, tenant_id=tenant) for r in assets]
        processes = [dict(r, tenant_id=tenant) for r in processes]
        owners = [dict(r, tenant_id=tenant) for r in owners]
        vendors = [dict(r, tenant_id=tenant) for r in vendors]
        certificates = [dict(r, tenant_id=tenant) for r in certificates]
        cloud_resources = [dict(r, tenant_id=tenant) for r in cloud_resources]
        network_resources = [dict(r, tenant_id=tenant) for r in network_resources]
        container_images = [dict(r, tenant_id=tenant) for r in container_images]
        edges = [dict(r, tenant_id=tenant) for r in edges]
        process_nodes, support_edges = payload.process_rows(processes)
        owner_nodes, owned_edges = payload.owner_rows(owners)
        scope_nodes, comply_edges = payload.scope_rows(systems)
        vendor_nodes, vendor_edges = payload.vendor_rows(vendors)
        cert_nodes, cert_edges = payload.cert_rows(certificates)
        cloud_nodes, cloud_edges = payload.cloud_rows(cloud_resources)
        network_nodes, network_edges = payload.network_rows(network_resources)
        container_nodes, container_edges = payload.container_rows(container_images)
        batches = (
            (cypher_writes.MERGE_SYSTEMS, payload.systems_rows(systems)),
            (cypher_writes.MERGE_ASSETS, payload.asset_rows(assets)),
            (cypher_writes.MERGE_PROCESSES, process_nodes),
            (cypher_writes.MERGE_OWNERS, owner_nodes),
            (cypher_writes.MERGE_SCOPES, scope_nodes),
            (cypher_writes.MERGE_VENDORS, vendor_nodes),
            (cypher_writes.MERGE_CERTS, cert_nodes),
            (cypher_writes.MERGE_CLOUD, cloud_nodes),
            (cypher_writes.MERGE_NETWORK, network_nodes),
            (cypher_writes.MERGE_CONTAINERS, container_nodes),
            (cypher_writes.MERGE_USES, payload.uses_rows(assets, systems)),
            (cypher_writes.MERGE_CALLS, payload.call_rows(edges)),
            (cypher_writes.MERGE_SUPPORTS, support_edges),
            (cypher_writes.MERGE_OWNED_BY, owned_edges),
            (cypher_writes.MERGE_COMPLY, comply_edges),
            (cypher_writes.MERGE_VENDOR_EDGE, vendor_edges),
            (cypher_writes.MERGE_SECURED_BY, cert_edges),
            (cypher_writes.MERGE_DEPLOYED_ON, cloud_edges),
            (cypher_writes.MERGE_CONNECTS_TO, network_edges),
            (cypher_writes.MERGE_RUNS, container_edges),
        )
        written = 0
        for query, rows in batches:
            if not rows:
                continue
            self._run(query, rows=rows)
            written += len(rows)
        # Collection gaps must never detach and erase relationship evidence.
        # Full non-System maintenance pruning requires an explicit attestation.
        complete = (collection_meta.get("outcome") == "COMPLETE"
                    and collection_meta.get("truncated") is False
                    and not any(value for key, value in collection_meta.items() if key.endswith("_truncated")))
        self._run(cypher_writes.QUARANTINE_LEGACY_CALLS, tenant=tenant)
        pruned = self._prune_ghosts(batches, tenant=tenant) if complete else 0
        counts = self.counts()
        logger.info("neo4j_graph_synced", extra={"written": written, "pruned": pruned, **counts})
        return {"written": written, "pruned": pruned, **counts, "backend": self.backend,
                "collection": collection_meta, "pruning_skipped": not complete,
                "retention": "System nodes and their relationship history are never absence-pruned"}

    _PRUNE_KINDS = (
        # (label, id property, id key in the merge rows)
        # System nodes are retained: detach-delete would erase tombstones.
        ("CryptoAsset", "asset_id", "asset_id"),
        ("BusinessProcess", "process_id", "process_id"),
        ("BusinessOwner", "owner_id", "owner_id"),
        ("Vendor", "vendor_id", "vendor_id"),
        ("Certificate", "cert_id", "cert_id"),
        ("CloudResource", "resource_id", "resource_id"),
        ("NetworkResource", "network_id", "network_id"),
        ("ContainerImage", "container_id", "container_id"),
    )

    def _sync_tenant(self) -> str:
        """The tenant this sync writes as ('platform' without a tenant plane)."""
        try:
            from db.tenancy import current_tenant

            return current_tenant() or "platform"
        except Exception:
            return "platform"

    def _prune_ghosts(self, batches, tenant: str = "platform") -> int:
        """Delete nodes of kinds present in the payload whose ids are absent.

        MERGE-only sync left deleted systems/assets in the graph forever —
        blast radius and counts kept answering for entities that no longer
        exist. Rule: a kind is pruned ONLY when the sync carries merge rows
        for it (an empty list means "not in this sync", never "delete
        all"); ComplianceScope nodes are never pruned (derived, re-merge
        idempotently). The full keep-set goes into ONE query per kind —
        chunking it would make every chunk delete the other chunks' nodes.
        """
        merge_rows = {query: rows for query, rows in batches}
        row_sources = {
            "system_id": merge_rows.get(cypher_writes.MERGE_SYSTEMS, ()),
            "asset_id": merge_rows.get(cypher_writes.MERGE_ASSETS, ()),
            "process_id": merge_rows.get(cypher_writes.MERGE_PROCESSES, ()),
            "owner_id": merge_rows.get(cypher_writes.MERGE_OWNERS, ()),
            "vendor_id": merge_rows.get(cypher_writes.MERGE_VENDORS, ()),
            "cert_id": merge_rows.get(cypher_writes.MERGE_CERTS, ()),
            "resource_id": merge_rows.get(cypher_writes.MERGE_CLOUD, ()),
            "network_id": merge_rows.get(cypher_writes.MERGE_NETWORK, ()),
            "container_id": merge_rows.get(cypher_writes.MERGE_CONTAINERS, ()),
        }
        pruned = 0
        for label, prop, key in self._PRUNE_KINDS:
            rows = row_sources.get(key) or []
            keep = sorted({str(row.get(key)) for row in rows if row.get(key)})
            if not keep:
                continue  # kind absent from this sync — leave its nodes alone
            query = cypher_writes.PRUNE_KIND.format(label=label, prop=prop)
            try:
                result = self._run(query, ids=keep, tenant=tenant)
            except Exception:
                logger.debug("neo4j_prune_failed", exc_info=True)
                continue
            if result:
                pruned += int(result[0].get("pruned") or 0)
        return pruned

    def refresh_relationship_lifecycle(self, systems, edges):
        """Fail-closed refresh of SQL-backed eligibility before native reads.

        No absence inference and no pruning: a bounded collector is not a full
        inventory. Do not re-stamp unregistered/inferred edges as SQL evidence.
        """
        managed = [edge for edge in edges if edge.get("lifecycle_revision") is not None]
        if not managed:
            return
        tenant = self._sync_tenant()
        system_rows = payload.systems_rows([dict(row, tenant_id=tenant) for row in systems])
        if system_rows:
            self._run(cypher_writes.MERGE_SYSTEMS, rows=system_rows)
        self._run(cypher_writes.MERGE_CALLS, rows=payload.call_rows([dict(edge, tenant_id=tenant) for edge in managed]))
        self._run(cypher_writes.QUARANTINE_LEGACY_CALLS, tenant=tenant)

    def _origins(self, start_id: str) -> list[str]:
        start_id = system_id(start_id)
        asset_prefix = start_id.startswith("asset:")
        rows = [] if asset_prefix else self._run(ORIGIN_SYSTEM, start=start_id)
        start_id = start_id.removeprefix("asset:")
        if rows:
            return [str(rows[0].get("id") or start_id)]
        return sorted({str(row["id"]) for row in self._run(SYSTEMS_USING_ASSET, start=start_id)
                       if row.get("id")})

    def _origin(self, start_id: str) -> str | None:
        origins = self._origins(start_id)
        return origins[0] if origins else None

    def _dependency_walk(self, start_id: str, *, hops: int, reverse: bool) -> dict[str, Any]:
        hops = max(1, min(MAX_SYSTEM_HOPS, hops))
        now = self._as_of or clock()
        origins = self._origins(start_id)
        by_id: dict[str, dict[str, Any]] = {}
        for origin in origins:
            rows = self._run(DEPENDENTS if reverse else BLAST_RADIUS,
                             start=origin, hops=hops, **query_parameters(now=now))
            for row in rows:
                sid = str(row.get("id") or "")
                if not sid or sid in origins:
                    continue
                candidate = {"id": sid, "name": row.get("name"),
                             "criticality": row.get("criticality"), "hops": int(row.get("hops") or 0)}
                if sid not in by_id or candidate["hops"] < by_id[sid]["hops"]:
                    by_id[sid] = candidate
        systems = sorted(by_id.values(), key=lambda row: (row["hops"], row.get("name") or "", row["id"]))
        requested = [row["id"] for row in systems]
        witnesses = self._run(WITNESS_UPSTREAM if reverse else WITNESS_DOWNSTREAM,
            starts=origins, targets=sorted(requested)[:MAX_WITNESSES], hops=hops, witness_limit=MAX_WITNESSES,
            **query_parameters(now=now)) if requested else []
        paths = {row["id"]: native_path(row, now=now, direction="upstream" if reverse else "downstream") for row in witnesses}
        start_links = self._domain_links(origins, {"USES"}, target_asset=str(start_id).removeprefix("asset:")) if origins and not self._run(ORIGIN_SYSTEM, start=system_id(start_id)) else None
        result = {"start_links": start_links, "traversal_evidence": envelope(paths, requested, now=now),
                "start": origins[0] if origins else start_id, "owning_systems": origins,
                "systems": systems, "hops": hops, "nodes_visited": len(systems) + len(origins),
                "backend": self.backend, "relationship_policy": policy_metadata()}

        bound = native_traversal_bound(systems, hops, reverse=reverse)
        result["coverage"] = analysis_coverage({"collector_coverage": getattr(self, "collection_meta", {})},
            {"traversal_evidence": {"dependent_consumers" if reverse else "supporting_context": result["traversal_evidence"]}}, traversals=[bound])
        return result

    def blast_radius(self, start_id: str, *, hops: int = 5) -> dict[str, Any]:
        return self._dependency_walk(start_id, hops=hops, reverse=False)

    def dependents(self, start_id: str, *, hops: int = 5) -> dict[str, Any]:
        return self._dependency_walk(start_id, hops=hops, reverse=True)

    def shortest_path(self, start_id: str, target_id: str, *, direction: str = "downstream") -> dict[str, Any]:
        now = self._as_of or clock()
        witness = None
        origin = self._origin(start_id)
        target = self._origin(target_id)
        resolved_start = origin is not None
        resolved_target = target is not None
        names: list[str] = []
        path_hops = None
        if resolved_start and resolved_target and origin == target:
            # Resolve zero hops without shortestPath's common-node restriction
            # on real Neo4j. Preserve the display name used by the memory path.
            rows = self._run(ORIGIN_SYSTEM, start=origin)
            names = [str((rows[0].get("name") if rows else None) or origin)]
            path_hops = 0
            witness = path_evidence([origin], [], now=now, direction=direction)
        elif resolved_start and resolved_target:
            query = SHORTEST_PATH_UPSTREAM if direction == "upstream" else SHORTEST_PATH_DOWNSTREAM
            rows = self._run(query, start=origin, target=target, **query_parameters(now=now))
            if rows and rows[0].get("names"):
                names = [str(item) for item in rows[0]["names"]]
                path_hops = int(rows[0].get("hops") or (len(names) - 1))
                witness = native_path(rows[0], now=now, direction=direction)
        return {
            "traversal_evidence": envelope({target: witness} if witness else {}, [target] if path_hops is not None else [], now=now),
            "start": origin if resolved_start else start_id,
            "target": target if resolved_target else target_id,
            "direction": "upstream" if direction == "upstream" else "downstream",
            "resolved_start": resolved_start,
            "resolved_target": resolved_target,
            "reachable": path_hops is not None,
            "hops": path_hops,
            "path": names,
            "relationship_policy": policy_metadata(), "backend": self.backend,
        }

    def crypto_hotspots(self) -> dict[str, Any]:
        rows = self._run(CRYPTO_HOTSPOTS)
        hotspots = [
            {
                "system_id": row.get("system_id") or row.get("id"),
                "name": row.get("name"),
                "criticality": row.get("criticality"),
                "total_assets": int(row.get("total_assets") or 0),
                "quantum_vulnerable_assets": int(row.get("quantum_vulnerable_assets") or 0),
                "vulnerable_algorithms": sorted({str(a) for a in row.get("vulnerable_algorithms") or []}),
            }
            for row in rows
        ]
        hotspots.sort(
            key=lambda row: (-row["quantum_vulnerable_assets"], -row["total_assets"], row.get("name") or "")
        )
        return {
            "hotspots": hotspots,
            "count": len(hotspots),
            "systems_with_assets": len(hotspots),
            "ranking": "quantum_vulnerable desc, total assets desc, name",
            "backend": self.backend,
        }

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

    def _domain_links(self, systems, relations, target_asset=None):
        rows = self._run(DOMAIN_LINKS, system_ids=sorted(set(systems)), relations=sorted(relations), target_asset=target_asset, domain_limit=MAX_WITNESSES + 1) if systems else []
        edges = [edge_evidence({**(r.get("properties") or {}), "from": r.get("source"), "to": r.get("target"), "label": r.get("relation")}, now=self._as_of or clock()) for r in rows[:MAX_WITNESSES]]
        return {"edges": edges, "returned_count": len(edges), "limit": MAX_WITNESSES,
                "truncated": len(rows) > MAX_WITNESSES, "note": "Domain/context links, not additional propagating dependencies."}

    def business_impact(self, start_id: str, *, hops: int = 5) -> dict[str, Any]:
        if self._as_of is None:
            view = copy(self)
            view._as_of = clock()
            return view.business_impact(start_id, hops=hops)
        radius = self.blast_radius(start_id, hops=hops)
        reverse = self.dependents(start_id, hops=hops)
        direct = radius.get("owning_systems") or []
        classification = classify_systems(direct, [r["id"] for r in reverse["systems"]], [r["id"] for r in radius["systems"]])
        system_ids = classification["review_systems"]
        registry = defaultdict(list)
        for row in self._run(PROCESS_LINKS, system_ids=system_ids) if system_ids else []:
            props = row.get("properties") or {}
            registry[row["system_id"]].append({**props, "id": row["id"], "name": row.get("name"),
                "revenue_daily": row.get("revenue_daily"), "customer_count": row.get("customer_count"),
                "relationship_record_id": props.get("record_id")})
        operational_edges = [{**metadata(r.get("properties") or {}), **(r.get("properties") or {}),
            "from": r["source"], "to": r["target"], "label": stored_relation(r.get("properties") or {})}
            for r in self._run(OPERATIONAL_LINKS, system_ids=system_ids, tenant=self._sync_tenant())] if system_ids else []
        references = {sid for edge in operational_edges for sid in condition(assertion_from_edge(edge))["assertion"].get("failover_system_ids") or []}
        loaded = {r["id"] for r in self._run(OPERATIONAL_SYSTEMS, ids=sorted(references), tenant=self._sync_tenant())} if references else set()
        operational = project_operational_dependencies(operational_edges, classification, known_systems=set(system_ids) | loaded,
            now=self._as_of, source_coverage=None)
        explanations = {"direct": [{"system_id": sid} for sid in direct],
            "dependent_consumers": reverse["traversal_evidence"], "supporting_context": radius["traversal_evidence"]}
        projection = project_processes(registry, classification, now=self._as_of or clock(), witnesses=explanations)
        rows = self._run(IMPACT_FROM_SYSTEMS, system_ids=system_ids) if system_ids else []
        record = rows[0] if rows else {}
        members = {r["id"]: r for r in [*radius["systems"], *reverse["systems"]] if r["id"] not in direct}
        result = {"start": radius["start"], "owning_systems": direct,
            "system_classification": classification, "process_impact": projection, "operational_impact": operational,
            "process_traversal_evidence": explanations,
            "total_revenue_at_risk": projection["economic_context"]["revenue_daily"]["known_sum"],
            "total_customers_at_risk": projection["economic_context"]["customer_count"]["known_sum"],
            "economic_totals_meaning": "Legacy aliases for declared exposed-process context, not predicted losses or unique people; see process_impact.economic_context.",
            "affected_processes": [p["name"] for p in projection["review_processes"] if p["name"]],
            "business_owners": sorted({n for n in record.get("owners", []) if n}),
            "compliance_scopes": sorted({n for n in record.get("scopes", []) if n}),
            "systems": sorted(members.values(), key=lambda r: (r["hops"], r["id"])),
            "traversal_evidence": radius["traversal_evidence"],
            "domain_links": self._domain_links(system_ids, {"SUPPORTS", "OWNED_BY", "MUST_COMPLY_WITH"}), "backend": self.backend}

        result["coverage"] = analysis_coverage({"collector_coverage": getattr(self, "collection_meta", {})},
            {**result, "traversal_evidence": explanations}, traversals=[*reverse["coverage"]["traversals"], *radius["coverage"]["traversals"]])
        return result

    def compliance_inheritance(self, start_id: str, *, hops: int = 5) -> dict[str, Any]:
        radius = self.blast_radius(start_id, hops=hops)
        origin = radius["start"] if radius["nodes_visited"] else self._origin(start_id)
        system_ids = [row["id"] for row in radius["systems"] if row.get("id")]
        system_ids.extend(radius.get("owning_systems") or ([origin] if origin else []))
        rows = self._run(COMPLIANCE_INHERITANCE, system_ids=system_ids) if system_ids else []
        scopes = []
        if rows:
            scopes = [name for name in (rows[0].get("scopes") or []) if name]
        return {"start": origin or start_id, "scopes": sorted(set(scopes)), "backend": self.backend,
                "traversal_evidence": radius["traversal_evidence"],
                "domain_links": self._domain_links(system_ids, {"MUST_COMPLY_WITH"})}

    def vendor_path(self, start_id: str) -> dict[str, Any]:
        now = self._as_of or clock()
        rows = self._run(VENDOR_PATH, start=system_id(start_id), **query_parameters(now=now))
        if not rows:
            return {"start": start_id, "path": [], "hops": 0, "vendor": None, "backend": self.backend, "relationship_policy": policy_metadata(), "traversal_evidence": envelope({}, [], now=now)}
        row = rows[0]
        destination = "vendor:" + str(row.get("vendor_id"))
        return {
            "traversal_evidence": envelope({destination: native_path(row, now=now)}, [destination] if row.get("vendor_id") else [], now=now),
            "start": start_id,
            "path": list(row.get("names") or []),
            "hops": int(row.get("hops") or 0),
            "vendor": row.get("vendor"),
            "vendor_id": row.get("vendor_id"),
            "backend": self.backend, "relationship_policy": policy_metadata(),
        }

    def vendor_chain(self, start_id: str) -> dict[str, Any]:
        from graph_engine.core.engine import GraphEngine
        rows = self._run(VENDOR_NEIGHBORHOOD, start=str(start_id).removeprefix("vendor:"))
        engine = GraphEngine.from_vis(self._vis_from_rows(rows))
        engine.backend = self.backend
        return engine.vendor_chain(start_id)

    def vendor_chains(self, *, limit: int = 100) -> dict[str, Any]:
        chains = [self.vendor_chain(row["id"]) for row in self._run(VENDOR_LIST, limit=max(1, min(limit, 1000)))]
        chains.sort(key=lambda c: (-c["total_assets"], c["vendor"]["name"] or ""))
        return {"chains": chains, "count": len(chains), "backend": self.backend}

    def crypto_for_system(self, start_id: str) -> dict[str, Any]:
        rows = self._run(CRYPTO_FOR_SYSTEM, start=start_id)
        assets = [
            {
                "id": row.get("id"),
                "algorithm": row.get("algorithm"),
                "purpose": row.get("purpose"),
                "confidence": row.get("confidence"),
                "key_size": row.get("key_size"),
                "usage_type": row.get("usage_type"),
            }
            for row in rows
        ]
        return {"start": start_id, "assets": assets, "count": len(assets), "backend": self.backend}

    def to_vis(self) -> dict[str, Any]:
        return self._vis_from_rows(self._run(EXPORT_VIS))

    def _vis_from_rows(self, rows):
        nodes: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, Any]] = []
        for row in rows:
            node = _as_vis_node(row.get("n") if hasattr(row, "get") else None)
            if node:
                nodes[node["id"]] = node
            other = _as_vis_node(row.get("m") if hasattr(row, "get") else None)
            rel = row.get("r") if hasattr(row, "get") else None
            if node and other and rel is not None:
                label = rel.get("type") if hasattr(rel, "get") else getattr(rel, "type", None)
                if label is None and isinstance(rel, dict):
                    label = rel.get("label")
                label = getattr(rel, "type", None) or label
                if label == "CALLS" and node.get("kind") == other.get("kind") == "System":
                    label = stored_relation(dict(rel))
                else:
                    label = normalize_relation(label or "RELATED")
                edge = {"from": node["id"], "to": other["id"], "label": label}
                # §4.5 (round 43): relationship properties written at MERGE
                # time (provenance class + source) survive the export instead
                # of collapsing to a bare relation label.
                for prop in (*METADATA_FIELDS, "evidence_refs_json", "operational_dependency_json", *FIELDS):
                    value = rel.get(prop) if hasattr(rel, "get") else getattr(rel, prop, None)
                    if value is None and isinstance(rel, dict):
                        value = rel.get(prop)
                    if value is not None:
                        edge[prop] = value
                edge.update(metadata(edge))
                edges.append(edge)
                nodes[other["id"]] = other
        as_of = self._as_of or clock()
        return {"nodes": list(nodes.values()), "edges": edges, "backend": self.backend,
                "lifecycle_as_of": as_of.isoformat(), "relationship_lifecycle": lifecycle_summary(edges, now=as_of)}


def _as_vis_node(raw: Any) -> dict[str, Any] | None:
    if raw is None:
        return None
    if hasattr(raw, "items") and not isinstance(raw, dict):
        # neo4j.graph.Node
        labels = list(getattr(raw, "labels", []) or [])
        props = dict(raw)
        kind = labels[0] if labels else str(props.get("_label") or "Node")
    elif isinstance(raw, dict):
        props = dict(raw)
        kind = str(props.get("_label") or props.get("kind") or "Node")
    else:
        return None
    prefix = KIND_PREFIX.get(kind, kind.lower())
    ident = (
        props.get("system_id")
        or props.get("asset_id")
        or props.get("process_id")
        or props.get("owner_id")
        or props.get("standard_name")
        or props.get("cert_id")
        or props.get("resource_id")
        or props.get("vendor_id")
        or props.get("id")
    )
    node_id = props.get("id") if isinstance(props.get("id"), str) and ":" in str(props.get("id")) else f"{prefix}:{ident}"
    label = props.get("name") or props.get("algorithm") or props.get("subject") or ident
    cleaned = {k: v for k, v in props.items() if k not in {"id", "_label"} and not str(k).startswith("_")}
    return {"id": node_id, "label": label, "group": kind, "kind": kind, **cleaned}
