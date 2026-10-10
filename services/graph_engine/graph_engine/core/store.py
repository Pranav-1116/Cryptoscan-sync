"""Neo4j-backed graph store. Same query surface as GraphEngine."""

from __future__ import annotations

import logging
from typing import Any, Iterable

from graph_engine.builders import cypher_writes, payload
from graph_engine.config.settings import get_graph_settings
from graph_engine.connection.session_manager import neo4j_session
from graph_engine.migrations.migrator import apply_migrations
from graph_engine.queries.blast_radius import BLAST_RADIUS, ORIGIN_SYSTEM, SYSTEMS_USING_ASSET
from graph_engine.queries.business_impact import IMPACT_FROM_SYSTEMS
from graph_engine.queries.compliance_inheritance import COMPLIANCE_INHERITANCE
from graph_engine.queries.crypto_inventory import CRYPTO_FOR_SYSTEM
from graph_engine.queries.dependents import DEPENDENTS, SHORTEST_PATH_DOWNSTREAM, SHORTEST_PATH_UPSTREAM
from graph_engine.queries.hotspots import CRYPTO_HOTSPOTS
from graph_engine.queries.reachability import COUNT_EDGES, COUNT_NODES, EXPORT_VIS, PING
from graph_engine.queries.vendor_dependency import VENDOR_PATH
from graph_engine.schemas.node_schemas import KIND_PREFIX

logger = logging.getLogger(__name__)


class Neo4jGraphStore:
    backend = "neo4j"

    def __init__(self, driver, database: str | None = None) -> None:
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
        systems = list(systems)
        assets = list(assets)
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
        pruned = self._prune_ghosts(batches)
        counts = self.counts()
        logger.info("neo4j_graph_synced", extra={"written": written, "pruned": pruned, **counts})
        return {"written": written, "pruned": pruned, **counts, "backend": self.backend,
                "collection": collection_meta}

    _PRUNE_KINDS = (
        # (label, id property, id key in the merge rows)
        ("System", "system_id", "system_id"),
        ("CryptoAsset", "asset_id", "asset_id"),
        ("BusinessProcess", "process_id", "process_id"),
        ("BusinessOwner", "owner_id", "owner_id"),
        ("Vendor", "vendor_id", "vendor_id"),
        ("Certificate", "cert_id", "cert_id"),
        ("CloudResource", "resource_id", "resource_id"),
        ("NetworkResource", "network_id", "network_id"),
        ("ContainerImage", "container_id", "container_id"),
    )

    def _prune_ghosts(self, batches) -> int:
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
                result = self._run(query, ids=keep)
            except Exception:
                logger.debug("neo4j_prune_failed", exc_info=True)
                continue
            if result:
                pruned += int(result[0].get("pruned") or 0)
        return pruned

    def _origin(self, start_id: str) -> str | None:
        rows = self._run(ORIGIN_SYSTEM, start=start_id)
        if rows:
            return str(rows[0].get("id") or start_id)
        asset_systems = self._run(SYSTEMS_USING_ASSET, start=start_id)
        if asset_systems:
            return str(asset_systems[0].get("id"))
        return None

    def blast_radius(self, start_id: str, *, hops: int = 5) -> dict[str, Any]:
        origin = self._origin(start_id)
        if origin is None:
            return {"start": start_id, "systems": [], "hops": hops, "nodes_visited": 0, "backend": self.backend}
        rows = self._run(BLAST_RADIUS, start=origin, hops=hops)
        systems = [
            {
                "id": row.get("id"),
                "name": row.get("name"),
                "criticality": row.get("criticality"),
                "hops": int(row.get("hops") or 0),
            }
            for row in rows
        ]
        return {
            "start": origin,
            "systems": systems,
            "hops": hops,
            "nodes_visited": len(systems) + 1,
            "backend": self.backend,
        }

    def dependents(self, start_id: str, *, hops: int = 5) -> dict[str, Any]:
        origin = self._origin(start_id)
        if origin is None:
            return {"start": start_id, "systems": [], "hops": hops, "nodes_visited": 0, "backend": self.backend}
        rows = self._run(DEPENDENTS, start=origin, hops=hops)
        systems = [
            {
                "id": row.get("id"),
                "name": row.get("name"),
                "criticality": row.get("criticality"),
                "hops": int(row.get("hops") or 0),
            }
            for row in rows
        ]
        return {
            "start": origin,
            "systems": systems,
            "hops": hops,
            "nodes_visited": len(systems) + 1,
            "backend": self.backend,
        }

    def shortest_path(self, start_id: str, target_id: str, *, direction: str = "downstream") -> dict[str, Any]:
        origin = self._origin(start_id)
        target = self._origin(target_id)
        resolved_start = origin is not None
        resolved_target = target is not None
        names: list[str] = []
        path_hops = None
        if resolved_start and resolved_target:
            query = SHORTEST_PATH_UPSTREAM if direction == "upstream" else SHORTEST_PATH_DOWNSTREAM
            rows = self._run(query, start=origin, target=target)
            if rows and rows[0].get("names"):
                names = [str(item) for item in rows[0]["names"]]
                path_hops = int(rows[0].get("hops") or (len(names) - 1))
        return {
            "start": origin if resolved_start else start_id,
            "target": target if resolved_target else target_id,
            "direction": "upstream" if direction == "upstream" else "downstream",
            "resolved_start": resolved_start,
            "resolved_target": resolved_target,
            "reachable": path_hops is not None,
            "hops": path_hops,
            "path": names,
            "backend": self.backend,
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

    def business_impact(self, start_id: str, *, hops: int = 5) -> dict[str, Any]:
        radius = self.blast_radius(start_id, hops=hops)
        origin = radius["start"] if radius["nodes_visited"] else self._origin(start_id)
        system_ids = [row["id"] for row in radius["systems"] if row.get("id")]
        if origin:
            system_ids.append(origin)
        if not system_ids:
            return {
                "start": start_id,
                "total_revenue_at_risk": 0,
                "total_customers_at_risk": 0,
                "affected_processes": [],
                "business_owners": [],
                "compliance_scopes": [],
                "systems": [],
                "backend": self.backend,
            }
        rows = self._run(IMPACT_FROM_SYSTEMS, system_ids=system_ids)
        record = rows[0] if rows else {}
        revenues = [float(v or 0) for v in (record.get("revenues") or [])]
        customers = [int(v or 0) for v in (record.get("customers") or [])]
        processes = [name for name in (record.get("processes") or []) if name]
        owners = [name for name in (record.get("owners") or []) if name]
        scopes = [name for name in (record.get("scopes") or []) if name]
        return {
            "start": origin or start_id,
            "total_revenue_at_risk": sum(revenues),
            "total_customers_at_risk": sum(customers),
            "affected_processes": processes,
            "business_owners": owners,
            "compliance_scopes": sorted(set(scopes)),
            "systems": radius["systems"],
            "backend": self.backend,
        }

    def compliance_inheritance(self, start_id: str, *, hops: int = 5) -> dict[str, Any]:
        radius = self.blast_radius(start_id, hops=hops)
        origin = radius["start"] if radius["nodes_visited"] else self._origin(start_id)
        system_ids = [row["id"] for row in radius["systems"] if row.get("id")]
        if origin:
            system_ids.append(origin)
        rows = self._run(COMPLIANCE_INHERITANCE, system_ids=system_ids) if system_ids else []
        scopes = []
        if rows:
            scopes = [name for name in (rows[0].get("scopes") or []) if name]
        return {"start": origin or start_id, "scopes": sorted(set(scopes)), "backend": self.backend}

    def vendor_path(self, start_id: str) -> dict[str, Any]:
        rows = self._run(VENDOR_PATH, start=start_id)
        if not rows:
            return {"start": start_id, "path": [], "hops": 0, "vendor": None, "backend": self.backend}
        row = rows[0]
        return {
            "start": start_id,
            "path": list(row.get("names") or []),
            "hops": int(row.get("hops") or 0),
            "vendor": row.get("vendor"),
            "vendor_id": row.get("vendor_id"),
            "backend": self.backend,
        }

    def vendor_chain(self, start_id: str) -> dict[str, Any]:
        # Fallback path: build a memory engine from the exported vis so the
        # chain is computed the same way as the in-memory backend.
        from graph_engine.core.engine import GraphEngine

        return GraphEngine.from_vis(self.to_vis()).vendor_chain(start_id)

    def vendor_chains(self, *, limit: int = 100) -> dict[str, Any]:
        from graph_engine.core.engine import GraphEngine

        return GraphEngine.from_vis(self.to_vis()).vendor_chains(limit=limit)

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
        rows = self._run(EXPORT_VIS)
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
                edges.append({"from": node["id"], "to": other["id"], "label": label or "RELATED"})
                nodes[other["id"]] = other
        return {"nodes": list(nodes.values()), "edges": edges, "backend": self.backend}


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
