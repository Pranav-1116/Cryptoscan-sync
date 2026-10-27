"""Universal vendor dependency graph (spec §21).

Connects vendor assets regardless of vendor: a Cisco router → Palo Alto
firewall → F5 load balancer → AWS application → Azure database → GCP
analytics service. Nodes are canonical assets; edges carry typed
relationships (USES_VPN, TLS_TO, PROTECTED_BY, DEPENDS_ON, SIGNS_WITH,
TRUSTS, USES_ALGORITHM).
"""

from __future__ import annotations

import json
from typing import Any, Iterable

from universal_vendor.models import UniversalObservation


class VendorGraph:
    def __init__(self) -> None:
        self._nodes: dict[str, dict[str, Any]] = {}
        self._edges: list[dict[str, Any]] = []
        self._edge_keys: set[tuple[str, str, str, str]] = set()

    # ── nodes ──────────────────────────────────────────────────────────

    def add_node(self, asset_id: str, *, vendor: str = "", product: str = "",
                 asset_type: str = "other", environment: str = "",
                 region: str = "", extra: dict[str, Any] | None = None) -> str:
        node = self._nodes.setdefault(
            asset_id,
            {"id": asset_id, "vendor": vendor, "product": product,
             "asset_type": asset_type, "environment": environment,
             "region": region, "extra": extra or {}},
        )
        # enrich first-seen attributes
        if vendor and not node["vendor"]:
            node["vendor"] = vendor
        if product and not node["product"]:
            node["product"] = product
        return asset_id

    def add_observation(self, observation: UniversalObservation) -> str:
        asset_id = observation.asset_id or f"{observation.vendor}:{observation.product}"
        return self.add_node(
            asset_id,
            vendor=observation.vendor,
            product=observation.product,
            asset_type=observation.asset_type,
            environment=observation.environment or "",
            region=observation.region or "",
        )

    # ── edges ──────────────────────────────────────────────────────────

    def add_edge(self, source: str, target: str, relationship: str,
                 detail: dict[str, Any] | None = None) -> None:
        detail = detail or {}
        detail_key = json.dumps(detail, sort_keys=True, default=str,
                                separators=(",", ":"))
        key = (str(source), str(target), str(relationship), detail_key)
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        self.add_node(source)
        self.add_node(target)
        self._edges.append({
            "source": source,
            "target": target,
            "relationship": relationship,
            "detail": detail,
        })

    def add_dependency(self, raw: dict[str, Any]) -> None:
        """Add an edge from a plugin dependency observation."""
        source = raw.get("asset_id") or raw.get("source_asset")
        target = raw.get("target_asset")
        relationship = raw.get("relationship", "DEPENDS_ON")
        if source and target:
            source = str(source)
            target = str(target)
            self.add_node(
                source,
                vendor=str(raw.get("vendor") or raw.get("source_vendor") or ""),
                product=str(raw.get("product") or raw.get("source_product") or ""),
                asset_type=str(raw.get("asset_type") or "other"),
            )
            self.add_node(
                target,
                vendor=str(raw.get("target_vendor") or ""),
                product=str(raw.get("target_product") or ""),
            )
            self.add_edge(source, target, str(relationship),
                          detail=raw.get("detail") or {})

    # ── queries ────────────────────────────────────────────────────────

    def nodes(self) -> list[dict[str, Any]]:
        return list(self._nodes.values())

    def edges(self) -> list[dict[str, Any]]:
        return list(self._edges)

    def node_count(self) -> int:
        return len(self._nodes)

    def edge_count(self) -> int:
        return len(self._edges)

    def neighbors(self, asset_id: str) -> list[dict[str, Any]]:
        out = []
        for edge in self._edges:
            if edge["source"] == asset_id:
                out.append({"asset_id": edge["target"], "relationship": edge["relationship"]})
            if edge["target"] == asset_id:
                out.append({"asset_id": edge["source"], "relationship": edge["relationship"]})
        return out

    def paths(self, source: str, target: str, max_depth: int = 6) -> list[list[str]]:
        """BFS all simple paths between two assets (spec §21 example)."""
        found: list[list[str]] = []

        def _walk(current: str, path: list[str], seen: set[str]) -> None:
            if len(path) > max_depth:
                return
            if current == target:
                found.append(list(path))
                return
            for neighbor in self.neighbors(current):
                nid = neighbor["asset_id"]
                if nid in seen:
                    continue
                seen.add(nid)
                _walk(nid, path + [nid], seen)
                seen.discard(nid)

        _walk(source, [source], {source})
        return found

    def to_dict(self) -> dict[str, Any]:
        return {"nodes": self.nodes(), "edges": self.edges()}


def build_graph(observations: Iterable[UniversalObservation],
                dependencies: Iterable[dict[str, Any]] | None = None) -> VendorGraph:
    graph = VendorGraph()
    for obs in observations:
        graph.add_observation(obs)
    for dep in dependencies or ():
        graph.add_dependency(dep)
    return graph
