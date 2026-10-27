"""§30 Blast-radius analysis — answer “what is affected if X changes?”

Walks the platform relationship graph from a seed (certificate, HSM,
library, algorithm, …) to every dependent asset and counts them by layer:

    certificate → load balancer → applications → APIs → business services

Deterministic BFS over the correlated relationships; the graph is the one
built by the discovery engine (or provided by the caller).
"""

from __future__ import annotations

from collections import deque
from typing import Any, Optional

#: layer order used for grouping affected assets
_LAYER_ORDER = [
    "network", "hardware", "cloud", "application", "crypto", "vendor",
]

#: business-facing asset types (the “so what” layer)
_BUSINESS_TYPES = {"application", "api", "database"}


class BlastRadiusAnalyzer:
    def __init__(self, assets: Optional[dict[str, Any]] = None,
                 relationships: Optional[list[dict[str, Any]]] = None) -> None:
        # assets: identity -> {asset_type, domain, ...}
        self.assets = assets or {}
        self._graph: dict[str, list[str]] = {}
        for rel in relationships or []:
            self._graph.setdefault(rel["from"], []).append(rel["to"])
            self._graph.setdefault(rel["to"], []).append(rel["from"])

    def analyze(self, seed: str, max_depth: int = 10) -> dict[str, Any]:
        """Impact set reachable from ``seed`` (undirected, deduped)."""
        affected: list[str] = []
        layers: dict[str, list[str]] = {}
        paths: dict[str, list[str]] = {}
        seen = {seed}
        queue: deque[tuple[str, list[str]]] = deque([(seed, [seed])])
        while queue:
            node, path = queue.popleft()
            if node != seed and node in self.assets:
                affected.append(node)
                asset = self.assets[node]
                domain = asset.get("domain") or "UNKNOWN"
                layers.setdefault(domain, []).append(node)
                paths[node] = path
            if len(path) >= max_depth:
                continue
            for neighbor in self._graph.get(node, []):
                if neighbor not in seen:
                    seen.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))
        business = [a for a in affected
                    if (self.assets.get(a) or {}).get("asset_type")
                    in _BUSINESS_TYPES]
        return {
            "seed": seed,
            "affected_count": len(affected),
            "affected": sorted(affected),
            "by_domain": {d: sorted(v) for d, v in sorted(layers.items())},
            "business_services_affected": sorted(business),
            "business_impact": bool(business),
            "paths": paths,
        }


def blast_radius(seed: str, assets: dict[str, Any],
                 relationships: list[dict[str, Any]],
                 max_depth: int = 10) -> dict[str, Any]:
    """Module-level entry point."""
    return BlastRadiusAnalyzer(assets, relationships).analyze(seed, max_depth)
