"""Network Blast Radius — answer the four questions.

- If this certificate changes, which endpoints break?
- If this VPN crypto changes, which branches are affected?
- If this CA changes, which devices are affected?
- If this TLS policy changes, which applications are affected?

Answers are DIRECT_IMPACT / INDIRECT_IMPACT / BUSINESS_IMPACT /
NETWORK_IMPACT / GEOGRAPHIC_IMPACT sets computed from the dependency graph.
"""

from __future__ import annotations

from typing import Any

from network_scanner.enterprise.topology import NetworkGraph

IMPACT_KINDS = ("DIRECT", "INDIRECT", "BUSINESS", "NETWORK", "GEOGRAPHIC")


def blast_radius(graph: NetworkGraph, asset: str, *,
                 asset_attributes: dict[str, dict[str, Any]] | None = None,
                 business_map: dict[str, str] | None = None,
                 geo_map: dict[str, str] | None = None) -> dict[str, Any]:
    """Compute the impact sets for one crypto asset (cert, CA, VPN, TLS policy).

    ``asset_attributes`` maps node -> attributes (device_type, criticality…);
    ``business_map`` maps node -> business unit; ``geo_map`` node -> location.
    """
    asset_attributes = asset_attributes or {}
    business_map = business_map or {}
    geo_map = geo_map or {}

    # DIRECT = nodes that immediately use/depend on the asset (edges point
    # toward the asset, e.g. lb -[USES_CERTIFICATE]-> cert)
    direct = sorted({edge.source for edge in graph.incoming(asset)})
    indirect = graph.dependents(asset)
    indirect = [node for node in indirect if node != asset and node not in direct]

    business_units = sorted({business_map.get(node, "UNKNOWN") for node in indirect + direct if node in business_map})
    zones = sorted({(asset_attributes.get(node, {}).get("network_zone") or "UNKNOWN") for node in indirect + direct})
    locations = sorted({geo_map.get(node) or asset_attributes.get(node, {}).get("location") or "UNKNOWN"
                        for node in indirect + direct})

    impacted_devices = sorted({
        node for node in indirect + direct
        if (asset_attributes.get(node, {}).get("device_type") or "unknown") not in ("unknown", "container")
    })

    critical = sorted({
        node for node in indirect + direct
        if (asset_attributes.get(node, {}).get("criticality") or "UNKNOWN") in ("CRITICAL", "HIGH")
    })

    return {
        "asset": asset,
        "direct_impact": direct,
        "indirect_impact": indirect,
        "business_impact": business_units,
        "network_impact": {"zones": zones, "devices": impacted_devices},
        "geographic_impact": locations,
        "critical_assets_impacted": critical,
        "impact_counts": {
            "DIRECT": len(direct),
            "INDIRECT": len(indirect),
            "BUSINESS": len(business_units),
            "NETWORK": len(impacted_devices),
            "GEOGRAPHIC": len(locations),
        },
    }
