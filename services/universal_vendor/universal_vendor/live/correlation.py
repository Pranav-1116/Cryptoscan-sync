"""Vendor-to-Cloud correlation + blast radius + alert correlation
(24/7 spec §13, §14, §18, §19).

The dependency graph understands cross-platform relationships: a Cisco
router → IPsec VPN → AWS VPC → EKS → application, or a Palo Alto → Azure
ExpressRoute/VPN → Azure VNet → AKS. When a vendor asset changes, blast
radius walks the graph to the affected assets, applications, business
services and compliance controls, and presents ONE correlated incident —
not thousands of independent alerts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from universal_vendor.graph import VendorGraph


@dataclass
class AffectedScope:
    asset_id: str
    change_type: str
    affected_assets: list[str] = field(default_factory=list)
    affected_applications: list[str] = field(default_factory=list)
    affected_business_services: list[str] = field(default_factory=list)
    affected_compliance_controls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"asset_id": self.asset_id, "change_type": self.change_type,
                "affected_assets": list(self.affected_assets),
                "affected_applications": list(self.affected_applications),
                "affected_business_services": list(self.affected_business_services),
                "affected_compliance_controls": list(self.affected_compliance_controls),
                "counts": {
                    "assets": len(self.affected_assets),
                    "applications": len(self.affected_applications),
                    "business_services": len(self.affected_business_services),
                    "compliance_controls": len(self.affected_compliance_controls),
                }}


class CorrelationEngine:
    """Records cross-platform edges and computes blast radius."""

    # node asset_type markers for scope classification
    _APP_TYPES = ("application", "saas", "load_balancer", "middleware")
    _SERVICE_TYPES = ("business_service", "service")
    _CONTROL_TYPES = ("compliance_control", "control")

    def __init__(self, graph: Optional[VendorGraph] = None) -> None:
        self.graph = graph or VendorGraph()

    # ── cross-platform edges (§14) ────────────────────────────────────

    def link_vendor_to_cloud(self, *, vendor_asset: str, vpn: str,
                             cloud_network: str, cluster: str,
                             application: str, relationship: str = "CONNECTS_VIA") -> None:
        """Cisco router → IPsec VPN → AWS VPC → EKS → application."""
        self.graph.add_edge(vendor_asset, vpn, "TERMINATES")
        self.graph.add_edge(vpn, cloud_network, relationship)
        self.graph.add_edge(cloud_network, cluster, "HOSTS")
        self.graph.add_edge(cluster, application, "RUNS")

    # ── blast radius (§18) ────────────────────────────────────────────

    def blast_radius(self, asset_id: str, *, change_type: str = "CHANGED",
                     max_depth: int = 8) -> AffectedScope:
        scope = AffectedScope(asset_id=asset_id, change_type=change_type)
        seen: set[str] = set()

        def _walk(current: str, depth: int) -> None:
            if depth > max_depth or current in seen:
                return
            seen.add(current)
            node = self._node(current)
            if node:
                atype = node.get("asset_type", "")
                if atype in self._APP_TYPES:
                    scope.affected_applications.append(current)
                elif atype in self._SERVICE_TYPES:
                    scope.affected_business_services.append(current)
                elif atype in self._CONTROL_TYPES:
                    scope.affected_compliance_controls.append(current)
                else:
                    scope.affected_assets.append(current)
            else:
                scope.affected_assets.append(current)
            for neighbor in self.graph.neighbors(current):
                _walk(neighbor["asset_id"], depth + 1)

        _walk(asset_id, 0)
        return scope

    def _node(self, asset_id: str) -> Optional[dict[str, Any]]:
        for node in self.graph.nodes():
            if node["id"] == asset_id:
                return node
        return None

    # ── alert correlation (§19) ───────────────────────────────────────

    def correlate(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Group change events by root asset into ONE incident per root.

        Example: ROOT CA CHANGE → 500 certificates, 1,200 applications,
        40 business services → ONE root incident.
        """
        by_root: dict[str, dict[str, Any]] = {}
        for event in events:
            root = event.get("root_asset_id") or event.get("asset_id")
            if not root:
                continue
            incident = by_root.setdefault(root, {
                "root_asset_id": root,
                "event_ids": [],
                "affected_assets": [],
                "affected_applications": [],
                "affected_business_services": [],
                "first_seen": event.get("timestamp"),
                "last_seen": event.get("timestamp"),
            })
            incident["event_ids"].append(event.get("event_id") or event.get("change_type"))
            scope = event.get("scope")
            if isinstance(scope, dict):
                for key in ("affected_assets", "affected_applications",
                            "affected_business_services"):
                    incident[key].extend(scope.get(key, []))
            incident["last_seen"] = event.get("timestamp")

        return [
            {
                "root_asset_id": data["root_asset_id"],
                "event_count": len(data["event_ids"]),
                "affected_assets": sorted(set(data["affected_assets"])),
                "affected_applications": sorted(set(data["affected_applications"])),
                "affected_business_services": sorted(set(data["affected_business_services"])),
                "first_seen": data["first_seen"],
                "last_seen": data["last_seen"],
                "summary": (
                    f"{data['root_asset_id']}: {len(data['event_ids'])} events, "
                    f"{len(set(data['affected_assets']))} assets, "
                    f"{len(set(data['affected_applications']))} applications, "
                    f"{len(set(data['affected_business_services']))} business services"
                ),
            }
            for data in by_root.values()
        ]
