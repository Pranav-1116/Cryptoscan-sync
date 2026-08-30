"""Geographic and international network model.

Global enterprises run the same crypto estate across countries, regions, data
centers, cloud regions, business units and network zones. This module models
that hierarchy and reports crypto exposure geographically.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from network_scanner.enterprise.topology import NetworkGraph


@dataclass
class GeoLocation:
    """One node in the geography hierarchy."""

    country: str
    region: str | None = None
    data_center: str | None = None
    cloud_region: str | None = None
    business_unit: str | None = None
    network_zones: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "country": self.country,
            "region": self.region,
            "data_center": self.data_center,
            "cloud_region": self.cloud_region,
            "business_unit": self.business_unit,
            "network_zones": list(self.network_zones),
        }


DEFAULT_GEOGRAPHY = [
    GeoLocation("UAE", "Dubai", "DXB-DC-1", "me-central-1", "Retail"),
    GeoLocation("UAE", "Abu Dhabi", "AUH-DC-1", "me-central-1", "Government"),
    GeoLocation("India", "Chennai", "MAA-DC-1", "ap-south-1", "Payments"),
    GeoLocation("India", "Mumbai", "BOM-DC-1", "ap-south-1", "Core Banking"),
    GeoLocation("USA", "Virginia", "IAD-DC-1", "us-east-1", "Platform"),
    GeoLocation("USA", "California", "LAX-DC-1", "us-west-2", "Platform"),
]


class GeographyModel:
    def __init__(self, locations: Iterable[GeoLocation] | None = None) -> None:
        # None/empty -> the default enterprise sample geography
        self.locations: list[GeoLocation] = list(locations) if locations else list(DEFAULT_GEOGRAPHY)

    def location_for_asset(self, asset: dict[str, Any]) -> GeoLocation | None:
        """Best-effort asset -> geography mapping by location/zone matching."""
        location = str(asset.get("location") or "").lower()
        zone = str(asset.get("network_zone") or "").lower()
        for geo in self.locations:
            if geo.region and geo.region.lower() in location:
                return geo
            if geo.country.lower() in location:
                return geo
            if geo.data_center and (geo.data_center.lower() in zone
                                    or geo.data_center.lower() in location):
                return geo
        return None

    def exposure_by_geography(self, graph: NetworkGraph, *, assets: Iterable[dict[str, Any]],
                              asset_issues: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """Crypto exposure per country/region/datacenter from graph + assets."""
        asset_issues = asset_issues or {}
        by_country: dict[str, dict[str, Any]] = {}
        by_region: dict[str, dict[str, Any]] = {}
        by_dc: dict[str, dict[str, Any]] = {}
        assets = list(assets)
        for asset in assets:
            identity = str(asset.get("asset_identity") or asset.get("ip") or "?")
            geo = self.location_for_asset(asset)
            if geo is None:
                continue
            issues = asset_issues.get(identity, [])
            exposure = {
                "assets": 1,
                "assets_with_issues": 1 if issues else 0,
                "issue_count": len(issues),
                "critical_assets": 1 if (asset.get("criticality") or "UNKNOWN") == "CRITICAL" else 0,
            }
            for bucket, key in ((by_country, geo.country), (by_region, f"{geo.country}/{geo.region}"),
                                (by_dc, f"{geo.country}/{geo.region}/{geo.data_center}")):
                entry = bucket.setdefault(key, {"assets": 0, "assets_with_issues": 0,
                                                "issue_count": 0, "critical_assets": 0})
                entry["assets"] += exposure["assets"]
                entry["assets_with_issues"] += exposure["assets_with_issues"]
                entry["issue_count"] += exposure["issue_count"]
                entry["critical_assets"] += exposure["critical_assets"]
        return {
            "by_country": by_country,
            "by_region": by_region,
            "by_data_center": by_dc,
        }

    def to_dict(self) -> list[dict[str, Any]]:
        return [loc.to_dict() for loc in self.locations]
