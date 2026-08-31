"""Live Network + Vendor + Cloud correlation — Asset Identity Resolver (§13).

The network scanner, vendor scanner and cloud scanner must share one asset
identity system. Every identity fingerprint (IP, MAC, hostname, serial,
cloud resource id, vendor asset id) resolves to a single UnifiedAssetRecord
that the graph, blast radius and alert correlation all use.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class AssetIdentity:
    """One identity fingerprint for an asset, from any scanner."""
    kind: str          # "ip" | "mac" | "hostname" | "serial" | "cloud_resource" | "vendor_asset"
    value: str
    source: str        # "network_scanner" | "vendor_scanner" | "cloud_scanner" | ...
    confidence: float = 0.8

    def key(self) -> str:
        return f"{self.kind}:{self.value.lower()}"


@dataclass
class UnifiedAssetRecord:
    asset_id: str
    identities: list[AssetIdentity] = field(default_factory=list)
    vendor: Optional[str] = None
    product: Optional[str] = None
    asset_type: str = "other"
    properties: dict[str, Any] = field(default_factory=dict)

    def identity(self, kind: str) -> Optional[str]:
        for item in self.identities:
            if item.kind == kind:
                return item.value
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "identities": [i.__dict__ for i in self.identities],
            "vendor": self.vendor,
            "product": self.product,
            "asset_type": self.asset_type,
            "properties": self.properties,
        }


class AssetIdentityResolver:
    """Resolves scanner identities into unified asset records.

    Correlation rules (configurable): an IP observed by the network scanner
    can be correlated to a vendor asset by hostname or MAC, and to a cloud
    resource by VPC/subnet metadata or by the vendor↔cloud edges recorded by
    the correlation engine.
    """

    def __init__(self) -> None:
        self._records: dict[str, UnifiedAssetRecord] = {}
        self._by_identity: dict[str, str] = {}  # identity.key() -> asset_id

    def register_identity(self, identity: AssetIdentity,
                          *, asset: Optional[UnifiedAssetRecord] = None) -> str:
        """Register an identity, resolving it to an existing record when
        possible. Returns the canonical asset_id."""
        key = identity.key()
        existing = self._by_identity.get(key)
        if existing:
            record = self._records[existing]
            # enrich: identities on the record can surface a vendor/product
            if asset and asset.vendor and not record.vendor:
                record.vendor = asset.vendor
            if asset and asset.product and not record.product:
                record.product = asset.product
            if asset and asset.asset_type != "other" and record.asset_type == "other":
                record.asset_type = asset.asset_type
            for other in asset.identities:
                self._merge_identity(record, other)
            return record.asset_id

        if asset is None:
            asset = UnifiedAssetRecord(asset_id=self._hash(key), asset_type="other")
        record_id = asset.asset_id
        self._records[record_id] = asset
        for item in asset.identities:
            self._by_identity[item.key()] = record_id
        self._by_identity[key] = record_id
        asset.identities.append(identity)
        return record_id

    def _merge_identity(self, record: UnifiedAssetRecord, identity: AssetIdentity) -> None:
        key = identity.key()
        if key not in self._by_identity and identity not in record.identities:
            record.identities.append(identity)
            self._by_identity[key] = record.asset_id

    @staticmethod
    def _hash(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]

    def resolve(self, *, ip: Optional[str] = None, mac: Optional[str] = None,
                hostname: Optional[str] = None, serial: Optional[str] = None,
                cloud_resource: Optional[str] = None,
                vendor_asset: Optional[str] = None) -> Optional[UnifiedAssetRecord]:
        for kind, value in (("ip", ip), ("mac", mac), ("hostname", hostname),
                            ("serial", serial), ("cloud_resource", cloud_resource),
                            ("vendor_asset", vendor_asset)):
            if not value:
                continue
            asset_id = self._by_identity.get(f"{kind}:{str(value).lower()}")
            if asset_id:
                return self._records[asset_id]
        return None

    def get(self, asset_id: str) -> Optional[UnifiedAssetRecord]:
        return self._records.get(asset_id)

    def all(self) -> list[UnifiedAssetRecord]:
        return list(self._records.values())

    def count(self) -> int:
        return len(self._records)

    def link(self, asset_id: str, identity: AssetIdentity) -> None:
        """Attach an additional identity to an existing record."""
        record = self._records.get(asset_id)
        if record is None:
            self.register_identity(identity)
            return
        self._merge_identity(record, identity)
