"""Advanced Asset Discovery — the normalized network asset model.

Assets are the spine of the discovery engine: every protocol observation,
crypto finding, topology edge and PQC readiness record hangs off an
:class:`NetworkAsset`. Fields follow the enterprise schema exactly.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

DEVICE_TYPES = (
    "server", "workstation", "router", "switch", "firewall", "load_balancer",
    "vpn_gateway", "wireless_controller", "proxy", "api_gateway", "hsm",
    "pki", "certificate_server", "dns_server", "directory_server",
    "database_server", "kubernetes_node", "container", "iot_device",
    "ot_device", "cloud_appliance", "unknown",
)

CRITICALITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class NetworkAsset:
    """One discovered network asset."""

    asset_identity: str
    ip_addresses: list[str] = field(default_factory=list)
    ipv6_addresses: list[str] = field(default_factory=list)
    mac_address: str | None = None
    hostname: str | None = None
    fqdn: str | None = None
    device_type: str = "unknown"
    manufacturer: str | None = None
    model: str | None = None
    os: str | None = None
    os_version: str | None = None
    network_zone: str | None = None
    environment: str | None = None
    cloud_provider: str | None = None
    location: str | None = None
    owner: str | None = None
    criticality: str = "UNKNOWN"
    discovery_confidence: float = 0.5  # 0..1
    first_seen: str = field(default_factory=_now)
    last_seen: str = field(default_factory=_now)
    source: str = "manual"
    extra: dict[str, Any] = field(default_factory=dict)

    def touch(self) -> None:
        self.last_seen = _now()

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_identity": self.asset_identity,
            "ip_addresses": list(self.ip_addresses),
            "ipv6_addresses": list(self.ipv6_addresses),
            "mac_address": self.mac_address,
            "hostname": self.hostname,
            "fqdn": self.fqdn,
            "device_type": self.device_type,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "os": self.os,
            "os_version": self.os_version,
            "network_zone": self.network_zone,
            "environment": self.environment,
            "cloud_provider": self.cloud_provider,
            "location": self.location,
            "owner": self.owner,
            "criticality": self.criticality,
            "discovery_confidence": round(self.discovery_confidence, 3),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "source": self.source,
            "extra": dict(self.extra),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NetworkAsset":
        return cls(
            asset_identity=str(data.get("asset_identity") or ""),
            ip_addresses=list(data.get("ip_addresses") or []),
            ipv6_addresses=list(data.get("ipv6_addresses") or []),
            mac_address=data.get("mac_address"),
            hostname=data.get("hostname"),
            fqdn=data.get("fqdn"),
            device_type=data.get("device_type") or "unknown",
            manufacturer=data.get("manufacturer"),
            model=data.get("model"),
            os=data.get("os"),
            os_version=data.get("os_version"),
            network_zone=data.get("network_zone"),
            environment=data.get("environment"),
            cloud_provider=data.get("cloud_provider"),
            location=data.get("location"),
            owner=data.get("owner"),
            criticality=data.get("criticality") or "UNKNOWN",
            discovery_confidence=float(data.get("discovery_confidence") or 0.5),
            first_seen=data.get("first_seen") or _now(),
            last_seen=data.get("last_seen") or _now(),
            source=data.get("source") or "manual",
            extra=dict(data.get("extra") or {}),
        )

    @classmethod
    def from_host(cls, host: str, *, device_type: str = "unknown", **kw: Any) -> "NetworkAsset":
        """Build an asset from a bare host string (IP or FQDN)."""
        identity = host.strip()
        ipv4: list[str] = []
        ipv6: list[str] = []
        hostname = None
        fqdn = None
        if ":" in identity and identity.count(":") >= 2:
            ipv6.append(identity)
        elif _looks_like_ipv4(identity):
            ipv4.append(identity)
        elif "." in identity:
            fqdn = identity
            hostname = identity.split(".", 1)[0]
        else:
            hostname = identity
        return cls(
            asset_identity=identity,
            ip_addresses=ipv4,
            ipv6_addresses=ipv6,
            hostname=hostname,
            fqdn=fqdn,
            device_type=device_type,
            **kw,
        )


def _looks_like_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def normalize_mac(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.replace(":", "").replace("-", "").replace(".", "").lower()
    return ":".join(cleaned[i:i + 2] for i in range(0, 12, 2)) if len(cleaned) == 12 else cleaned or None


class AssetRegistry:
    """Deduplicating asset store keyed by asset_identity."""

    def __init__(self) -> None:
        self._assets: dict[str, NetworkAsset] = {}

    def upsert(self, asset: NetworkAsset) -> NetworkAsset:
        key = asset.asset_identity
        existing = self._assets.get(key)
        if existing is None:
            self._assets[key] = asset
            return asset
        existing.touch()
        # merge new observations into the existing record
        for field_name in ("ip_addresses", "ipv6_addresses"):
            for value in getattr(asset, field_name):
                if value not in getattr(existing, field_name):
                    getattr(existing, field_name).append(value)
        for attr_name in ("mac_address", "hostname", "fqdn", "manufacturer", "model",
                          "os", "os_version", "network_zone", "environment",
                          "cloud_provider", "location", "owner"):
            value = getattr(asset, attr_name)
            if value and not getattr(existing, attr_name):
                setattr(existing, attr_name, value)
        if asset.criticality != "UNKNOWN" and existing.criticality == "UNKNOWN":
            existing.criticality = asset.criticality
        existing.discovery_confidence = max(existing.discovery_confidence, asset.discovery_confidence)
        existing.source = existing.source if existing.source != "manual" else asset.source
        return existing

    def get(self, identity: str) -> NetworkAsset | None:
        return self._assets.get(identity)

    def by_ip(self, ip: str) -> list[NetworkAsset]:
        return [a for a in self._assets.values() if ip in a.ip_addresses or ip in a.ipv6_addresses]

    def all(self) -> list[NetworkAsset]:
        return list(self._assets.values())

    def count(self) -> int:
        return len(self._assets)

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for asset in self._assets.values():
            counts[asset.device_type] = counts.get(asset.device_type, 0) + 1
        return counts

    def to_dicts(self) -> list[dict[str, Any]]:
        return [asset.to_dict() for asset in self.all()]

    def import_records(self, records: Iterable[dict[str, Any]]) -> int:
        added = 0
        for record in records:
            if not record.get("asset_identity"):
                continue
            self.upsert(NetworkAsset.from_dict(record))
            added += 1
        return added


def asset_identity_for(ip: str, *, hostname: str | None = None) -> str:
    """Deterministic identity: prefer FQDN, else IP (stable for dedupe)."""
    hostname = (hostname or "").strip().lower()
    if hostname:
        return hostname
    return ip.strip()
