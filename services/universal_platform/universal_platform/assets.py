"""§1 Universal asset model — the canonical identity for every discovered
asset across the five scanner domains (network, cloud, vendor, hardware,
cryptography).

Every asset carries: a stable identity, its owning domain, one of the
catalogued asset types, the sources that saw it, and evidence. Nothing here
is AI — identity keys are explicit fields provided by the domain adapters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

#: asset types the Universal Discovery Engine knows (§1) — domain-tagged
ASSET_TYPES: dict[str, str] = {
    # network domain
    "ip_range": "network", "subnet": "network", "host": "network",
    "server": "network", "workstation": "network", "network_device": "network",
    "firewall": "network", "router": "network", "switch": "network",
    "load_balancer": "network", "proxy": "network", "vpn_gateway": "network",
    # hardware domain
    "hsm": "hardware", "tpm": "hardware", "storage": "hardware",
    "crypto_accelerator": "hardware", "cpu": "hardware", "gpu": "hardware",
    "nic": "hardware", "raid": "hardware", "hba": "hardware",
    "secure_element": "hardware", "bios": "hardware", "uefi": "hardware",
    "bmc": "hardware", "firmware": "hardware",
    # cloud domain
    "vm": "cloud", "container": "cloud", "kubernetes": "cloud",
    "cloud_resource": "cloud",
    # database / application domain
    "database": "application", "application": "application", "api": "application",
    # crypto domain
    "certificate": "crypto", "crypto_library": "crypto",
    "crypto_implementation": "crypto", "key_metadata": "crypto",
    "algorithm": "crypto", "protocol": "crypto",
    # vendor domain
    "vendor": "vendor", "vendor_product": "vendor",
}

#: identity keys tried in order when correlating assets across domains
IDENTITY_KEYS: list[str] = [
    "asset_id", "hostname", "ip", "fqdn", "mac", "serial", "arn", "uuid",
    "cn", "common_name", "certificate_id", "library", "vendor", "product",
]


@dataclass
class PlatformAsset:
    """A discovered asset in canonical form."""

    asset_type: str
    domain: str
    identity: str
    attributes: dict[str, Any] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    status: str = "ACTIVE"  # ACTIVE | CHANGED | REMOVED | SUSPECT
    first_seen: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat())
    related: list[str] = field(default_factory=list)  # identities it links to

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_type": self.asset_type,
            "domain": self.domain,
            "identity": self.identity,
            "attributes": self.attributes,
            "sources": sorted(set(self.sources)),
            "evidence": self.evidence,
            "status": self.status,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "related": sorted(set(self.related)),
        }


def asset_domain(asset_type: str) -> str:
    """Owning domain for an asset type (``UNKNOWN`` types are honest)."""
    return ASSET_TYPES.get(asset_type, "UNKNOWN")


def pick_identity(row: dict[str, Any]) -> str:
    """Deterministic identity: first present key in priority order."""
    for key in IDENTITY_KEYS:
        value = row.get(key)
        if value not in (None, "", []):
            return str(value)
    return "asset"


def normalize_asset(row: dict[str, Any]) -> PlatformAsset:
    """Turn one domain report row into a canonical platform asset."""
    asset_type = str(row.get("asset_type") or row.get("type")
                     or row.get("device_type") or "asset")
    domain = str(row.get("domain") or asset_domain(asset_type))
    identity = str(row.get("identity") or pick_identity(row))
    attributes = {k: v for k, v in row.items()
                  if k not in ("asset_type", "type", "domain", "identity",
                               "sources", "evidence", "status")}
    return PlatformAsset(
        asset_type=asset_type, domain=domain, identity=identity,
        attributes=attributes,
        sources=list(row.get("sources") or [row.get("source") or "platform"]),
        evidence=list(row.get("evidence") or []),
        status=str(row.get("status") or "ACTIVE"),
    )
