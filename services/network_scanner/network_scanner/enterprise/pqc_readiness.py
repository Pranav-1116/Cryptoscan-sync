"""PQC Network Readiness Scanner — per-asset readiness, unique to this stack.

For every network asset: classical crypto in use, the dependencies that carry
it (IPsec/SSH/TLS…), a PQC status, vendor capability, compatibility, and
migration blockers (HSM dependency, legacy VPN peer, CA dependency).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from network_scanner.enterprise.tunnels import Tunnel, pqc_migration_impact

# vendor -> PQC capability (best-known, updateable; UNKNOWN is honest default)
VENDOR_PQC_CAPABILITY = {
    "cisco": "SUPPORTED",          # IOS-XE 17.x+ offers post-quantum IKE/SSH
    "juniper": "SUPPORTED",
    "paloalto": "SUPPORTED",
    "fortinet": "SUPPORTED",
    "arista": "SUPPORTED",
    "huawei": "UNKNOWN",
    "mikrotik": "UNKNOWN",
    "ubiquiti": "UNKNOWN",
    "vmware": "SUPPORTED",
    "generic": "UNKNOWN",
}

PQ_CLASSICAL = ("RSA", "ECDH", "ECDSA", "DH", "DSA")


@dataclass
class PqcReadiness:
    asset: str
    classical_crypto: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    pqc_status: str = "UNKNOWN"
    vendor_capability: str = "UNKNOWN"
    compatibility: str = "UNKNOWN"
    migration_blockers: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset": self.asset,
            "classical_crypto": list(self.classical_crypto),
            "dependencies": list(self.dependencies),
            "pqc_status": self.pqc_status,
            "vendor_capability": self.vendor_capability,
            "compatibility": self.compatibility,
            "migration_blockers": list(self.migration_blockers),
            "notes": list(self.notes),
        }


def _vendor_of(asset: dict[str, Any]) -> str:
    return str(asset.get("manufacturer") or asset.get("vendor") or "generic").lower()


def assess_asset_readiness(asset: dict[str, Any], *, crypto: list[str] | None = None,
                           dependencies: list[str] | None = None,
                           tunnels: Iterable[Tunnel] = (),
                           has_hsm_dependency: bool = False) -> PqcReadiness:
    """One asset's PQC readiness. Caller supplies what the asset carries."""
    identity = str(asset.get("asset_identity") or asset.get("ip") or "?")
    classical = [c for c in (crypto or []) if c.upper() in PQ_CLASSICAL or c.upper().startswith("RSA")]
    deps = list(dependencies or [])
    blockers: list[str] = []
    if has_hsm_dependency:
        blockers.append("HSM dependency")
    for tunnel in tunnels:
        impact = pqc_migration_impact(tunnel)
        if impact.get("pqc_status") == "MIGRATION_REQUIRED":
            blockers.append(f"Legacy VPN peer ({tunnel.endpoint_b})")
    if any("ca" in str(d).lower() for d in deps):
        blockers.append("Certificate authority dependency")

    vendor = _vendor_of(asset)
    capability = VENDOR_PQC_CAPABILITY.get(vendor, "UNKNOWN")
    if classical:
        status = "MIGRATION_REQUIRED"
    elif not crypto:
        status = "UNKNOWN"
    else:
        status = "COMPATIBLE"
    compatibility = "UNKNOWN"
    if capability == "UNSUPPORTED" and status == "MIGRATION_REQUIRED":
        compatibility = "INCOMPATIBLE"
        blockers.append(f"Vendor capability unsupported ({vendor})")

    return PqcReadiness(
        asset=identity,
        classical_crypto=sorted(set(classical)),
        dependencies=sorted(set(deps)),
        pqc_status=status,
        vendor_capability=capability,
        compatibility=compatibility,
        migration_blockers=blockers,
    )


def network_pqc_readiness(assets: Iterable[dict[str, Any]], *, asset_crypto: dict[str, list[str]] | None = None,
                          asset_deps: dict[str, list[str]] | None = None,
                          tunnels: Iterable[Tunnel] = ()) -> dict[str, Any]:
    """Fleet-level PQC readiness summary."""
    asset_crypto = asset_crypto or {}
    asset_deps = asset_deps or {}
    rows: list[PqcReadiness] = []
    for asset in assets:
        identity = str(asset.get("asset_identity") or asset.get("ip") or "?")
        rows.append(assess_asset_readiness(
            asset,
            crypto=asset_crypto.get(identity) or [],
            dependencies=asset_deps.get(identity) or [],
            tunnels=tunnels,
        ))
    counts: dict[str, int] = {}
    blockers: set[str] = set()
    for row in rows:
        counts[row.pqc_status] = counts.get(row.pqc_status, 0) + 1
        blockers.update(row.migration_blockers)
    return {
        "assets_assessed": len(rows),
        "by_status": counts,
        "migration_blockers": sorted(blockers),
        "assets": [row.to_dict() for row in rows],
    }
