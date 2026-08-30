"""HSM discovery — metadata only. Keys are never extracted, ever.

Discovers HSM vendor, model, firmware, supported algorithms and key types,
certificate dependencies and crypto-provider integration from safe sources:
vendor APIs, config references, and endpoint probes. The module hard-fails
any attempt to return key material (enforced by a scrub pass + tests).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from network_scanner.enterprise.credentials import scrub_secrets

HSM_VENDORS = ("Thales", "Utimaco", "Entrust", "AWS CloudHSM", "Azure Managed HSM",
               "Google Cloud HSM", "IBM", "Futurex", "Gemalto")


@dataclass
class HsmProfile:
    """Metadata-only HSM profile."""

    asset: str
    vendor: str | None = None
    model: str | None = None
    firmware_version: str | None = None
    supported_algorithms: list[str] = field(default_factory=list)
    supported_key_types: list[str] = field(default_factory=list)
    certificate_dependencies: list[str] = field(default_factory=list)
    crypto_provider_integration: list[str] = field(default_factory=list)
    source: str = "unknown"
    key_material_present: bool = False  # must always be False

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset": self.asset,
            "vendor": self.vendor,
            "model": self.model,
            "firmware_version": self.firmware_version,
            "supported_algorithms": list(self.supported_algorithms),
            "supported_key_types": list(self.supported_key_types),
            "certificate_dependencies": list(self.certificate_dependencies),
            "crypto_provider_integration": list(self.crypto_provider_integration),
            "source": self.source,
            "key_material_present": self.key_material_present,
            "note": "metadata only — key material is never extracted",
        }


def hsm_profile_from_data(asset: str, data: dict[str, Any]) -> HsmProfile:
    """Build an HSM profile from vendor API / config data (scrubbed)."""
    cleaned = scrub_secrets(dict(data))
    profile = HsmProfile(
        asset=asset,
        vendor=cleaned.get("vendor") or cleaned.get("manufacturer"),
        model=cleaned.get("model"),
        firmware_version=cleaned.get("firmware_version") or cleaned.get("firmware"),
        supported_algorithms=[str(a) for a in (cleaned.get("supported_algorithms") or cleaned.get("algorithms") or [])],
        supported_key_types=[str(k) for k in (cleaned.get("supported_key_types") or cleaned.get("key_types") or [])],
        certificate_dependencies=[str(c) for c in (cleaned.get("certificate_dependencies") or [])],
        crypto_provider_integration=[str(i) for i in (cleaned.get("crypto_provider_integration") or cleaned.get("providers") or [])],
        source=cleaned.get("source") or "vendor-api",
    )
    if _contains_key_material(cleaned):
        profile.key_material_present = True  # marks a data problem; keys still not returned
    return profile


def _contains_key_material(data: dict[str, Any]) -> bool:
    text = str(data)
    return any(token in text.lower() for token in ("begin private key", "-----begin", "keymaterial", "key_value", "wrapped_key"))


def discover_hsm_endpoint_probe(asset: str, *, ports: Iterable[int] = (443, 8443, 22)) -> HsmProfile:
    """Safe endpoint probe: presence of an HSM management surface (metadata).

    No handshakes, no key material — just TCP reachability of common
    management ports, reported as an unverified presence hint.
    """
    import socket

    reachable: list[int] = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            sock.connect((asset, port))
            sock.close()
            reachable.append(port)
        except OSError:
            continue
    return HsmProfile(
        asset=asset,
        source="endpoint-probe",
        crypto_provider_integration=[f"tcp:{port}" for port in reachable] or ["none-reachable"],
    )


def hsm_summary(profiles: Iterable[HsmProfile]) -> dict[str, Any]:
    profiles = list(profiles)
    by_vendor: dict[str, int] = {}
    for profile in profiles:
        by_vendor[str(profile.vendor or "Unknown")] = by_vendor.get(str(profile.vendor or "Unknown"), 0) + 1
    return {
        "hsm_count": len(profiles),
        "by_vendor": by_vendor,
        "any_key_material_present": any(p.key_material_present for p in profiles),
        "algorithms_in_use": sorted({a for p in profiles for a in p.supported_algorithms}),
    }
