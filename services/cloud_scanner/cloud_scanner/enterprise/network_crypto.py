"""ZELNX Cloud Discovery Engine — cloud network cryptography (spec §7).

Scans cloud networking for TLS / IPsec / IKE and cryptographic dependencies:

- AWS:    VPC, Transit Gateway, VPN, Direct Connect, Load Balancers,
          CloudFront, API Gateway
- Azure:  Virtual Network, VPN Gateway, ExpressRoute, Application Gateway,
          Front Door, API Management
- GCP:    VPC, Cloud VPN, Cloud Interconnect, Cloud Load Balancing,
          API Gateway

Captures TLS profiles, IPsec/IKE proposals, certificates, encryption
profiles and secure tunnel relationships (which VPCs connect to which VPN
tunnels / interconnects).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from cloud_scanner.enterprise.models import EvidenceSource

NetworkEnumerator = Callable[[], list[dict[str, Any]]]


def _pick(row: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if row.get(name) is not None:
            return row[name]
    return default


WEAK_IKE_ENCRYPTION = ("DES", "3DES")
WEAK_IKE_MAC = ("MD5", "SHA1", "SHA-1")
WEAK_IKE_DH_GROUPS = {1, 2, 5}
WEAK_TLS_TOKENS = ("TLSV1.0", "TLSV1.1", "TLS1.0", "TLS1.1", "SSLV3")


@dataclass
class TlsProfile:
    """One TLS termination profile on a network appliance."""

    profile_id: str
    provider: str = ""
    account: str = ""
    region: str = ""
    service: str = ""  # elb | cloudfront | api_gateway | app_gateway | front_door | ...
    tls_versions: list[str] = field(default_factory=list)
    min_tls: str = ""
    weak: bool = False
    certificate_id: str = ""
    evidence: EvidenceSource = field(default_factory=EvidenceSource)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "provider": self.provider,
            "account": self.account,
            "region": self.region,
            "service": self.service,
            "tls_versions": list(self.tls_versions),
            "min_tls": self.min_tls,
            "weak": self.weak,
            "certificate_id": self.certificate_id,
            "evidence": self.evidence.to_dict(),
        }


@dataclass
class IpsecProfile:
    """One IPsec/IKE proposal on a VPN / Direct Connect / Interconnect."""

    profile_id: str
    provider: str = ""
    account: str = ""
    region: str = ""
    service: str = ""  # vpn | direct_connect | express_route | interconnect
    ike_version: str = ""
    encryption: list[str] = field(default_factory=list)
    integrity: list[str] = field(default_factory=list)
    dh_groups: list[int] = field(default_factory=list)
    pfs: bool | None = None
    weak: bool = False
    evidence: EvidenceSource = field(default_factory=EvidenceSource)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "provider": self.provider,
            "account": self.account,
            "region": self.region,
            "service": self.service,
            "ike_version": self.ike_version,
            "encryption": list(self.encryption),
            "integrity": list(self.integrity),
            "dh_groups": list(self.dh_groups),
            "pfs": self.pfs,
            "weak": self.weak,
            "evidence": self.evidence.to_dict(),
        }


@dataclass
class TunnelRelationship:
    """A secure tunnel / private-connectivity edge (spec §7 + §14)."""

    source: str
    target: str
    kind: str = "VPN_TUNNEL"  # VPN_TUNNEL | PRIVATE_CONNECT | INTERCONNECT | TRANSIT
    provider: str = ""
    account: str = ""
    profile_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "kind": self.kind,
            "provider": self.provider,
            "account": self.account,
            "profile_id": self.profile_id,
        }


def tls_weak(versions: list[str] | None) -> bool:
    return any(any(weak in str(v).upper() for weak in WEAK_TLS_TOKENS) for v in (versions or []))


def ipsec_weak(encryption: list[str] | None, integrity: list[str] | None,
               dh_groups: list[int] | None, pfs: bool | None) -> bool:
    enc = [str(item).upper() for item in (encryption or [])]
    mac = [str(item).upper() for item in (integrity or [])]
    groups = {int(item) for item in (dh_groups or []) if str(item).isdigit()}
    weak = any(any(weak in e for weak in WEAK_IKE_ENCRYPTION) for e in enc)
    weak = weak or any(any(weak in m for weak in WEAK_IKE_MAC) for m in mac)
    weak = weak or bool(groups & WEAK_IKE_DH_GROUPS)
    weak = weak or (pfs is False)
    return weak


@dataclass
class NetworkCryptoInventory:
    """TLS + IPsec profiles and tunnel relationships across clouds."""

    tls_profiles: list[TlsProfile] = field(default_factory=list)
    ipsec_profiles: list[IpsecProfile] = field(default_factory=list)
    tunnels: list[TunnelRelationship] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)

    def to_dicts(self) -> list[dict[str, Any]]:
        return {
            "tls_profiles": [p.to_dict() for p in self.tls_profiles],
            "ipsec_profiles": [p.to_dict() for p in self.ipsec_profiles],
            "tunnels": [t.to_dict() for t in self.tunnels],
            "errors": list(self.errors),
        }

    def weak_profiles(self) -> list[dict[str, Any]]:
        weak = [p.to_dict() for p in self.tls_profiles if p.weak]
        weak += [p.to_dict() for p in self.ipsec_profiles if p.weak]
        return weak

    def summary(self) -> dict[str, Any]:
        return {
            "tls_profiles": len(self.tls_profiles),
            "ipsec_profiles": len(self.ipsec_profiles),
            "tunnels": len(self.tunnels),
            "weak_profiles": len(self.weak_profiles()),
            "errors": self.errors,
        }


class NetworkCryptoDiscovery:
    """Run network crypto discovery for injected enumerators.

    Adapter shape: ``{"provider": "aws", "enumerate_tls": fn,
    "enumerate_ipsec": fn, "enumerate_tunnels": fn}``.
    """

    def __init__(self, providers: list[dict[str, Any]]) -> None:
        self._providers = list(providers)

    def discover(self) -> NetworkCryptoInventory:
        inventory = NetworkCryptoInventory()
        for entry in self._providers:
            provider = str(entry.get("provider") or "").lower()
            for kind, enumerator_key, handler in (
                ("tls", "enumerate_tls", self._tls),
                ("ipsec", "enumerate_ipsec", self._ipsec),
                ("tunnels", "enumerate_tunnels", self._tunnel),
            ):
                enumerator = entry.get(enumerator_key)
                if enumerator is None:
                    continue
                try:
                    rows = enumerator() or []
                except Exception as exc:  # noqa: BLE001
                    inventory.errors.append(
                        {"provider": provider, "kind": kind, "detail": str(exc)[:300]}
                    )
                    continue
                handler(inventory, rows, provider=provider)
        return inventory

    @staticmethod
    def _tls(inventory: NetworkCryptoInventory, rows: list[dict[str, Any]],
             *, provider: str) -> None:
        for row in rows:
            if not isinstance(row, dict):
                continue
            versions = [str(v) for v in (_pick(row, "tls_versions", "protocols", "ssl_protocols",
                                                default=[]) or [])]
            if not versions:
                min_tls = str(_pick(row, "min_tls", "minimum_tls", default="") or "")
                if min_tls:
                    versions = [min_tls]
            profile = TlsProfile(
                profile_id=str(_pick(row, "profile_id", "id", "name", "arn", "policy_name",
                                     default="") or ""),
                provider=provider,
                account=str(_pick(row, "account", default="") or ""),
                region=str(_pick(row, "region", default="") or ""),
                service=str(_pick(row, "service", "type", default="") or ""),
                tls_versions=versions,
                min_tls=str(_pick(row, "min_tls", "minimum_tls", default="") or ""),
                weak=tls_weak(versions) or bool(_pick(row, "weak", default=False)),
                certificate_id=str(_pick(row, "certificate_id", "certificate", default="") or ""),
                evidence=EvidenceSource(
                    source_provider=provider,
                    account=str(_pick(row, "account", default="") or ""),
                    api_source=str(_pick(row, "api_source", default="network-crypto") or ""),
                ),
            )
            inventory.tls_profiles.append(profile)

    @staticmethod
    def _ipsec(inventory: NetworkCryptoInventory, rows: list[dict[str, Any]],
               *, provider: str) -> None:
        for row in rows:
            if not isinstance(row, dict):
                continue
            enc = [str(e) for e in (_pick(row, "encryption", "encryption_algorithms",
                                           default=[]) or [])]
            integrity = [str(m) for m in (_pick(row, "integrity", "integrity_algorithms",
                                                 "mac", default=[]) or [])]
            dh = [int(g) if str(g).isdigit() else g
                  for g in (_pick(row, "dh_groups", "dhGroup", "dh_group", default=[]) or [])]
            pfs = _pick(row, "pfs", "perfect_forward_secrecy", default=None)
            profile = IpsecProfile(
                profile_id=str(_pick(row, "profile_id", "id", "name", "connection_id",
                                     default="") or ""),
                provider=provider,
                account=str(_pick(row, "account", default="") or ""),
                region=str(_pick(row, "region", default="") or ""),
                service=str(_pick(row, "service", "type", default="") or ""),
                ike_version=str(_pick(row, "ike_version", "ike", default="") or ""),
                encryption=enc,
                integrity=integrity,
                dh_groups=dh,
                pfs=pfs,
                weak=ipsec_weak(enc, integrity, dh, pfs) or bool(_pick(row, "weak", default=False)),
                evidence=EvidenceSource(
                    source_provider=provider,
                    account=str(_pick(row, "account", default="") or ""),
                    api_source=str(_pick(row, "api_source", default="network-crypto") or ""),
                ),
            )
            inventory.ipsec_profiles.append(profile)

    @staticmethod
    def _tunnel(inventory: NetworkCryptoInventory, rows: list[dict[str, Any]],
                *, provider: str) -> None:
        for row in rows:
            if not isinstance(row, dict):
                continue
            inventory.tunnels.append(TunnelRelationship(
                source=str(_pick(row, "source", "vpc", "network", default="") or ""),
                target=str(_pick(row, "target", "vpn", "interconnect", default="") or ""),
                kind=str(_pick(row, "kind", default="VPN_TUNNEL") or "VPN_TUNNEL"),
                provider=provider,
                account=str(_pick(row, "account", default="") or ""),
                profile_id=str(_pick(row, "profile_id", default="") or ""),
            ))
