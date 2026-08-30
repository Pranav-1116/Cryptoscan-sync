"""Firewall and load balancer crypto discovery.

Many enterprises terminate TLS before traffic reaches the application — the
firewall/LB is the crypto boundary. This module models TLS termination
profiles, certificates, cipher policies and VPN policies for the major
vendors (Cisco Firepower, Palo Alto, Fortinet, Check Point, F5, cloud LBs),
fed by injected config/API data or probe observations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

FIREWALL_VENDORS = ("cisco-firepower", "paloalto", "fortinet", "checkpoint", "f5", "cloud-lb")

WEAK_TLS = {"tls1.0", "tls1.1", "ssl3"}


@dataclass
class TlsTerminationProfile:
    """Where TLS is terminated and how."""

    device: str
    device_type: str  # firewall / load_balancer
    vendor: str
    tls_versions: list[str] = field(default_factory=list)
    cipher_policy: str | None = None
    certificates: list[dict[str, Any]] = field(default_factory=list)
    vpn_policy: dict[str, Any] | None = None
    terminator_for: list[str] = field(default_factory=list)  # backend apps

    def to_dict(self) -> dict[str, Any]:
        return {
            "device": self.device,
            "device_type": self.device_type,
            "vendor": self.vendor,
            "tls_versions": list(self.tls_versions),
            "cipher_policy": self.cipher_policy,
            "certificates": list(self.certificates),
            "vpn_policy": self.vpn_policy,
            "terminator_for": list(self.terminator_for),
        }

    @staticmethod
    def _normalize_version(version: str) -> str:
        # "TLSv1.0"/"TLS 1.0"/"TLS1.0" -> "tls1.0"
        return version.lower().replace("tlsv", "tls").replace("tls ", "tls").replace(" ", "")

    def issues(self) -> list[str]:
        issues: list[str] = []
        for version in self.tls_versions:
            if self._normalize_version(version) in WEAK_TLS:
                issues.append(f"WEAK_TLS_VERSION:{self.device}:{version}")
        if self.vpn_policy and (self.vpn_policy.get("encryption") or "").lower() in {"des", "3des"}:
            issues.append(f"WEAK_VPN_ENCRYPTION:{self.device}")
        return sorted(set(issues))


def profile_from_vendor_data(device: str, device_type: str, vendor: str,
                             data: dict[str, Any]) -> TlsTerminationProfile:
    """Build a profile from vendor-shaped config/API data.

    Accepts both snake_case and camelCase keys so injected controller payloads
    (Palo Alto ``tls_profiles``, F5 ``ssl-profiles``, FortiOS ``ssl-ssh-profiles``,
    cloud LB TLS policies) normalize the same way.
    """
    def _pick(*names: str, default: Any = None) -> Any:
        for name in names:
            if name in data and data[name] is not None:
                return data[name]
        return default

    tls_versions = _pick("tls_versions", "tlsVersions", "versions", default=[])
    if isinstance(tls_versions, str):
        tls_versions = [tls_versions]
    certs = _pick("certificates", default=[])
    vpn = _pick("vpn_policy", "vpnPolicy")
    terminator_for = _pick("terminator_for", "terminatorFor", default=[])
    return TlsTerminationProfile(
        device=device, device_type=device_type, vendor=vendor,
        tls_versions=[str(v) for v in tls_versions],
        cipher_policy=_pick("cipher_policy", "cipherPolicy"),
        certificates=list(certs) if isinstance(certs, list) else [],
        vpn_policy=vpn if isinstance(vpn, dict) else None,
        terminator_for=[str(t) for t in terminator_for] if isinstance(terminator_for, list) else [],
    )


def discover_termination_profiles(records: Iterable[dict[str, Any]]) -> list[TlsTerminationProfile]:
    """Records may come from vendor plugins, cloud APIs or passive LB logs."""
    profiles = []
    for record in records:
        profiles.append(profile_from_vendor_data(
            str(record.get("device") or record.get("name") or "lb"),
            str(record.get("device_type") or "load_balancer"),
            str(record.get("vendor") or "unknown"),
            record,
        ))
    return profiles


def terminate_edges(profiles: Iterable[TlsTerminationProfile]) -> list[dict[str, Any]]:
    """Graph edges: LB TERMINATES_TLS_FOR backend app; LB USES_CERTIFICATE."""
    edges: list[dict[str, Any]] = []
    for profile in profiles:
        for backend in profile.terminator_for:
            edges.append({"from": profile.device, "to": backend,
                          "relationship": "TERMINATES_TLS_FOR",
                          "metadata": {"vendor": profile.vendor}})
        for cert in profile.certificates:
            fingerprint = cert.get("fingerprint_sha256") or cert.get("sha256_fingerprint")
            if fingerprint:
                edges.append({"from": profile.device, "to": f"cert:{fingerprint}",
                              "relationship": "USES_CERTIFICATE",
                              "metadata": {"subject": cert.get("subject")}})
    return edges
