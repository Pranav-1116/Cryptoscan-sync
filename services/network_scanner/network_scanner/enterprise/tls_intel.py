"""TLS Intelligence Engine — deep per-endpoint TLS posture + profiles.

Aggregates probe results into a rich TLS observation per endpoint and builds
the four profiles: TLS_CONFIGURATION_PROFILE, CERTIFICATE_PROFILE,
CIPHER_PROFILE and CRYPTOGRAPHIC_STRENGTH_PROFILE.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

WEAK_TLS_VERSIONS = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3"}
DEPRECATED_CIPHERS = {"RC4", "DES", "3DES", "CBC-SHA", "EXPORT", "NULL"}


@dataclass
class TlsIntelligence:
    """Deep TLS observation for one endpoint."""

    endpoint: str
    tls_versions_supported: list[str] = field(default_factory=list)
    negotiated_tls_version: str | None = None
    cipher_suites_supported: list[str] = field(default_factory=list)
    negotiated_cipher_suite: str | None = None
    signature_algorithms: list[str] = field(default_factory=list)
    key_exchange: str | None = None
    key_size: int | None = None
    elliptic_curves: list[str] = field(default_factory=list)
    alpn: list[str] = field(default_factory=list)
    sni_behavior: str | None = None
    session_resumption: str | None = None
    ocsp_stapling: bool | None = None
    certificate_chain: list[dict[str, Any]] = field(default_factory=list)
    certificate_fingerprints: list[str] = field(default_factory=list)
    trust_chain_verified: bool | None = None
    certificate_expiration: str | None = None
    certificate_reuse: int = 0
    weak_protocol_configuration: list[str] = field(default_factory=list)
    deprecated_cipher_configuration: list[str] = field(default_factory=list)
    source_findings: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "tls_versions_supported": list(self.tls_versions_supported),
            "negotiated_tls_version": self.negotiated_tls_version,
            "cipher_suites_supported": list(self.cipher_suites_supported),
            "negotiated_cipher_suite": self.negotiated_cipher_suite,
            "signature_algorithms": list(self.signature_algorithms),
            "key_exchange": self.key_exchange,
            "key_size": self.key_size,
            "elliptic_curves": list(self.elliptic_curves),
            "alpn": list(self.alpn),
            "sni_behavior": self.sni_behavior,
            "session_resumption": self.session_resumption,
            "ocsp_stapling": self.ocsp_stapling,
            "certificate_chain": list(self.certificate_chain),
            "certificate_fingerprints": list(self.certificate_fingerprints),
            "trust_chain_verified": self.trust_chain_verified,
            "certificate_expiration": self.certificate_expiration,
            "certificate_reuse": self.certificate_reuse,
            "weak_protocol_configuration": list(self.weak_protocol_configuration),
            "deprecated_cipher_configuration": list(self.deprecated_cipher_configuration),
            "source_findings": self.source_findings,
        }


def build_tls_intelligence(endpoint: str, findings: Iterable[dict[str, Any]]) -> TlsIntelligence:
    """Aggregate one endpoint's probe findings into deep TLS intelligence."""
    info = TlsIntelligence(endpoint=endpoint)
    versions: set[str] = set()
    ciphers: set[str] = set()
    fingerprints: set[str] = set()
    for finding in findings:
        crypto = finding.get("crypto") or {}
        version = crypto.get("tls_version")
        cipher = crypto.get("cipher_suite")
        if version:
            versions.add(version)
            info.negotiated_tls_version = info.negotiated_tls_version or version
        if cipher:
            ciphers.add(cipher)
            info.negotiated_cipher_suite = info.negotiated_cipher_suite or cipher
        if crypto.get("algorithm"):
            info.key_exchange = info.key_exchange or crypto.get("algorithm")
        if crypto.get("key_size"):
            info.key_size = info.key_size or crypto.get("key_size")
        if crypto.get("curve"):
            info.elliptic_curves.append(crypto["curve"])
        for cert in finding.get("certificates") or []:
            fp = cert.get("fingerprint_sha256") or cert.get("sha256_fingerprint")
            if fp:
                fingerprints.add(fp)
            if cert.get("not_after"):
                info.certificate_expiration = cert["not_after"]
            info.certificate_chain.append({
                "subject": cert.get("subject"),
                "issuer": cert.get("issuer"),
                "fingerprint_sha256": fp,
                "not_after": cert.get("not_after"),
            })
        if crypto.get("alpn"):
            info.alpn.extend(crypto["alpn"] if isinstance(crypto["alpn"], list) else [crypto["alpn"]])
        if crypto.get("signature_algorithm"):
            info.signature_algorithms.append(crypto["signature_algorithm"])
        if finding.get("ocsp_stapling") is not None:
            info.ocsp_stapling = bool(finding["ocsp_stapling"])
        if finding.get("session_resumption"):
            info.session_resumption = finding["session_resumption"]
        if finding.get("sni_behavior"):
            info.sni_behavior = finding["sni_behavior"]
        if finding.get("chain_verified") is not None:
            info.trust_chain_verified = bool(finding["chain_verified"])
        info.source_findings += 1

    info.tls_versions_supported = sorted(versions)
    info.cipher_suites_supported = sorted(ciphers)
    info.certificate_fingerprints = sorted(fingerprints)
    for version in versions:
        if version in WEAK_TLS_VERSIONS:
            info.weak_protocol_configuration.append(version)
    for cipher in ciphers:
        upper = cipher.upper()
        if any(token in upper for token in DEPRECATED_CIPHERS):
            info.deprecated_cipher_configuration.append(cipher)
    return info


# ------------------------------------------------------------------ profiles


def tls_configuration_profile(info: TlsIntelligence) -> dict[str, Any]:
    weak = list(info.weak_protocol_configuration)
    grade = "WEAK" if weak else ("STRONG" if info.negotiated_tls_version == "TLSv1.3" else "ACCEPTABLE")
    return {
        "profile_type": "TLS_CONFIGURATION_PROFILE",
        "endpoint": info.endpoint,
        "grade": grade,
        "supported_versions": info.tls_versions_supported,
        "negotiated_version": info.negotiated_tls_version,
        "weak_versions": weak,
        "recommendation": "disable TLS 1.0/1.1; prefer TLS 1.3" if weak else "ok",
    }


def certificate_profile(info: TlsIntelligence) -> dict[str, Any]:
    return {
        "profile_type": "CERTIFICATE_PROFILE",
        "endpoint": info.endpoint,
        "chain_length": len(info.certificate_chain),
        "fingerprints": info.certificate_fingerprints,
        "trust_verified": info.trust_chain_verified,
        "expiration": info.certificate_expiration,
        "reuse_count": info.certificate_reuse,
        "ocsp_stapling": info.ocsp_stapling,
    }


def cipher_profile(info: TlsIntelligence) -> dict[str, Any]:
    return {
        "profile_type": "CIPHER_PROFILE",
        "endpoint": info.endpoint,
        "cipher_suites": info.cipher_suites_supported,
        "negotiated_cipher": info.negotiated_cipher_suite,
        "deprecated_ciphers": info.deprecated_cipher_configuration,
    }


def cryptographic_strength_profile(info: TlsIntelligence) -> dict[str, Any]:
    """Overall strength grade from protocol + cipher + key size."""
    score = 100
    reasons: list[str] = []
    if info.weak_protocol_configuration:
        score -= 40
        reasons.append("weak TLS version configured")
    if info.deprecated_cipher_configuration:
        score -= 30
        reasons.append("deprecated ciphers configured")
    if info.key_size and info.key_size < 2048:
        score -= 20
        reasons.append(f"key size {info.key_size} < 2048")
    if info.ocsp_stapling is False:
        score -= 5
        reasons.append("OCSP stapling disabled")
    grade = "STRONG" if score >= 85 else ("ACCEPTABLE" if score >= 60 else "WEAK")
    return {
        "profile_type": "CRYPTOGRAPHIC_STRENGTH_PROFILE",
        "endpoint": info.endpoint,
        "grade": grade,
        "score": max(0, score),
        "reasons": reasons,
    }


def profile_all(info: TlsIntelligence) -> list[dict[str, Any]]:
    return [
        tls_configuration_profile(info),
        certificate_profile(info),
        cipher_profile(info),
        cryptographic_strength_profile(info),
    ]


def build_profiles(endpoint: str, findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return profile_all(build_tls_intelligence(endpoint, findings))
