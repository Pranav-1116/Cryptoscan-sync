"""ZELNX Cloud Discovery Engine — unified cloud crypto posture (spec §15).

Rolls per-provider posture into one estate-wide picture:

    AWS Crypto Posture + Azure Crypto Posture + GCP Crypto Posture
        ──▶ UNIFIED CRYPTO POSTURE

Metrics: vulnerable crypto assets, weak algorithms, expiring certificates,
non-rotating keys, externally exposed crypto services, critical crypto
dependencies, PQC migration candidates, unknown crypto configurations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cloud_scanner.enterprise.certificate_discovery import CertificateInventory
from cloud_scanner.enterprise.dependency_graph import CloudDependencyGraph
from cloud_scanner.enterprise.encryption_discovery import EncryptionInventory
from cloud_scanner.enterprise.key_discovery import KeyInventory
from cloud_scanner.enterprise.kubernetes_crypto import KubernetesInventory
from cloud_scanner.enterprise.network_crypto import NetworkCryptoInventory
from cloud_scanner.enterprise.pki_intelligence import PkiIntelligence
from cloud_scanner.enterprise.serverless_crypto import ServerlessInventory
from cloud_scanner.enterprise.tls_discovery import (
    PQC_MIGRATION_REQUIRED,
    TLS_LEGACY,
    TLS_WEAK,
    TlsInventory,
    UNKNOWN,
)

PROVIDERS = ("aws", "azure", "gcp")


@dataclass
class ProviderPosture:
    """Posture metrics for one cloud provider."""

    provider: str
    vulnerable_assets: int = 0
    weak_algorithms: int = 0
    expiring_certificates: int = 0
    non_rotating_keys: int = 0
    externally_exposed_crypto: int = 0
    critical_crypto_dependencies: int = 0
    pqc_migration_candidates: int = 0
    unknown_crypto_configurations: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "vulnerable_assets": self.vulnerable_assets,
            "weak_algorithms": self.weak_algorithms,
            "expiring_certificates": self.expiring_certificates,
            "non_rotating_keys": self.non_rotating_keys,
            "externally_exposed_crypto": self.externally_exposed_crypto,
            "critical_crypto_dependencies": self.critical_crypto_dependencies,
            "pqc_migration_candidates": self.pqc_migration_candidates,
            "unknown_crypto_configurations": self.unknown_crypto_configurations,
        }


@dataclass
class CryptoPosture:
    """Per-provider + unified posture."""

    providers: dict[str, ProviderPosture] = field(default_factory=dict)
    metrics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "unified": dict(self.metrics),
            "by_provider": [posture.to_dict() for posture in self.providers.values()],
        }


class PostureEngine:
    """Compute unified posture from the discovery inventories."""

    def __init__(
        self,
        *,
        keys: KeyInventory | None = None,
        certificates: CertificateInventory | None = None,
        pki: PkiIntelligence | None = None,
        encryption: EncryptionInventory | None = None,
        network: NetworkCryptoInventory | None = None,
        tls: TlsInventory | None = None,
        kubernetes: KubernetesInventory | None = None,
        serverless: ServerlessInventory | None = None,
        graph: CloudDependencyGraph | None = None,
        expiring_cert_days: int = 30,
    ) -> None:
        self._keys = keys or KeyInventory()
        self._certificates = certificates or CertificateInventory()
        self._pki = pki or PkiIntelligence()
        self._encryption = encryption or EncryptionInventory()
        self._network = network or NetworkCryptoInventory()
        self._tls = tls or TlsInventory()
        self._kubernetes = kubernetes or KubernetesInventory()
        self._serverless = serverless or ServerlessInventory()
        self._graph = graph or CloudDependencyGraph()
        self._expiring_days = expiring_cert_days

    # ------------------------------------------------------------------

    def evaluate(self) -> CryptoPosture:
        postures = {provider: ProviderPosture(provider=provider) for provider in PROVIDERS}
        expiring = self._certificates.expiring(days=self._expiring_days)
        for provider in PROVIDERS:
            posture = postures[provider]
            posture.vulnerable_assets = self._vulnerable_assets(provider)
            posture.weak_algorithms = self._weak_algorithms(provider)
            posture.expiring_certificates = sum(
                1 for cert in expiring if cert.provider == provider)
            posture.non_rotating_keys = sum(
                1 for key in self._keys.by_provider(provider)
                if key.rotation_enabled is False and key.key_manager == "CUSTOMER_MANAGED"
            )
            posture.externally_exposed_crypto = sum(
                1 for endpoint in
                (self._tls.by_classification(TLS_WEAK)
                 + self._tls.by_classification(TLS_LEGACY))
                if endpoint.provider == provider
            ) + sum(1 for profile in self._network.tls_profiles
                    if profile.provider == provider and profile.weak)
            posture.critical_crypto_dependencies = len(self._graph.by_relation("USES_KEY"))
            posture.pqc_migration_candidates = self._pqc_candidates(provider)
            posture.unknown_crypto_configurations = self._unknown(provider)
        unified = {
            "vulnerable_assets": sum(p.vulnerable_assets for p in postures.values()),
            "weak_algorithms": sum(p.weak_algorithms for p in postures.values()),
            "expiring_certificates": sum(p.expiring_certificates for p in postures.values()),
            "non_rotating_keys": sum(p.non_rotating_keys for p in postures.values()),
            "externally_exposed_crypto": sum(p.externally_exposed_crypto for p in postures.values()),
            "critical_crypto_dependencies": sum(p.critical_crypto_dependencies for p in postures.values()),
            "pqc_migration_candidates": sum(p.pqc_migration_candidates for p in postures.values()),
            "unknown_crypto_configurations": sum(p.unknown_crypto_configurations for p in postures.values()),
            "total_assets": (
                len(self._keys.keys) + len(self._certificates.certificates)
                + len(self._encryption.resources) + len(self._tls.endpoints)
                + len(self._network.tls_profiles) + len(self._network.ipsec_profiles)
                + len(self._kubernetes.clusters) + len(self._serverless.functions)
            ),
        }
        return CryptoPosture(providers=postures, metrics=unified)

    # ------------------------------------------------------------------

    def _vulnerable_assets(self, provider: str) -> int:
        count = 0
        count += sum(1 for e in self._encryption.resources
                     if e.provider == provider and e.at_rest == "NOT_ENCRYPTED")
        count += len(self._tls.by_classification(TLS_WEAK)) + len(self._tls.by_classification(TLS_LEGACY))
        count += len(self._kubernetes.weak_api_tls()) + len(self._kubernetes.unencrypted_secrets())
        count += len(self._serverless.with_weak_tls())
        return count

    def _weak_algorithms(self, provider: str) -> int:
        count = 0
        for key in self._keys.by_provider(provider):
            if key.algorithm in ("RSA",) and key.key_size is not None and key.key_size < 2048:
                count += 1
        count += len(self._pki.weak_chains())
        for profile in self._network.ipsec_profiles:
            if profile.provider == provider and profile.weak:
                count += 1
        return count

    CLASSICAL_PUBLIC_KEY = ("RSA", "ECDSA", "ECDH", "DSA", "DH", "ED25519", "X25519", "EC")

    def _pqc_candidates(self, provider: str) -> int:
        count = len(self._tls.by_classification(PQC_MIGRATION_REQUIRED))
        count += sum(1 for key in self._keys.by_provider(provider)
                     if key.algorithm in self.CLASSICAL_PUBLIC_KEY)
        count += sum(1 for cert in self._certificates.by_provider(provider)
                     if cert.public_key_algorithm in self.CLASSICAL_PUBLIC_KEY)
        return count

    def _unknown(self, provider: str) -> int:
        count = 0
        count += sum(1 for e in self._encryption.resources
                     if e.provider == provider and e.at_rest == "UNKNOWN")
        count += len(self._tls.by_classification(UNKNOWN))
        for cluster in self._kubernetes.clusters:
            if cluster.provider == provider:
                count += int(cluster.etcd_encryption == "UNKNOWN")
                count += int(cluster.secrets_encryption == "UNKNOWN")
        return count
