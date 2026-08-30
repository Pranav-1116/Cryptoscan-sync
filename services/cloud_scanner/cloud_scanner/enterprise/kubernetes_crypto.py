"""ZELNX Cloud Discovery Engine — Kubernetes crypto discovery (spec §9).

A separate major feature: EKS / AKS / GKE crypto posture.

    Cluster
       ├── Node
       ├── Namespace
       ├── Workload  ── Crypto Dependency
       ├── Ingress   ── Certificate
       └── Service Mesh ── mTLS

Discovers (metadata only, read-only config APIs):
- Kubernetes API TLS version + cipher policy
- etcd encryption configuration metadata
- secrets encryption configuration metadata (provider KMS references)
- ingress TLS + cert-manager certificates
- service mesh mTLS mode
- workload identity
- crypto libraries inside workloads / container image cryptography
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from cloud_scanner.enterprise.models import EvidenceSource

ClusterEnumerator = Callable[[], list[dict[str, Any]]]


def _pick(row: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if row.get(name) is not None:
            return row[name]
    return default


@dataclass
class IngressTls:
    """One ingress host + its TLS certificate."""

    host: str
    certificate_id: str = ""
    secret_name: str = ""
    issuer: str = ""
    tls_min_version: str = ""
    namespace: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "certificate_id": self.certificate_id,
            "secret_name": self.secret_name,
            "issuer": self.issuer,
            "tls_min_version": self.tls_min_version,
            "namespace": self.namespace,
        }


@dataclass
class WorkloadCrypto:
    """One workload's crypto dependency surface (libraries + keys + certs)."""

    workload: str
    namespace: str = ""
    crypto_libraries: list[str] = field(default_factory=list)
    key_references: list[str] = field(default_factory=list)
    certificate_references: list[str] = field(default_factory=list)
    image: str = ""
    image_digest: str = ""
    identity: str = ""
    mtls: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "workload": self.workload,
            "namespace": self.namespace,
            "crypto_libraries": list(self.crypto_libraries),
            "key_references": list(self.key_references),
            "certificate_references": list(self.certificate_references),
            "image": self.image,
            "image_digest": self.image_digest,
            "identity": self.identity,
            "mtls": self.mtls,
        }


@dataclass
class ClusterCrypto:
    """One cluster's crypto posture."""

    cluster_id: str
    provider: str = ""
    account: str = ""
    region: str = ""
    api_tls_version: str = ""
    api_tls_ciphers: list[str] = field(default_factory=list)
    api_tls_weak: bool = False
    etcd_encryption: str = "UNKNOWN"  # ENABLED | DISABLED | UNKNOWN
    secrets_encryption: str = "UNKNOWN"  # KMS_ENCRYPTED | DISABLED | UNKNOWN
    secrets_key_reference: str = ""
    nodes: list[str] = field(default_factory=list)
    namespaces: list[str] = field(default_factory=list)
    ingress_tls: list[IngressTls] = field(default_factory=list)
    workloads: list[WorkloadCrypto] = field(default_factory=list)
    mesh: str = "NONE"  # NONE | ISTIO | LINKERD | CONSUL | ...
    mesh_mtls: str = "UNKNOWN"  # STRICT | PERMISSIVE | DISABLED | UNKNOWN
    evidence: EvidenceSource = field(default_factory=EvidenceSource)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "provider": self.provider,
            "account": self.account,
            "region": self.region,
            "api_tls_version": self.api_tls_version,
            "api_tls_ciphers": list(self.api_tls_ciphers),
            "api_tls_weak": self.api_tls_weak,
            "etcd_encryption": self.etcd_encryption,
            "secrets_encryption": self.secrets_encryption,
            "secrets_key_reference": self.secrets_key_reference,
            "nodes": list(self.nodes),
            "namespaces": list(self.namespaces),
            "ingress_tls": [ing.to_dict() for ing in self.ingress_tls],
            "workloads": [w.to_dict() for w in self.workloads],
            "mesh": self.mesh,
            "mesh_mtls": self.mesh_mtls,
            "evidence": self.evidence.to_dict(),
        }


@dataclass
class KubernetesInventory:
    """All clusters across providers."""

    clusters: list[ClusterCrypto] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)

    def to_dicts(self) -> list[dict[str, Any]]:
        return [cluster.to_dict() for cluster in self.clusters]

    def count(self, provider: str | None = None) -> int:
        if provider is None:
            return len(self.clusters)
        return sum(1 for c in self.clusters if c.provider == provider)

    def unencrypted_secrets(self) -> list[ClusterCrypto]:
        return [c for c in self.clusters if c.secrets_encryption == "DISABLED"]

    def weak_api_tls(self) -> list[ClusterCrypto]:
        return [c for c in self.clusters if c.api_tls_weak]

    def summary(self) -> dict[str, Any]:
        return {
            "clusters": len(self.clusters),
            "by_provider": {
                provider: self.count(provider) for provider in ("aws", "azure", "gcp")
            },
            "secrets_encryption_disabled": len(self.unencrypted_secrets()),
            "weak_api_tls": len(self.weak_api_tls()),
            "workloads": sum(len(c.workloads) for c in self.clusters),
            "ingress_hosts": sum(len(c.ingress_tls) for c in self.clusters),
            "errors": self.errors,
        }


class KubernetesCryptoDiscovery:
    """Discover cluster crypto posture from injected enumerators.

    Adapter shape: ``{"provider": "aws", "enumerate_clusters": fn}`` where
    each row carries the full cluster + ingress + workload details.
    """

    def __init__(self, providers: list[dict[str, Any]]) -> None:
        self._providers = list(providers)

    def discover(self) -> KubernetesInventory:
        inventory = KubernetesInventory()
        for entry in self._providers:
            provider = str(entry.get("provider") or "").lower()
            enumerator = entry.get("enumerate_clusters")
            if enumerator is None:
                continue
            try:
                rows = enumerator() or []
            except Exception as exc:  # noqa: BLE001
                inventory.errors.append(
                    {"provider": provider, "kind": "enumerate", "detail": str(exc)[:300]}
                )
                continue
            for row in rows:
                if isinstance(row, dict):
                    inventory.clusters.append(self._cluster(row, provider=provider))
        return inventory

    @staticmethod
    def _cluster(row: dict[str, Any], *, provider: str) -> ClusterCrypto:
        api_version = str(_pick(row, "api_tls_version", "tls_version", default="") or "")
        ciphers = [str(c) for c in (_pick(row, "api_tls_ciphers", "tls_ciphers", default=[]) or [])]
        weak = (
            any(weak in api_version.upper() for weak in ("TLS1.0", "TLS1.1", "SSLV3"))
            or bool(_pick(row, "api_tls_weak", default=False))
        )
        secrets_enc = str(_pick(row, "secrets_encryption", "secrets_encryption_config",
                                "secretsEncryption", default="UNKNOWN") or "UNKNOWN").upper()
        etcd_enc = str(_pick(row, "etcd_encryption", "etcd_encryption_config",
                             "etcdEncryption", default="UNKNOWN") or "UNKNOWN").upper()
        ingress_rows = _pick(row, "ingress_tls", "ingresses", default=[]) or []
        workload_rows = _pick(row, "workloads", "workload_crypto", default=[]) or []
        return ClusterCrypto(
            cluster_id=str(_pick(row, "cluster_id", "id", "name", "arn", default="") or ""),
            provider=provider,
            account=str(_pick(row, "account", "subscription", "project", default="") or ""),
            region=str(_pick(row, "region", default="") or ""),
            api_tls_version=api_version,
            api_tls_ciphers=ciphers,
            api_tls_weak=weak,
            etcd_encryption=etcd_enc,
            secrets_encryption=secrets_enc,
            secrets_key_reference=str(_pick(row, "secrets_key_reference", "secrets_kms_key",
                                            "secretsKeyReference", default="") or ""),
            nodes=[str(n) for n in (_pick(row, "nodes", default=[]) or [])],
            namespaces=[str(n) for n in (_pick(row, "namespaces", default=[]) or [])],
            ingress_tls=[IngressTls(
                host=str(_pick(ing, "host", "hostname", default="") or ""),
                certificate_id=str(_pick(ing, "certificate_id", "certificate", default="") or ""),
                secret_name=str(_pick(ing, "secret_name", default="") or ""),
                issuer=str(_pick(ing, "issuer", "cert_manager_issuer", default="") or ""),
                tls_min_version=str(_pick(ing, "tls_min_version", default="") or ""),
                namespace=str(_pick(ing, "namespace", default="") or ""),
            ) for ing in ingress_rows],
            workloads=[WorkloadCrypto(
                workload=str(_pick(w, "workload", "name", "workload_id", default="") or ""),
                namespace=str(_pick(w, "namespace", default="") or ""),
                crypto_libraries=[str(l) for l in (_pick(w, "crypto_libraries", "libraries",
                                                         default=[]) or [])],
                key_references=[str(k) for k in (_pick(w, "key_references", "keys", default=[]) or [])],
                certificate_references=[str(c) for c in (_pick(w, "certificate_references",
                                                               "certificates", default=[]) or [])],
                image=str(_pick(w, "image", default="") or ""),
                image_digest=str(_pick(w, "image_digest", default="") or ""),
                identity=str(_pick(w, "identity", "workload_identity", default="") or ""),
                mtls=_pick(w, "mtls", default=None),
            ) for w in workload_rows],
            mesh=str(_pick(row, "mesh", "service_mesh", default="NONE") or "NONE"),
            mesh_mtls=str(_pick(row, "mesh_mtls", "mtls_mode", "mtls",
                               default="UNKNOWN") or "UNKNOWN").upper(),
            evidence=EvidenceSource(
                source_provider=provider,
                account=str(_pick(row, "account", "subscription", "project", default="") or ""),
                api_source=str(_pick(row, "api_source", default="kubernetes-crypto") or ""),
            ),
        )
