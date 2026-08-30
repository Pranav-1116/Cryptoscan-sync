"""ZELNX Live Cloud Intelligence Engine — continuous Kubernetes (§11) and
serverless (§12) monitoring.

Kubernetes watcher (EKS/AKS/GKE): new namespace / workload / ingress,
certificate changed, mTLS changed, service mesh changed, image changed,
crypto dependency changed.  Pipeline: event → watcher → workload identity
resolver → crypto dependency discovery → targeted re-evaluation.

Serverless watcher (Lambda / Functions / Cloud Functions / Cloud Run):
new deployment / version, dependency change, runtime change, environment
config change, key reference change, certificate reference change → crypto
library analysis → live CBOM update.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cloud_scanner.enterprise.live.event_schema import CloudEvent

K8S_EVENT_TYPES = (
    "K8S_NEW_NAMESPACE", "K8S_NEW_WORKLOAD", "K8S_NEW_INGRESS",
    "K8S_CERTIFICATE_CHANGED", "K8S_MTLS_CHANGED", "K8S_MESH_CHANGED",
    "K8S_IMAGE_CHANGED", "K8S_CRYPTO_DEPENDENCY_CHANGED",
)

SERVERLESS_EVENT_TYPES = (
    "SERVERLESS_NEW_DEPLOYMENT", "SERVERLESS_NEW_VERSION",
    "SERVERLESS_DEPENDENCY_CHANGE", "SERVERLESS_RUNTIME_CHANGE",
    "SERVERLESS_ENV_CONFIG_CHANGE", "SERVERLESS_KEY_REF_CHANGE",
    "SERVERLESS_CERT_REF_CHANGE",
)


def is_k8s_event(event_type: str) -> bool:
    return str(event_type or "") in K8S_EVENT_TYPES


def is_serverless_event(event_type: str) -> bool:
    return str(event_type or "") in SERVERLESS_EVENT_TYPES


@dataclass
class KubernetesChange:
    """One Kubernetes change with identity + crypto dependency resolution."""

    resource_id: str
    event_type: str = ""
    provider: str = ""
    cluster_id: str = ""
    namespace: str = ""
    workload_identity: str = ""
    crypto_dependencies: list[str] = field(default_factory=list)
    targeted_reevaluation: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "event_type": self.event_type,
            "provider": self.provider,
            "cluster_id": self.cluster_id,
            "namespace": self.namespace,
            "workload_identity": self.workload_identity,
            "crypto_dependencies": list(self.crypto_dependencies),
            "targeted_reevaluation": self.targeted_reevaluation,
        }


class KubernetesLiveMonitor:
    """Watch EKS/AKS/GKE changes; resolve workload identity + crypto deps."""

    def __init__(self, *, resolve_identity=None, find_crypto_dependencies=None) -> None:
        self._resolve_identity = resolve_identity or (lambda resource_id: "")
        self._find_crypto = find_crypto_dependencies or (lambda resource_id: [])
        self._changes: list[KubernetesChange] = []

    def watch(self, event: CloudEvent) -> KubernetesChange | None:
        if not is_k8s_event(event.event_type):
            return None
        identity = self._resolve_identity(event.resource_id) or ""
        deps = [str(d) for d in (self._find_crypto(event.resource_id) or [])]
        change = KubernetesChange(
            resource_id=event.resource_id,
            event_type=event.event_type,
            provider=event.provider,
            cluster_id=str(event.provider_metadata.get("cluster_id") or ""),
            namespace=str(event.provider_metadata.get("namespace") or ""),
            workload_identity=identity,
            crypto_dependencies=deps,
            targeted_reevaluation=True,
        )
        self._changes.append(change)
        return change

    def changes(self) -> list[KubernetesChange]:
        return list(self._changes)

    def summary(self) -> dict[str, Any]:
        return {
            "changes": len(self._changes),
            "by_type": {
                event_type: sum(1 for c in self._changes if c.event_type == event_type)
                for event_type in K8S_EVENT_TYPES
            },
        }


@dataclass
class ServerlessChange:
    """One serverless change with crypto-library analysis."""

    resource_id: str
    event_type: str = ""
    provider: str = ""
    runtime: str = ""
    crypto_libraries: list[str] = field(default_factory=list)
    key_references: list[str] = field(default_factory=list)
    certificate_references: list[str] = field(default_factory=list)
    cbom_updated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "event_type": self.event_type,
            "provider": self.provider,
            "runtime": self.runtime,
            "crypto_libraries": list(self.crypto_libraries),
            "key_references": list(self.key_references),
            "certificate_references": list(self.certificate_references),
            "cbom_updated": self.cbom_updated,
        }


class ServerlessLiveMonitor:
    """Watch serverless deployments; analyze crypto surface (injectable)."""

    def __init__(self, *, analyze=None) -> None:
        self._analyze = analyze or (lambda event: ())
        self._changes: list[ServerlessChange] = []

    def watch(self, event: CloudEvent) -> ServerlessChange | None:
        if not is_serverless_event(event.event_type):
            return None
        analysis = self._analyze(event) or {}
        change = ServerlessChange(
            resource_id=event.resource_id,
            event_type=event.event_type,
            provider=event.provider,
            runtime=str(analysis.get("runtime") or ""),
            crypto_libraries=[str(lib) for lib in (analysis.get("crypto_libraries") or [])],
            key_references=[str(ref) for ref in (analysis.get("key_references") or [])],
            certificate_references=[str(ref) for ref in
                                    (analysis.get("certificate_references") or [])],
            cbom_updated=True,
        )
        self._changes.append(change)
        return change

    def changes(self) -> list[ServerlessChange]:
        return list(self._changes)

    def summary(self) -> dict[str, Any]:
        return {
            "changes": len(self._changes),
            "by_type": {
                event_type: sum(1 for c in self._changes if c.event_type == event_type)
                for event_type in SERVERLESS_EVENT_TYPES
            },
        }
