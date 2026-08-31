"""Kubernetes core scanner + provider adapters (spec §14).

One core scanner handles the standard Kubernetes API; the adapters
(EKS, AKS, GKE, OpenShift, Rancher) only supply *provider-specific*
information on top of the core — they are never separate systems.
"""

from __future__ import annotations

import re
from typing import Any

from universal_vendor.models import (
    AssetType,
    CryptoType,
    UniversalObservation,
    VendorCategory,
    Visibility,
)
from universal_vendor.plugin import scrub_secrets
from universal_vendor.plugins._helpers import BannerPluginBase, extract_algorithms


class KubernetesCorePlugin(BannerPluginBase):
    plugin_id = "kubernetes"
    vendor = "Kubernetes"
    product = "Kubernetes"
    category = VendorCategory.KUBERNETES
    supported_features = ["tls", "certificates", "secrets", "service_accounts",
                          "etcd", "kubelet", "admission_webhooks"]
    trusted = True

    _config_keys = ("kubeconfig",)

    _patterns = [
        (r"kubernetes|k8s", "Kubernetes", "Kubernetes", 0.85),
    ]

    _detection_fields = ("banner", "ssh_banner", "server_header", "config",
                         "kubeconfig", "api_metadata")

    def detect(self, context: dict[str, Any]):
        return self._detect_banner(
            context,
            banner_fields=self._detection_fields,
            patterns=self._patterns,
        )

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        config = context.get("config", "") or ""
        observations = []
        for algo in extract_algorithms(config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.ALGORITHM.value, algorithm=algo,
                asset_id="k8s"))
        for match in re.finditer(r"--tls-cert-file=(\S+)", config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="TLS",
                asset_id="k8s", configuration={"kube-apiserver": match.group(1)},
                protocol="TLS"))
        for match in re.finditer(r"(?:etcd-cafile|etcd-certfile)=(\S+)", config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="etcd-TLS",
                asset_id="k8s",
                configuration={"etcd": match.group(1)},
                protocol="TLS"))
        for match in re.finditer(r"--service-account-signing-key-file=(\S+)", config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="SA-signing",
                asset_id="k8s", configuration={"key": match.group(1)}))
        return observations

    def discover_certificates(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        certs = []
        for match in re.finditer(r"(?:--tls-cert-file|--etcd-certfile)=(\S+)", context.get("config", "")):
            certs.append({"path": match.group(1), "type": "server"})
        return [self._raw_observation(
            crypto_type=CryptoType.CERTIFICATE.value, asset_id="k8s",
            certificate=cert) for cert in certs]

    def discover_inventory(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        metadata = context.get("api_metadata")
        if isinstance(metadata, str):
            try:
                import json

                metadata = json.loads(metadata)
            except Exception:
                metadata = {}
        metadata = metadata if isinstance(metadata, dict) else {}
        observations = []
        for kind in ("namespaces", "deployments", "secrets"):
            for item in metadata.get(kind) or []:
                observations.append(self._raw_observation(
                    crypto_type=CryptoType.CONFIGURATION.value, algorithm=kind.rstrip("s"),
                    asset_id=item if isinstance(item, str) else str(item.get("name", item)),
                    configuration={"kind": kind},
                    visibility=Visibility.API_VISIBLE.value))
        return observations

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            product_version=raw.get("product_version"),
            asset_id=raw.get("asset_id") or "k8s",
            asset_type=AssetType.KUBERNETES.value,
            crypto_type=raw.get("crypto_type", CryptoType.ALGORITHM.value),
            algorithm=raw.get("algorithm"),
            protocol=raw.get("protocol"),
            certificate=raw.get("certificate"),
            configuration=raw.get("configuration"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", 0.85),
            visibility=raw.get("visibility", Visibility.OBSERVED.value),
            vendor_specific=scrub_secrets(raw),
        )


class _KubernetesAdapterBase(KubernetesCorePlugin):
    """Provider adapters layer provider metadata over the core scanner.

    They reuse the core discovery pipeline and add provider observations
    (managed control plane version, provider certificate management).
    """

    _provider_patterns: list[tuple[str, str]] = []
    provider_version_key = "provider_version"

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        observations = super().discover_crypto(context)
        provider_version = context.get(self.provider_version_key)
        if provider_version:
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="control-plane",
                asset_id="k8s", configuration={"provider": self.vendor,
                                               "version": provider_version},
                product_version=provider_version,
                visibility=Visibility.API_VISIBLE.value))
        return observations

    @classmethod
    def detection_patterns(cls) -> list[tuple[str, str, str, float]]:
        patterns = list(KubernetesCorePlugin._patterns)
        for pattern, _product in cls._provider_patterns:
            patterns.append((pattern, cls.vendor, cls.product, 0.9))
        return patterns

    def detect(self, context: dict[str, Any]):
        return self._detect_banner(
            context,
            banner_fields=self._detection_fields,
            patterns=self.detection_patterns(),
        )


class EksPlugin(_KubernetesAdapterBase):
    plugin_id = "aws_eks"
    vendor = "AWS"
    product = "EKS"
    category = VendorCategory.KUBERNETES
    provider_version_key = "eks_version"
    _provider_patterns = [("eks", "eks"), (r"amazon eks", "eks")]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        observations = super().discover_crypto(context)
        if context.get("cmk_arn"):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.KEY.value, algorithm="KMS",
                asset_id="k8s", configuration={"cmk_arn": context["cmk_arn"]},
                visibility=Visibility.API_VISIBLE.value))
        return observations


class AksPlugin(_KubernetesAdapterBase):
    plugin_id = "azure_aks"
    vendor = "Microsoft"
    product = "AKS"
    category = VendorCategory.KUBERNETES
    provider_version_key = "aks_version"
    _provider_patterns = [("aks", "aks"), (r"azure kubernetes", "aks")]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        observations = super().discover_crypto(context)
        if context.get("key_vault_id"):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.KEY.value, algorithm="KeyVault",
                asset_id="k8s", configuration={"key_vault": context["key_vault_id"]},
                visibility=Visibility.API_VISIBLE.value))
        return observations


class GkePlugin(_KubernetesAdapterBase):
    plugin_id = "google_gke"
    vendor = "Google"
    product = "GKE"
    category = VendorCategory.KUBERNETES
    provider_version_key = "gke_version"
    _provider_patterns = [("gke", "gke"), (r"google kubernetes", "gke")]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        observations = super().discover_crypto(context)
        if context.get("cmek_key"):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.KEY.value, algorithm="CloudKMS",
                asset_id="k8s", configuration={"cmek": context["cmek_key"]},
                visibility=Visibility.API_VISIBLE.value))
        return observations


class OpenShiftPlugin(_KubernetesAdapterBase):
    plugin_id = "openshift"
    vendor = "Red Hat"
    product = "OpenShift"
    category = VendorCategory.KUBERNETES
    provider_version_key = "openshift_version"
    _provider_patterns = [("openshift", "openshift"), (r"ocp", "openshift")]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        observations = super().discover_crypto(context)
        config = context.get("config", "") or ""
        for match in re.finditer(r"ingresscontroller.*?servingCertificate", config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="ingress-serving-cert",
                asset_id="k8s"))
        return observations


class RancherPlugin(_KubernetesAdapterBase):
    plugin_id = "rancher"
    vendor = "SUSE"
    product = "Rancher"
    category = VendorCategory.KUBERNETES
    provider_version_key = "rancher_version"
    _provider_patterns = [("rancher", "rancher")]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        observations = super().discover_crypto(context)
        if context.get("cluster_ids"):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="managed-clusters",
                asset_id="k8s", configuration={"clusters": context["cluster_ids"]},
                visibility=Visibility.API_VISIBLE.value))
        return observations
