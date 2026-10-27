"""Cloud vendor plugins (spec §3): AWS, Microsoft Azure, Google Cloud.

Discover through the operator's authorized credentials: KMS/Key Vault/Cloud
KMS, ACM/PCA/Certificate Manager, compute, containers, networking, databases,
storage. Metadata-only — key material is never fetched (KMS returns key
*metadata*: algorithm, key size, state, rotation).

Without credentials the plugins still emit honest API_VISIBLE observations
from the provided metadata blob (never fabricated).
"""

from __future__ import annotations

from typing import Any

from universal_vendor.models import (
    AssetType,
    CryptoType,
    UniversalObservation,
    VendorCategory,
    Visibility,
)
from universal_vendor.plugin import scrub_secrets
from universal_vendor.plugins._helpers import BannerPluginBase


class _CloudPluginBase(BannerPluginBase):
    _config_keys = ("api_metadata",)

    def validate_connection(self, context: dict[str, Any]):
        """Cloud plugins connect via operator-supplied API metadata or
        credentials (read-only). Detection signals may live inside the
        metadata blob, so presence of the artifact is the gate."""
        from universal_vendor.models import ConnectionResult

        if "api_metadata" not in context:
            return ConnectionResult(
                connected=False,
                message="missing api_metadata: operator-owned credentials or "
                        "API metadata required",
            )
        return ConnectionResult(connected=True,
                                message="cloud API metadata present")

    def _metadata(self, context: dict[str, Any]) -> dict[str, Any]:
        metadata = context.get("api_metadata")
        if isinstance(metadata, str):
            try:
                import json

                metadata = json.loads(metadata)
            except Exception:
                metadata = {}
        return metadata if isinstance(metadata, dict) else {}

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        metadata = self._metadata(context)
        observations = []
        keys = metadata.get("keys") or []
        for key in keys:
            observations.append(self._raw_observation(
                crypto_type=CryptoType.KEY.value,
                algorithm=(key.get("algorithm") or "UNKNOWN"),
                asset_id=key.get("key_id") or key.get("name") or "cloud-key",
                key_size=key.get("key_size"),
                configuration={"state": key.get("state"),
                               "rotation": key.get("rotation_period")},
                visibility=Visibility.API_VISIBLE.value))
        for algo in metadata.get("algorithms") or []:
            observations.append(self._raw_observation(
                crypto_type=CryptoType.ALGORITHM.value, algorithm=str(algo),
                asset_id="cloud", visibility=Visibility.API_VISIBLE.value))
        return observations

    def discover_certificates(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        metadata = self._metadata(context)
        certs = []
        for cert in metadata.get("certificates") or []:
            certs.append({"name": cert.get("name") or cert.get("arn") or cert.get("id"),
                          "type": cert.get("type", "managed"),
                          "expires": cert.get("expires_at"),
                          "algorithm": cert.get("signature_algorithm")})
        return [self._raw_observation(
            crypto_type=CryptoType.CERTIFICATE.value, asset_id="cloud",
            certificate=cert, visibility=Visibility.API_VISIBLE.value)
            for cert in certs]

    def discover_dependencies(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        metadata = self._metadata(context)
        deps = []
        for edge in metadata.get("dependencies") or []:
            deps.append({"asset_id": edge.get("source") or "cloud",
                         "target_asset": edge.get("target"),
                         "relationship": edge.get("relationship", "DEPENDS_ON")})
        return deps

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            product_version=raw.get("product_version"),
            asset_id=raw.get("asset_id") or "cloud",
            asset_type=AssetType.APPLICATION.value,
            region=raw.get("region"),
            crypto_type=raw.get("crypto_type", CryptoType.ALGORITHM.value),
            algorithm=raw.get("algorithm"),
            key_size=raw.get("key_size"),
            certificate=raw.get("certificate"),
            configuration=raw.get("configuration"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", 0.85),
            visibility=raw.get("visibility", Visibility.API_VISIBLE.value),
            vendor_specific=scrub_secrets(raw),
        )


class AwsPlugin(_CloudPluginBase):
    plugin_id = "aws"
    vendor = "AWS"
    product = "AWS"
    category = VendorCategory.CLOUD
    supported_features = ["kms", "acm", "acm_pca", "ec2", "eks", "lambda",
                          "networking", "databases", "storage"]
    api_requirements = ["AWS credentials (operator-owned)"]
    auth_methods = ["access_key", "role_arn", "sso"]
    trusted = True

    _patterns = [
        (r"aws|amazon web services", "AWS", "AWS", 0.8),
        (r"kms|acm", "AWS", "AWS", 0.7),
    ]


class AzurePlugin(_CloudPluginBase):
    plugin_id = "microsoft_azure"
    vendor = "Microsoft"
    product = "Azure"
    category = VendorCategory.CLOUD
    supported_features = ["key_vault", "managed_hsm", "aks", "app_gateway",
                          "front_door", "databases", "storage"]
    api_requirements = ["Azure subscription credentials (operator-owned)"]
    auth_methods = ["service_principal", "managed_identity", "cli"]
    trusted = True

    _patterns = [
        (r"azure", "Microsoft", "Azure", 0.8),
        (r"key vault|managed hsm", "Microsoft", "Azure", 0.75),
    ]


class GcpPlugin(_CloudPluginBase):
    plugin_id = "google_cloud"
    vendor = "Google"
    product = "GCP"
    category = VendorCategory.CLOUD
    supported_features = ["cloud_kms", "certificate_manager",
                          "certificate_authority", "gke", "compute", "cloud_run",
                          "networking"]
    api_requirements = ["GCP service-account credentials (operator-owned)"]
    auth_methods = ["service_account", "workload_identity"]
    trusted = True

    _patterns = [
        (r"google cloud|gcp", "Google", "GCP", 0.8),
        (r"cloud kms|google kms", "Google", "GCP", 0.75),
    ]
