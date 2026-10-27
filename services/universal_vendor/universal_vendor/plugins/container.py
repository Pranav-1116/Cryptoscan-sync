"""Container / registry vendor plugins (spec §13): Docker Engine, Docker Hub,
GitHub Container Registry, GitLab, Azure Container Registry, Amazon ECR,
Google Artifact Registry, Harbor.

Discover (through the existing container scanning surface): container images,
layers, image metadata, base images, registry access, image signing
(cosign/notary), image encryption.
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


class _RegistryPluginBase(BannerPluginBase):
    _config_keys = ("api_metadata",)

    def validate_connection(self, context: dict[str, Any]):
        from universal_vendor.models import ConnectionResult

        if "api_metadata" not in context:
            return ConnectionResult(
                connected=False,
                message="missing api_metadata: registry API metadata required",
            )
        return ConnectionResult(connected=True,
                                message="registry API metadata present")

    def _metadata(self, context: dict[str, Any]) -> dict[str, Any]:
        metadata = context.get("api_metadata")
        if isinstance(metadata, str):
            try:
                import json

                metadata = json.loads(metadata)
            except Exception:
                metadata = {}
        return metadata if isinstance(metadata, dict) else {}

    def discover_inventory(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        metadata = self._metadata(context)
        observations = []
        for image in metadata.get("images") or []:
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="image",
                asset_id=image.get("name") or image.get("repository") or "image",
                configuration={"tag": image.get("tag"),
                               "digest": image.get("digest"),
                               "base_image": image.get("base_image")},
                visibility=Visibility.API_VISIBLE.value))
        return observations

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        metadata = self._metadata(context)
        observations = []
        for algo in extract_algorithms(str(metadata)):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.ALGORITHM.value, algorithm=algo,
                asset_id="registry", visibility=Visibility.API_VISIBLE.value))
        if metadata.get("signing"):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="image-signing",
                asset_id="registry",
                configuration=metadata.get("signing"),
                visibility=Visibility.API_VISIBLE.value))
        return observations

    def discover_dependencies(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        metadata = self._metadata(context)
        deps = []
        for image in metadata.get("images") or []:
            if image.get("base_image"):
                deps.append({"asset_id": image.get("name") or image.get("repository"),
                             "target_asset": image.get("base_image"),
                             "relationship": "BASED_ON"})
        return deps

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            asset_id=raw.get("asset_id") or "container",
            asset_type=AssetType.CONTAINER.value,
            crypto_type=raw.get("crypto_type", CryptoType.ALGORITHM.value),
            algorithm=raw.get("algorithm"),
            configuration=raw.get("configuration"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", 0.85),
            visibility=raw.get("visibility", Visibility.API_VISIBLE.value),
            vendor_specific=scrub_secrets(raw),
        )


class DockerEnginePlugin(_RegistryPluginBase):
    plugin_id = "docker_engine"
    vendor = "Docker"
    product = "Docker Engine"
    category = VendorCategory.CONTAINER
    supported_features = ["images", "layers", "metadata"]
    trusted = True

    _patterns = [
        (r"docker engine|docker daemon", "Docker", "Docker Engine", 0.9),
        (r"docker", "Docker", "Docker Engine", 0.8),
    ]


class DockerHubPlugin(_RegistryPluginBase):
    plugin_id = "docker_hub"
    vendor = "Docker"
    product = "Docker Hub"
    category = VendorCategory.CONTAINER
    supported_features = ["images", "registry"]
    trusted = True

    _patterns = [
        (r"docker hub", "Docker", "Docker Hub", 0.9),
    ]


class GhcrPlugin(_RegistryPluginBase):
    plugin_id = "github_ghcr"
    vendor = "GitHub"
    product = "GHCR"
    category = VendorCategory.CONTAINER
    supported_features = ["images", "registry"]
    trusted = True

    _patterns = [
        (r"ghcr\.io|github container registry", "GitHub", "GHCR", 0.92),
    ]


class AwsEcrPlugin(_RegistryPluginBase):
    plugin_id = "aws_ecr"
    vendor = "AWS"
    product = "ECR"
    category = VendorCategory.CONTAINER
    supported_features = ["images", "registry", "scanning"]
    trusted = True

    _patterns = [
        (r"amazon ecr|\.ecr\.", "AWS", "ECR", 0.92),
    ]


class AzureAcrPlugin(_RegistryPluginBase):
    plugin_id = "azure_acr"
    vendor = "Microsoft"
    product = "Azure Container Registry"
    category = VendorCategory.CONTAINER
    supported_features = ["images", "registry"]
    trusted = True

    _patterns = [
        (r"azure container registry|\.azurecr\.io", "Microsoft",
         "Azure Container Registry", 0.92),
    ]


class GoogleArtifactRegistryPlugin(_RegistryPluginBase):
    plugin_id = "google_artifact_registry"
    vendor = "Google"
    product = "Artifact Registry"
    category = VendorCategory.CONTAINER
    supported_features = ["images", "registry"]
    trusted = True

    _patterns = [
        (r"artifact registry|pkg\.dev", "Google", "Artifact Registry", 0.9),
    ]


class HarborPlugin(_RegistryPluginBase):
    plugin_id = "harbor"
    vendor = "Harbor"
    product = "Harbor"
    category = VendorCategory.CONTAINER
    supported_features = ["images", "registry", "scanning"]
    trusted = True

    _patterns = [
        (r"harbor", "Harbor", "Harbor", 0.88),
    ]
