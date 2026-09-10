"""DevOps / source-platform vendor plugins (spec §12): GitHub, GitLab,
Bitbucket, Azure DevOps.

Discover through authorized repository access: source repositories, crypto
dependencies, cryptographic libraries, certificates in repositories,
infrastructure-as-code crypto configuration. Connects to the existing
source-code scanner (``scanner`` service).
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


class _DevOpsPluginBase(BannerPluginBase):
    _config_keys = ("api_metadata",)

    def validate_connection(self, context: dict[str, Any]):
        from universal_vendor.models import ConnectionResult

        if "api_metadata" not in context:
            return ConnectionResult(
                connected=False,
                message="missing api_metadata: repository API metadata required",
            )
        return ConnectionResult(connected=True,
                                message="repository API metadata present")

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
        for dependency in metadata.get("dependencies") or []:
            observations.append(self._raw_observation(
                crypto_type=CryptoType.ALGORITHM.value,
                algorithm=dependency.get("algorithm") or "UNKNOWN",
                asset_id=dependency.get("repo") or "repo",
                configuration={"library": dependency.get("library"),
                                "version": dependency.get("version")},
                visibility=Visibility.API_VISIBLE.value))
        # IaC crypto configuration inside repositories
        for iac in metadata.get("iac") or []:
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="IaC-crypto",
                asset_id=iac.get("repo") or "repo",
                configuration=scrub_secrets(iac),
                visibility=Visibility.API_VISIBLE.value))
        return observations

    def discover_dependencies(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        metadata = self._metadata(context)
        deps = []
        for dependency in metadata.get("dependencies") or []:
            deps.append({"asset_id": dependency.get("repo") or "repo",
                         "target_asset": dependency.get("library"),
                         "relationship": "USES_LIBRARY"})
        return deps

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            asset_id=raw.get("asset_id") or "repo",
            asset_type=AssetType.APPLICATION.value,
            crypto_type=raw.get("crypto_type", CryptoType.ALGORITHM.value),
            algorithm=raw.get("algorithm"),
            configuration=raw.get("configuration"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", 0.85),
            visibility=raw.get("visibility", Visibility.API_VISIBLE.value),
            vendor_specific=scrub_secrets(raw),
        )


class GithubPlugin(_DevOpsPluginBase):
    plugin_id = "github"
    vendor = "GitHub"
    product = "GitHub"
    category = VendorCategory.DEVOPS
    supported_features = ["repositories", "crypto_dependencies", "iac_crypto"]
    api_requirements = ["GitHub token with repo read scope"]
    auth_methods = ["token", "app"]
    trusted = True

    _patterns = [
        (r"github", "GitHub", "GitHub", 0.92),
    ]


class GitlabPlugin(_DevOpsPluginBase):
    plugin_id = "gitlab"
    vendor = "GitLab"
    product = "GitLab"
    category = VendorCategory.DEVOPS
    supported_features = ["repositories", "crypto_dependencies", "iac_crypto"]
    api_requirements = ["GitLab token with read_api scope"]
    auth_methods = ["token", "oauth"]
    trusted = True

    _patterns = [
        (r"gitlab", "GitLab", "GitLab", 0.92),
    ]


class BitbucketPlugin(_DevOpsPluginBase):
    plugin_id = "bitbucket"
    vendor = "Atlassian"
    product = "Bitbucket"
    category = VendorCategory.DEVOPS
    supported_features = ["repositories", "crypto_dependencies"]
    trusted = True

    _patterns = [
        (r"bitbucket", "Atlassian", "Bitbucket", 0.9),
    ]


class AzureDevOpsPlugin(_DevOpsPluginBase):
    plugin_id = "azure_devops"
    vendor = "Microsoft"
    product = "Azure DevOps"
    category = VendorCategory.DEVOPS
    supported_features = ["repositories", "crypto_dependencies", "iac_crypto"]
    trusted = True

    _patterns = [
        (r"azure devops", "Microsoft", "Azure DevOps", 0.9),
    ]
