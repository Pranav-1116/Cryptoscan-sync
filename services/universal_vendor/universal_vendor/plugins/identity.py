"""Identity vendor plugins (spec §6): Keycloak, Microsoft Entra ID, Okta,
Ping Identity, Auth0.

Discover crypto-relevant metadata: signing certificates, federation
certificates, SAML signing configuration, OIDC metadata, JWT signing
algorithms, token signing keys, certificate expiration.
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


class _IdentityPluginBase(BannerPluginBase):
    """Shared OIDC-metadata discovery for identity providers."""

    _config_keys = ()  # detect() decides from banner / oidc_document / config

    def _oidc_metadata(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        metadata = context.get("oidc_document")
        if isinstance(metadata, str):
            try:
                import json

                metadata = json.loads(metadata)
            except Exception:
                metadata = None
        if not isinstance(metadata, dict):
            return []
        observations = []
        algos = metadata.get("id_token_signing_alg_values_supported") or []
        for algo in algos:
            observations.append(self._raw_observation(
                crypto_type=CryptoType.ALGORITHM.value, algorithm=str(algo),
                asset_id="idp", configuration={"use": "id_token_signing"},
                visibility=Visibility.API_VISIBLE.value))
        for algo in metadata.get("token_endpoint_auth_signing_alg_values_supported") or []:
            observations.append(self._raw_observation(
                crypto_type=CryptoType.ALGORITHM.value, algorithm=str(algo),
                asset_id="idp", configuration={"use": "token_endpoint_auth"},
                visibility=Visibility.API_VISIBLE.value))
        if metadata.get("jwks_uri"):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="JWKS",
                asset_id="idp", configuration={"jwks_uri": metadata["jwks_uri"]},
                visibility=Visibility.API_VISIBLE.value))
        return observations

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        observations = self._oidc_metadata(context)
        config = context.get("config", "") or ""
        for algo in extract_algorithms(config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.ALGORITHM.value, algorithm=algo,
                asset_id="idp"))
        return observations

    def discover_certificates(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        certs = []
        metadata = context.get("oidc_document")
        if isinstance(metadata, str):
            try:
                import json

                metadata = json.loads(metadata)
            except Exception:
                metadata = None
        if isinstance(metadata, dict) and metadata.get("jwks_uri"):
            certs.append({"source": "jwks_uri", "uri": metadata["jwks_uri"],
                          "type": "signing-keys"})
        for match in re.finditer(r"signing[ _-]?certificate[=:]\s*(\S+)",
                                 context.get("config", ""), re.IGNORECASE):
            certs.append({"name": match.group(1), "type": "saml-signing"})
        return [self._raw_observation(
            crypto_type=CryptoType.CERTIFICATE.value, asset_id="idp",
            certificate=cert, visibility=Visibility.API_VISIBLE.value)
            for cert in certs]

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            asset_id=raw.get("asset_id") or "idp",
            asset_type=AssetType.IDENTITY_PROVIDER.value,
            crypto_type=raw.get("crypto_type", CryptoType.ALGORITHM.value),
            algorithm=raw.get("algorithm"),
            configuration=raw.get("configuration"),
            certificate=raw.get("certificate"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", 0.9),
            visibility=raw.get("visibility", Visibility.API_VISIBLE.value),
            vendor_specific=scrub_secrets(raw),
        )


class KeycloakPlugin(_IdentityPluginBase):
    plugin_id = "keycloak"
    vendor = "Keycloak"
    product = "Keycloak"
    category = VendorCategory.IDENTITY
    supported_features = ["oidc_metadata", "saml_signing", "jwt_algorithms",
                          "signing_certificates"]
    trusted = True

    _patterns = [
        (r"keycloak", "Keycloak", "Keycloak", 0.92),
    ]


class EntraIdPlugin(_IdentityPluginBase):
    plugin_id = "microsoft_entra_id"
    vendor = "Microsoft"
    product = "Entra ID"
    category = VendorCategory.IDENTITY
    supported_features = ["oidc_metadata", "saml_signing", "jwt_algorithms",
                          "federation_certificates"]
    trusted = True

    _patterns = [
        (r"entra id|azure ad|microsoftonline|sts\.windows", "Microsoft", "Entra ID", 0.9),
    ]


class OktaPlugin(_IdentityPluginBase):
    plugin_id = "okta"
    vendor = "Okta"
    product = "Okta"
    category = VendorCategory.IDENTITY
    supported_features = ["oidc_metadata", "saml_signing", "jwt_algorithms"]
    trusted = True

    _patterns = [
        (r"okta", "Okta", "Okta", 0.9),
    ]


class PingIdentityPlugin(_IdentityPluginBase):
    plugin_id = "ping_identity"
    vendor = "Ping Identity"
    product = "PingFederate"
    category = VendorCategory.IDENTITY
    supported_features = ["oidc_metadata", "saml_signing", "jwt_algorithms"]
    trusted = True

    _patterns = [
        (r"pingidentity|ping federate", "Ping Identity", "PingFederate", 0.9),
    ]
