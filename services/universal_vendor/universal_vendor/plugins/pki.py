"""PKI vendor plugins (spec §4): HashiCorp Vault PKI, Microsoft AD CS,
OpenSSL internal PKI, Entrust.

Discover: root CA, intermediate CA, issuing CA, certificate consumers,
trust stores, revocation services, RSA/ECC, signature algorithms,
expiration, key sizes, CA dependencies, PQC migration blockers.
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


class HashiCorpVaultPkiPlugin(BannerPluginBase):
    plugin_id = "hashicorp_vault_pki"
    vendor = "HashiCorp"
    product = "Vault PKI"
    category = VendorCategory.PKI
    supported_features = ["root_ca", "intermediate_ca", "issuing_ca",
                          "certificates", "trust_stores", "revocation",
                          "key_sizes", "signature_algorithms"]
    api_requirements = ["Vault API or configuration"]
    auth_methods = ["token", "approle", "cert"]
    trusted = True

    _patterns = [
        (r"hashi(?:\.)?corp vault", "HashiCorp", "Vault PKI", 0.95),
        (r"pki_mount|vault write pki", "HashiCorp", "Vault PKI", 0.85),
    ]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        config = context.get("config", "") or context.get("api_metadata", "") or ""
        observations = []
        for algo in extract_algorithms(config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.ALGORITHM.value, algorithm=algo,
                asset_id="vault-pki"))
        # key type / bits from vault pki role config
        for match in re.finditer(r"key_type=(\S+)", config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.KEY.value, key_type=match.group(1),
                algorithm="CA", asset_id="vault-pki"))
        for match in re.finditer(r"key_bits=(\d+)", config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.KEY.value, key_size=int(match.group(1)),
                asset_id="vault-pki"))
        for match in re.finditer(r"signature_bits=(\d+)", config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="SHA",
                asset_id="vault-pki",
                configuration={"signature_bits": match.group(1)}))
        return observations

    def discover_certificates(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        certs = []
        for match in re.finditer(r"pki(?:/|_mount\s+)(\S+?)", context.get("config", "")):
            certs.append({"mount": match.group(1), "type": "pki-engine"})
        if "ca_chain" in context.get("api_metadata", ""):
            certs.append({"type": "ca_chain", "source": "api_metadata"})
        return [self._raw_observation(
            crypto_type=CryptoType.CERTIFICATE.value, asset_id="vault-pki",
            certificate=cert, visibility=Visibility.API_VISIBLE.value)
            for cert in certs]

    def discover_dependencies(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        deps = []
        for match in re.finditer(r"(?:issue|sign)\s+(\S+)", context.get("config", "")):
            deps.append({"asset_id": "vault-pki", "target_asset": match.group(1),
                         "relationship": "ISSUES"})
        return deps

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            asset_id=raw.get("asset_id") or "vault-pki",
            asset_type=AssetType.CA.value,
            crypto_type=raw.get("crypto_type", CryptoType.ALGORITHM.value),
            algorithm=raw.get("algorithm"),
            key_type=raw.get("key_type"),
            key_size=raw.get("key_size"),
            certificate=raw.get("certificate"),
            configuration=raw.get("configuration"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", 0.9),
            visibility=raw.get("visibility", Visibility.OBSERVED.value),
            vendor_specific=scrub_secrets(raw),
        )


class AdcsPlugin(BannerPluginBase):
    plugin_id = "microsoft_adcs"
    vendor = "Microsoft"
    product = "AD CS"
    category = VendorCategory.PKI
    supported_features = ["root_ca", "issuing_ca", "certificates",
                          "trust_stores", "revocation", "key_sizes"]
    trusted = True

    _patterns = [
        (r"active directory certificate services|adcs", "Microsoft", "AD CS", 0.92),
        (r"certsvc|pki.*windows", "Microsoft", "AD CS", 0.8),
    ]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        config = context.get("config", "")
        observations = []
        for algo in extract_algorithms(config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.ALGORITHM.value, algorithm=algo,
                asset_id="adcs"))
        for match in re.finditer(r"KeyLength=(\d+)", config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.KEY.value, key_size=int(match.group(1)),
                asset_id="adcs"))
        for match in re.finditer(r"(?:HashAlgorithm|SignatureAlgorithm)=(\S+)", config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.ALGORITHM.value, algorithm=match.group(1),
                asset_id="adcs"))
        return observations

    def discover_certificates(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        certs = []
        for match in re.finditer(r"(?:CA|IssuingCA)=(\S+)", context.get("config", "")):
            certs.append({"name": match.group(1), "type": "issuing-ca"})
        return [self._raw_observation(
            crypto_type=CryptoType.CERTIFICATE.value, asset_id="adcs",
            certificate=cert) for cert in certs]

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            asset_id=raw.get("asset_id") or "adcs",
            asset_type=AssetType.CA.value,
            crypto_type=raw.get("crypto_type", CryptoType.ALGORITHM.value),
            algorithm=raw.get("algorithm"),
            key_size=raw.get("key_size"),
            certificate=raw.get("certificate"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", 0.9),
            visibility=raw.get("visibility", Visibility.OBSERVED.value),
            vendor_specific=scrub_secrets(raw),
        )


class OpenSslPkiPlugin(BannerPluginBase):
    plugin_id = "openssl_internal_pki"
    vendor = "OpenSSL"
    product = "Internal PKI"
    category = VendorCategory.PKI
    supported_features = ["root_ca", "issuing_ca", "certificates",
                          "revocation", "key_sizes"]
    trusted = True

    _patterns = [
        (r"openssl", "OpenSSL", "Internal PKI", 0.7),
    ]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        config = context.get("config", "")
        observations = []
        for algo in extract_algorithms(config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.ALGORITHM.value, algorithm=algo,
                asset_id="openssl-ca"))
        for match in re.finditer(r"default_bits\s*=\s*(\d+)", config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.KEY.value, key_size=int(match.group(1)),
                asset_id="openssl-ca"))
        for match in re.finditer(r"default_md\s*=\s*(\S+)", config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.ALGORITHM.value, algorithm=match.group(1),
                asset_id="openssl-ca"))
        return observations

    def discover_certificates(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        certs = []
        config = context.get("config", "")
        for match in re.finditer(r"dir\s*=\s*(\S+)", config):
            certs.append({"dir": match.group(1), "type": "ca-directory"})
        return [self._raw_observation(
            crypto_type=CryptoType.CERTIFICATE.value, asset_id="openssl-ca",
            certificate=cert) for cert in certs]

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            asset_id=raw.get("asset_id") or "openssl-ca",
            asset_type=AssetType.CA.value,
            crypto_type=raw.get("crypto_type", CryptoType.ALGORITHM.value),
            algorithm=raw.get("algorithm"),
            key_size=raw.get("key_size"),
            certificate=raw.get("certificate"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", 0.8),
            visibility=raw.get("visibility", Visibility.OBSERVED.value),
            vendor_specific=scrub_secrets(raw),
        )


class EntrustPkiPlugin(BannerPluginBase):
    plugin_id = "entrust_pki"
    vendor = "Entrust"
    product = "PKI"
    category = VendorCategory.PKI
    supported_features = ["certificates", "issuing_ca"]
    trusted = True

    _patterns = [
        (r"entrust", "Entrust", "PKI", 0.85),
    ]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        config = context.get("config", "") or context.get("api_metadata", "") or ""
        return [self._raw_observation(
            crypto_type=CryptoType.ALGORITHM.value, algorithm=algo,
            asset_id="entrust-pki", visibility=Visibility.API_VISIBLE.value)
            for algo in extract_algorithms(config)]

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            asset_id=raw.get("asset_id") or "entrust-pki",
            asset_type=AssetType.CA.value,
            crypto_type=raw.get("crypto_type", CryptoType.ALGORITHM.value),
            algorithm=raw.get("algorithm"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", 0.8),
            visibility=raw.get("visibility", Visibility.API_VISIBLE.value),
            vendor_specific=scrub_secrets(raw),
        )
