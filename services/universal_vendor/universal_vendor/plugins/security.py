"""EDR, SIEM, and SaaS vendor plugins (spec §10, §11, §15)."""

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


class _SecurityPluginBase(BannerPluginBase):
    """EDR / SIEM / SaaS plugins gate on detection only (intelligence
    sources and API-visible SaaS surfaces)."""

    _config_keys = ()


class CrowdStrikePlugin(_SecurityPluginBase):
    plugin_id = "crowdstrike_falcon"
    vendor = "CrowdStrike"
    product = "Falcon"
    category = VendorCategory.EDR
    supported_features = ["endpoint_observations"]
    trusted = True

    _patterns = [
        (r"crowdstrike|falcon", "CrowdStrike", "Falcon", 0.9),
    ]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        observations = []
        for endpoint in context.get("endpoints") or []:
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="endpoint",
                asset_id=str(endpoint.get("hostname", "endpoint")),
                configuration={"tls": endpoint.get("tls"),
                               "certs": endpoint.get("certs")},
                visibility=Visibility.OBSERVED.value))
        return observations

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            asset_id=raw.get("asset_id") or "edr",
            asset_type=AssetType.EDR.value,
            crypto_type=raw.get("crypto_type", CryptoType.ALGORITHM.value),
            algorithm=raw.get("algorithm"),
            configuration=raw.get("configuration"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", 0.8),
            visibility=raw.get("visibility", Visibility.OBSERVED.value),
            vendor_specific=scrub_secrets(raw),
        )


class SentinelOnePlugin(_SecurityPluginBase):
    plugin_id = "sentinelone"
    vendor = "SentinelOne"
    product = "SentinelOne"
    category = VendorCategory.EDR
    supported_features = ["endpoint_observations"]
    trusted = True

    _patterns = [
        (r"sentinelone", "SentinelOne", "SentinelOne", 0.9),
    ]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        observations = []
        for endpoint in context.get("endpoints") or []:
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="endpoint",
                asset_id=str(endpoint.get("hostname", "endpoint")),
                configuration={"tls": endpoint.get("tls"),
                               "certs": endpoint.get("certs")},
                visibility=Visibility.OBSERVED.value))
        return observations

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            asset_id=raw.get("asset_id") or "edr",
            asset_type=AssetType.EDR.value,
            crypto_type=raw.get("crypto_type", CryptoType.ALGORITHM.value),
            algorithm=raw.get("algorithm"),
            configuration=raw.get("configuration"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", 0.8),
            visibility=raw.get("visibility", Visibility.OBSERVED.value),
            vendor_specific=scrub_secrets(raw),
        )


class SplunkPlugin(_SecurityPluginBase):
    plugin_id = "splunk_esi"
    vendor = "Splunk"
    product = "Splunk ES"
    category = VendorCategory.SIEM
    supported_features = ["tls_events", "cert_events", "vpn_events",
                          "policy_change_events", "anomaly_events"]
    trusted = True

    _patterns = [
        (r"splunk", "Splunk", "Splunk ES", 0.9),
    ]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        observations = []
        for event in context.get("events") or []:
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="siem-event",
                asset_id=str(event.get("asset_id", "siem")),
                configuration=scrub_secrets(event),
                visibility=Visibility.OBSERVED.value))
        return observations

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            asset_id=raw.get("asset_id") or "siem",
            asset_type=AssetType.SIEM.value,
            crypto_type=raw.get("crypto_type", CryptoType.ALGORITHM.value),
            algorithm=raw.get("algorithm"),
            configuration=raw.get("configuration"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", 0.7),
            visibility=raw.get("visibility", Visibility.OBSERVED.value),
            vendor_specific=scrub_secrets(raw),
        )


class QradarPlugin(_SecurityPluginBase):
    plugin_id = "ibm_qradar"
    vendor = "IBM"
    product = "QRadar"
    category = VendorCategory.SIEM
    supported_features = ["tls_events", "cert_events", "vpn_events"]
    trusted = True

    _patterns = [
        (r"qradar", "IBM", "QRadar", 0.9),
    ]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        observations = []
        for event in context.get("events") or []:
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="siem-event",
                asset_id=str(event.get("asset_id", "siem")),
                configuration=scrub_secrets(event),
                visibility=Visibility.OBSERVED.value))
        return observations

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            asset_id=raw.get("asset_id") or "siem",
            asset_type=AssetType.SIEM.value,
            crypto_type=raw.get("crypto_type", CryptoType.ALGORITHM.value),
            algorithm=raw.get("algorithm"),
            configuration=raw.get("configuration"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", 0.7),
            visibility=raw.get("visibility", Visibility.OBSERVED.value),
            vendor_specific=scrub_secrets(raw),
        )


class SalesforcePlugin(_SecurityPluginBase):
    plugin_id = "salesforce"
    vendor = "Salesforce"
    product = "Salesforce"
    category = VendorCategory.SAAS
    supported_features = ["certificate_config", "tls_config"]
    api_requirements = ["Salesforce Metadata API"]
    trusted = True

    _patterns = [
        (r"salesforce", "Salesforce", "Salesforce", 0.88),
    ]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        observations = []
        cert = context.get("certificate")
        if cert:
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CERTIFICATE.value, algorithm="TLS",
                asset_id="salesforce",
                certificate={"type": "configured", **scrub_secrets(cert)},
                visibility=Visibility.API_VISIBLE.value))
        for algo in context.get("tls_ciphers") or []:
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm=str(algo),
                asset_id="salesforce",
                configuration={"tls_cipher": algo},
                visibility=Visibility.API_VISIBLE.value))
        return observations

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            asset_id=raw.get("asset_id") or "saas",
            asset_type=AssetType.SAAS.value,
            crypto_type=raw.get("crypto_type", CryptoType.ALGORITHM.value),
            algorithm=raw.get("algorithm"),
            certificate=raw.get("certificate"),
            configuration=raw.get("configuration"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", 0.75),
            visibility=raw.get("visibility", Visibility.API_VISIBLE.value),
            vendor_specific=scrub_secrets(raw),
        )


class Microsoft365Plugin(_SecurityPluginBase):
    plugin_id = "microsoft_365"
    vendor = "Microsoft"
    product = "Microsoft 365"
    category = VendorCategory.SAAS
    supported_features = ["certificate_config", "key_config"]
    trusted = True

    _patterns = [
        (r"microsoft 365|office 365", "Microsoft", "Microsoft 365", 0.88),
    ]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        observations = []
        for algo in context.get("signing_algorithms") or []:
            observations.append(self._raw_observation(
                crypto_type=CryptoType.ALGORITHM.value, algorithm=str(algo),
                asset_id="m365",
                configuration={"use": "token-signing"},
                visibility=Visibility.API_VISIBLE.value))
        for key in context.get("customer_keys") or []:
            observations.append(self._raw_observation(
                crypto_type=CryptoType.KEY.value, algorithm="customer-key",
                asset_id=str(key.get("name", "m365-key")),
                configuration=scrub_secrets(key),
                visibility=Visibility.API_VISIBLE.value))
        return observations

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            asset_id=raw.get("asset_id") or "m365",
            asset_type=AssetType.SAAS.value,
            crypto_type=raw.get("crypto_type", CryptoType.ALGORITHM.value),
            algorithm=raw.get("algorithm"),
            configuration=raw.get("configuration"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", 0.75),
            visibility=raw.get("visibility", Visibility.API_VISIBLE.value),
            vendor_specific=scrub_secrets(raw),
        )


class NotSupportedSaaSPlugin(_SecurityPluginBase):
    """SaaS with no exposed crypto configuration (e.g. pure consumer SaaS).

    Honest UNKNOWN / NOT_SUPPORTED — never over-claim.
    """

    plugin_id = "saas_not_supported"
    vendor = "SaaS"
    product = "Unspecified SaaS"
    category = VendorCategory.SAAS
    supported_features = []
    trusted = True

    _patterns = [
        (r"saas", "SaaS", "Unspecified SaaS", 0.5),
    ]

    def detect(self, context: dict[str, Any]):
        """Never auto-detects — an operator selects it explicitly for SaaS
        surfaces with no exposed crypto configuration."""
        from universal_vendor.models import DetectionResult

        return DetectionResult(confidence=0.0)

    def validate_connection(self, context: dict[str, Any]):
        from universal_vendor.models import ConnectionResult

        return ConnectionResult(connected=True,
                                message="operator-selected honest-SaaS scan")

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        return [self._raw_observation(
            crypto_type=CryptoType.CONFIGURATION.value, algorithm="unknown",
            asset_id="saas",
            configuration={"note": "crypto configuration not exposed by vendor API"},
            visibility=Visibility.NOT_SUPPORTED.value)]

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            asset_id=raw.get("asset_id") or "saas",
            asset_type=AssetType.SAAS.value,
            crypto_type=raw.get("crypto_type", CryptoType.CONFIGURATION.value),
            algorithm=raw.get("algorithm"),
            configuration=raw.get("configuration"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", 0.5),
            visibility=raw.get("visibility", Visibility.NOT_SUPPORTED.value),
            vendor_specific=scrub_secrets(raw),
        )
