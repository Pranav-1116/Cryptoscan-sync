"""Firewall / security vendor plugins (spec §2B): Palo Alto, Fortinet,
Check Point, Sophos, SonicWall.

Discovery: TLS inspection, VPN configuration, IPsec/IKE, certificates,
cryptographic policies, secure tunnels, management interfaces. Config-text
parsing only; secrets scrubbed.
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


class PaloAltoPlugin(BannerPluginBase):
    plugin_id = "paloalto_panos"
    vendor = "Palo Alto"
    product = "PAN-OS"
    category = VendorCategory.FIREWALL
    supported_features = ["tls_inspection", "vpn", "ipsec", "ike",
                          "certificates", "crypto_policies"]
    auth_methods = ["api", "ssh"]
    trusted = True

    _patterns = [
        (r"palo.?alto (?:networks )?pan-os", "Palo Alto", "PAN-OS", 0.95),
        (r"palo.?alto", "Palo Alto", "PAN-OS", 0.85),
    ]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        config = context.get("config", "")
        observations = []
        for algo in extract_algorithms(config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.ALGORITHM.value, algorithm=algo,
                asset_id="firewall"))
        for match in re.finditer(r"set network ike crypto-profiles ike-crypto-profiles (\S+)", config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.PROTOCOL.value, algorithm="IKE",
                asset_id="firewall", configuration={"profile": match.group(1)},
                protocol="IKE"))
        for match in re.finditer(r"set network ipsec crypto-profiles ipsec-crypto-profiles (\S+)", config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.PROTOCOL.value, algorithm="IPsec",
                asset_id="firewall", configuration={"profile": match.group(1)},
                protocol="IPsec"))
        for match in re.finditer(r"set shared ssl-decryption.*?certificate (\S+)", config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="TLS-Inspection",
                asset_id="firewall",
                configuration={"certificate": match.group(1)},
                protocol="TLS"))
        return observations

    def discover_certificates(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        certs = []
        for match in re.finditer(r"set (?:shared )?certificate (\S+)", context.get("config", "")):
            certs.append({"name": match.group(1)})
        return [self._raw_observation(
            crypto_type=CryptoType.CERTIFICATE.value, asset_id="firewall",
            certificate=cert) for cert in certs]

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            asset_id=raw.get("asset_id") or "firewall",
            asset_type=AssetType.FIREWALL.value,
            crypto_type=raw.get("crypto_type", CryptoType.ALGORITHM.value),
            algorithm=raw.get("algorithm"),
            protocol=raw.get("protocol"),
            certificate=raw.get("certificate"),
            configuration=raw.get("configuration"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", 0.9),
            visibility=raw.get("visibility", Visibility.OBSERVED.value),
            vendor_specific=scrub_secrets(raw),
        )


class FortinetPlugin(BannerPluginBase):
    plugin_id = "fortinet_fortios"
    vendor = "Fortinet"
    product = "FortiOS"
    category = VendorCategory.FIREWALL
    supported_features = ["vpn", "ipsec", "ike", "tls_inspection",
                          "certificates", "crypto_policies"]
    auth_methods = ["ssh", "api"]
    trusted = True

    _patterns = [
        (r"fortinet fortios", "Fortinet", "FortiOS", 0.95),
        (r"fortios", "Fortinet", "FortiOS", 0.88),
        (r"fortigate", "Fortinet", "FortiGate", 0.9),
    ]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        config = context.get("config", "")
        observations = []
        for algo in extract_algorithms(config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.ALGORITHM.value, algorithm=algo,
                asset_id="firewall"))
        for match in re.finditer(r"config vpn ipsec phase1-interface.*?edit \"?(\S+?)\"?", config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.PROTOCOL.value, algorithm="IKE",
                asset_id="firewall", configuration={"phase1": match.group(1)},
                protocol="IPsec/IKE"))
        for match in re.finditer(r"config vpn ipsec phase2-interface.*?edit \"?(\S+?)\"?", config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.PROTOCOL.value, algorithm="IPsec",
                asset_id="firewall", configuration={"phase2": match.group(1)},
                protocol="IPsec"))
        return observations

    def discover_certificates(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        certs = []
        for match in re.finditer(r"config vpn certificate local.*?edit \"?(\S+?)\"?", context.get("config", "")):
            certs.append({"name": match.group(1), "type": "local"})
        return [self._raw_observation(
            crypto_type=CryptoType.CERTIFICATE.value, asset_id="firewall",
            certificate=cert) for cert in certs]

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            asset_id=raw.get("asset_id") or "firewall",
            asset_type=AssetType.FIREWALL.value,
            crypto_type=raw.get("crypto_type", CryptoType.ALGORITHM.value),
            algorithm=raw.get("algorithm"),
            protocol=raw.get("protocol"),
            certificate=raw.get("certificate"),
            configuration=raw.get("configuration"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", 0.9),
            visibility=raw.get("visibility", Visibility.OBSERVED.value),
            vendor_specific=scrub_secrets(raw),
        )


class CheckPointPlugin(BannerPluginBase):
    plugin_id = "checkpoint_gaia"
    vendor = "Check Point"
    product = "Gaia"
    category = VendorCategory.FIREWALL
    supported_features = ["vpn", "ipsec", "ike", "certificates"]
    trusted = True

    _patterns = [
        (r"check point (?:gaia|secureplatform)", "Check Point", "Gaia", 0.92),
        (r"checkpoint", "Check Point", "Gaia", 0.8),
    ]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        config = context.get("config", "")
        observations = []
        for algo in extract_algorithms(config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.ALGORITHM.value, algorithm=algo,
                asset_id="firewall"))
        for match in re.finditer(r"ike (?:encryption|hash|diffie-hellman|life)\S*\s+(\S+)", config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.PROTOCOL.value, algorithm="IKE",
                asset_id="firewall",
                configuration={"parameter": match.group(1)},
                protocol="IKE"))
        return observations

    def discover_certificates(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        certs = []
        for match in re.finditer(r"certificate (\S+)", context.get("config", "")):
            certs.append({"name": match.group(1)})
        return [self._raw_observation(
            crypto_type=CryptoType.CERTIFICATE.value, asset_id="firewall",
            certificate=cert) for cert in certs]

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            asset_id=raw.get("asset_id") or "firewall",
            asset_type=AssetType.FIREWALL.value,
            crypto_type=raw.get("crypto_type", CryptoType.ALGORITHM.value),
            algorithm=raw.get("algorithm"),
            protocol=raw.get("protocol"),
            certificate=raw.get("certificate"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", 0.85),
            visibility=raw.get("visibility", Visibility.OBSERVED.value),
            vendor_specific=scrub_secrets(raw),
        )


class SophosPlugin(BannerPluginBase):
    plugin_id = "sophos_xg"
    vendor = "Sophos"
    product = "XG"
    category = VendorCategory.FIREWALL
    supported_features = ["vpn", "ipsec", "tls"]
    trusted = True

    _patterns = [
        (r"sophos (?:xg|xg firewall)", "Sophos", "XG", 0.9),
        (r"sophos", "Sophos", "XG", 0.75),
    ]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        config = context.get("config", "")
        return [self._raw_observation(
            crypto_type=CryptoType.ALGORITHM.value, algorithm=algo,
            asset_id="firewall") for algo in extract_algorithms(config)]

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            asset_id=raw.get("asset_id") or "firewall",
            asset_type=AssetType.FIREWALL.value,
            crypto_type=raw.get("crypto_type", CryptoType.ALGORITHM.value),
            algorithm=raw.get("algorithm"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", 0.8),
            visibility=raw.get("visibility", Visibility.OBSERVED.value),
            vendor_specific=scrub_secrets(raw),
        )
