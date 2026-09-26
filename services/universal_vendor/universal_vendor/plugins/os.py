"""Operating-system vendor plugins (spec §9): Red Hat, Ubuntu, Debian, SUSE,
Windows, VMware ESXi.

Discover (can reuse the existing host/agent scanner architecture): OpenSSL
versions, crypto libraries, system TLS configuration, SSH configuration,
certificates, trusted CA stores, deprecated cryptography.
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
from universal_vendor.plugins._helpers import BannerPluginBase, extract_algorithms


class _OsPluginBase(BannerPluginBase):
    _config_keys = ("banner",)

    def discover_configuration(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Record the OS crypto surface identity — versioned libraries and
        banner — so every OS scan yields an honest baseline observation."""
        observations = []
        banner = context.get("banner")
        version = context.get("version")
        openssl = context.get("openssl_version")
        identity = {
            "banner": banner,
            "version": version,
            "openssl_version": openssl,
            "ssh_enabled": bool(context.get("ssh_config")),
            "ca_stores": context.get("ca_stores") or [],
        }
        observations.append(self._raw_observation(
            crypto_type=CryptoType.CONFIGURATION.value, algorithm="os-identity",
            asset_id="os", configuration=scrub_secrets(identity),
            product_version=version))
        return observations

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        openssl = context.get("openssl_version", "")
        config = context.get("config", "") or ""
        observations = []
        if openssl:
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="OpenSSL",
                asset_id="os", configuration={"version": openssl},
                protocol="library", product_version=openssl))
        if context.get("ssh_config"):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="SSH",
                asset_id="os",
                configuration=scrub_secrets(context.get("ssh_config")),
                protocol="SSH"))
        for algo in extract_algorithms(config):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.ALGORITHM.value, algorithm=algo,
                asset_id="os"))
        return observations

    def discover_certificates(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        certs = []
        for path in context.get("ca_stores") or []:
            certs.append({"path": path, "type": "trust-store"})
        return [self._raw_observation(
            crypto_type=CryptoType.CERTIFICATE.value, asset_id="os",
            certificate=cert) for cert in certs]

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            product_version=raw.get("product_version"),
            asset_id=raw.get("asset_id") or "os",
            asset_type=AssetType.OS.value,
            crypto_type=raw.get("crypto_type", CryptoType.ALGORITHM.value),
            algorithm=raw.get("algorithm"),
            protocol=raw.get("protocol"),
            certificate=raw.get("certificate"),
            configuration=raw.get("configuration"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", 0.88),
            visibility=raw.get("visibility", Visibility.OBSERVED.value),
            vendor_specific=scrub_secrets(raw),
        )


class RedHatPlugin(_OsPluginBase):
    plugin_id = "redhat_rhel"
    vendor = "Red Hat"
    product = "RHEL"
    category = VendorCategory.OS
    supported_features = ["openssl", "ssh", "tls", "certificates", "ca_stores"]
    trusted = True

    _patterns = [
        (r"red hat enterprise linux|rhel", "Red Hat", "RHEL", 0.9),
    ]


class UbuntuPlugin(_OsPluginBase):
    plugin_id = "ubuntu"
    vendor = "Ubuntu"
    product = "Ubuntu"
    category = VendorCategory.OS
    supported_features = ["openssl", "ssh", "tls", "certificates", "ca_stores"]
    trusted = True

    _patterns = [
        (r"ubuntu", "Ubuntu", "Ubuntu", 0.88),
    ]


class DebianPlugin(_OsPluginBase):
    plugin_id = "debian"
    vendor = "Debian"
    product = "Debian"
    category = VendorCategory.OS
    supported_features = ["openssl", "ssh", "tls", "certificates", "ca_stores"]
    trusted = True

    _patterns = [
        (r"debian", "Debian", "Debian", 0.88),
    ]


class SusePlugin(_OsPluginBase):
    plugin_id = "suse_sles"
    vendor = "SUSE"
    product = "SLES"
    category = VendorCategory.OS
    supported_features = ["openssl", "ssh", "tls", "certificates"]
    trusted = True

    _patterns = [
        (r"suse|sles", "SUSE", "SLES", 0.9),
    ]


class WindowsPlugin(_OsPluginBase):
    plugin_id = "microsoft_windows"
    vendor = "Microsoft"
    product = "Windows"
    category = VendorCategory.OS
    supported_features = ["tls", "schannel", "certificates", "ca_stores"]
    trusted = True

    _patterns = [
        (r"microsoft windows", "Microsoft", "Windows", 0.9),
    ]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        observations = super().discover_crypto(context)
        for algo in context.get("schannel_ciphers") or []:
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm=str(algo),
                asset_id="os", configuration={"provider": "schannel"},
                protocol="TLS"))
        return observations


class VmwareEsxiPlugin(_OsPluginBase):
    plugin_id = "vmware_esxi"
    vendor = "VMware"
    product = "ESXi"
    category = VendorCategory.OS
    supported_features = ["tls", "ssh", "certificates"]
    trusted = True

    _patterns = [
        (r"vmware esxi|esxi", "VMware", "ESXi", 0.92),
    ]
