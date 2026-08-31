"""HSM vendor plugins (spec §5): Thales Luna, Entrust nShield, Utimaco,
AWS CloudHSM.

Discover **metadata only**:
    HSM → Vendor / Model / Firmware / Crypto Capabilities /
           Supported Algorithms / Key Types / Certificate Dependencies /
           PQC Capability
Never extract: private keys, master keys, PINs, credentials, secret
material. A hard guard rejects any record carrying key-material fields.
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

_FORBIDDEN_KEY_MATERIAL = (
    "private_key", "privatekey", "master_key", "masterkey", "key_material",
    "key_value", "pin", "secret", "password", "token",
)


def _contains_key_material(data: dict[str, Any]) -> bool:
    dump = str(data).lower()
    return any(token in dump for token in _FORBIDDEN_KEY_MATERIAL)


class HsmPluginBase(BannerPluginBase):
    """HSM plugins share the metadata-only contract."""

    _config_keys = ("banner",)

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        text = (context.get("config", "") or context.get("api_metadata", "")) or ""
        observations = []
        for algo in extract_algorithms(text):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.ALGORITHM.value, algorithm=algo,
                asset_id="hsm"))
        for match in re.finditer(r"(?:supported_|algorithms?|capabilit\w*)[:=]\s*([^\n,]+)", text, re.IGNORECASE):
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="capability",
                asset_id="hsm",
                configuration={"capabilities": match.group(1).strip()[:120]}))
        model = context.get("model") or context.get("firmware")
        if model:
            observations.append(self._raw_observation(
                crypto_type=CryptoType.CONFIGURATION.value, algorithm="hsm-model",
                asset_id="hsm",
                configuration={"model": model, "firmware": context.get("firmware")}))
        return observations

    def discover_inventory(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        slot_count = context.get("slots")
        return [self._raw_observation(
            crypto_type=CryptoType.CONFIGURATION.value, algorithm="inventory",
            asset_id="hsm", configuration={"slots": slot_count,
                                           "model": context.get("model"),
                                           "firmware": context.get("firmware")})]

    def normalize(self, raw: dict[str, Any]) -> UniversalObservation:
        assert not _contains_key_material(raw), "HSM plugin refused key material"
        return UniversalObservation(
            vendor=self.vendor, product=self.product,
            asset_id=raw.get("asset_id") or "hsm",
            asset_type=AssetType.HSM.value,
            crypto_type=raw.get("crypto_type", CryptoType.ALGORITHM.value),
            algorithm=raw.get("algorithm"),
            configuration=raw.get("configuration"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", 0.9),
            visibility=raw.get("visibility", Visibility.API_VISIBLE.value),
            vendor_specific=scrub_secrets(raw),
        )


class ThalesLunaPlugin(HsmPluginBase):
    plugin_id = "thales_luna"
    vendor = "Thales"
    product = "Luna HSM"
    category = VendorCategory.HSM
    supported_features = ["model", "firmware", "crypto_capabilities",
                          "supported_algorithms", "key_types", "pqc_metadata"]
    api_requirements = ["HSM admin API or config"]
    trusted = True

    _patterns = [
        (r"thales (?:luna|pay|dsm)", "Thales", "Luna HSM", 0.95),
        (r"luna k[567]|luna sa", "Thales", "Luna HSM", 0.9),
    ]


class EntrustNshieldPlugin(HsmPluginBase):
    plugin_id = "entrust_nshield"
    vendor = "Entrust"
    product = "nShield HSM"
    category = VendorCategory.HSM
    supported_features = ["model", "firmware", "crypto_capabilities",
                          "supported_algorithms", "pqc_metadata"]
    trusted = True

    _patterns = [
        (r"entrust nshield", "Entrust", "nShield HSM", 0.95),
        (r"nshield", "Entrust", "nShield HSM", 0.85),
    ]


class UtimacoPlugin(HsmPluginBase):
    plugin_id = "utimaco_securityserver"
    vendor = "Utimaco"
    product = "SecurityServer"
    category = VendorCategory.HSM
    supported_features = ["model", "firmware", "crypto_capabilities",
                          "supported_algorithms", "pqc_metadata"]
    trusted = True

    _patterns = [
        (r"utimaco (?:securityserver|q-safe)", "Utimaco", "SecurityServer", 0.95),
        (r"utimaco", "Utimaco", "SecurityServer", 0.85),
    ]


class AwsCloudHsmPlugin(HsmPluginBase):
    plugin_id = "aws_cloudhsm"
    vendor = "AWS"
    product = "CloudHSM"
    category = VendorCategory.HSM
    supported_features = ["model", "firmware", "crypto_capabilities",
                          "supported_algorithms", "key_types"]
    trusted = True

    _patterns = [
        (r"cloudhsm", "AWS", "CloudHSM", 0.9),
    ]
