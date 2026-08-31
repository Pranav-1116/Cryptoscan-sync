"""Storage + GPU hardware plugins."""

from __future__ import annotations

from typing import Any

from universal_vendor.hardware.models import (
    HardwareConfidence,
    HardwareIdentity,
    HardwareObservation,
    HardwareType,
)
from universal_vendor.hardware.plugin import UniversalHardwarePlugin


class _StoragePluginBase(UniversalHardwarePlugin):
    category = HardwareType.SAN
    discovery_methods = ["network", "api"]
    _patterns: list[tuple[str, str, str]] = []

    def detect(self, context: dict[str, Any]) -> dict[str, Any]:
        return self._detect_banner(context, self._patterns)

    def identify(self, context: dict[str, Any]) -> HardwareIdentity:
        from universal_vendor.hardware.identity import (
            HardwareIdentityResolver,
            IdentitySignal,
        )

        resolver = HardwareIdentityResolver()
        signals = []
        if context.get("serial"):
            signals.append(IdentitySignal("serial", str(context["serial"]), "storage-api"))
        if context.get("asset_id"):
            signals.append(IdentitySignal("hostname", str(context["asset_id"]), "storage-api"))
        return resolver.build_identity(
            signals=signals, manufacturer=self.manufacturer,
            model=str(context.get("model") or self.product),
            device_type=HardwareType.SAN.value,
            firmware=context.get("firmware"),
            source=self.plugin_id)

    def inventory(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        return [self._raw(
            asset_id=context.get("asset_id") or context.get("serial") or "storage",
            serial_reference=context.get("serial"),
            firmware=context.get("firmware"),
            vendor_specific={"controllers": context.get("controllers"),
                             "disk_encryption": context.get("disk_encryption")})]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        records = []
        if context.get("disk_encryption"):
            records.append(self._raw(
                asset_id=context.get("asset_id", "storage"),
                algorithm="disk-encryption",
                disk_encryption=context["disk_encryption"]))
        return records

    def discover_firmware(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        if not context.get("firmware"):
            return []
        return [self._raw(asset_id=context.get("asset_id", "storage"),
                          firmware_component="STORAGE",
                          version=context["firmware"])]

    def discover_capabilities(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        capabilities = context.get("capabilities")
        if not capabilities:
            return []
        return [self._raw(asset_id=context.get("asset_id", "storage"),
                          algorithm="capability", capabilities=capabilities)]

    def normalize(self, raw: dict[str, Any]) -> HardwareObservation:
        return HardwareObservation(
            asset_id=str(raw.get("asset_id") or "storage"),
            manufacturer=self.manufacturer,
            model=str(raw.get("model") or self.product),
            serial_reference=raw.get("serial_reference"),
            device_type=HardwareType.SAN.value,
            firmware=raw.get("firmware"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", HardwareConfidence.HIGH.value),
            firmware_components=dict(raw.get("firmware_components") or {}),
            vendor_specific=self._canonical_vendor_specific(raw),
        )


class DellEmeStoragePlugin(_StoragePluginBase):
    plugin_id = "hw_dell_eme_storage"
    manufacturer = "Dell EMC"
    product = "PowerMax"
    _patterns = [
        (r"dell.*emc.*(powermax|unity|powerstore)", "Dell EMC", "PowerMax"),
        (r"powermax|powerstore", "Dell EMC", "PowerMax"),
    ]


class NetappStoragePlugin(_StoragePluginBase):
    plugin_id = "hw_netapp"
    manufacturer = "NetApp"
    product = "AFF"
    _patterns = [
        (r"netapp.*(aff|fas|ontap)", "NetApp", "AFF"),
        (r"netapp", "NetApp", "AFF"),
    ]


class HpeStoragePlugin(_StoragePluginBase):
    plugin_id = "hw_hpe_storage"
    manufacturer = "HPE"
    product = "Primera"
    _patterns = [
        (r"hpe.*(primera|3par|nimble)", "HPE", "Primera"),
    ]
