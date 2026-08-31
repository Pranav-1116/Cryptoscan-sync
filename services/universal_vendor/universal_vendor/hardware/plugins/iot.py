"""IoT gateway hardware plugins — Cisco IR, Dell Edge Gateway"""

from __future__ import annotations

from typing import Any

from universal_vendor.hardware.models import (
    HardwareConfidence,
    HardwareIdentity,
    HardwareObservation,
    HardwareType,
)
from universal_vendor.hardware.plugin import UniversalHardwarePlugin


class _IotGatewayPluginBase(UniversalHardwarePlugin):
    category = HardwareType.IOT_GATEWAY
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
        if context.get("asset_id"):
            signals.append(IdentitySignal("hostname", str(context["asset_id"]), "network"))
        return resolver.build_identity(
            signals=signals, manufacturer=self.manufacturer,
            model=str(context.get("model") or self.product),
            device_type=HardwareType.IOT_GATEWAY.value,
            firmware=context.get("firmware"), source=self.plugin_id)

    def inventory(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        return [self._raw(
            asset_id=context.get("asset_id", "iot-gateway"),
            model=context.get("model") or self.product,
            firmware=context.get("firmware"),
            vendor_specific={"connected_devices": context.get("connected_devices")})]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        crypto = context.get("crypto")
        if not crypto:
            return []
        return [self._raw(asset_id=context.get("asset_id", "iot-gateway"),
                          algorithm="iot-crypto", crypto=crypto)]

    def discover_firmware(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        if not context.get("firmware"):
            return []
        return [self._raw(asset_id=context.get("asset_id", "iot-gateway"),
                          firmware_component="NETWORK_APPLIANCE",
                          version=context["firmware"])]

    def discover_capabilities(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        capabilities = context.get("capabilities")
        if not capabilities:
            return []
        return [self._raw(asset_id=context.get("asset_id", "iot-gateway"),
                          algorithm="capability", capabilities=capabilities)]

    def normalize(self, raw: dict[str, Any]) -> HardwareObservation:
        return HardwareObservation(
            asset_id=str(raw.get("asset_id") or "iot-gateway"),
            manufacturer=self.manufacturer,
            model=str(raw.get("model") or self.product),
            device_type=HardwareType.IOT_GATEWAY.value,
            firmware=raw.get("firmware"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", HardwareConfidence.MEDIUM.value),
            firmware_components=dict(raw.get("firmware_components") or {}),
            vendor_specific=self._canonical_vendor_specific(raw),
        )


class CiscoIotGatewayPlugin(_IotGatewayPluginBase):
    plugin_id = "hw_cisco_iot"
    manufacturer = "Cisco"
    product = "IR"
    _patterns = [
        (r"cisco.*(ir[0-9]+|iot)", "Cisco", "IR"),
    ]


class DellIotGatewayPlugin(_IotGatewayPluginBase):
    plugin_id = "hw_dell_iot"
    manufacturer = "Dell"
    product = "Edge Gateway"
    _patterns = [
        (r"dell.*edge gateway", "Dell", "Edge Gateway"),
    ]


