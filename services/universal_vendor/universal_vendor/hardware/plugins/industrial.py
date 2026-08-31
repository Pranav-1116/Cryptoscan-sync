"""Industrial/PLC hardware plugins — passive-first by contract (§22)"""

from __future__ import annotations

from typing import Any

from universal_vendor.hardware.models import (
    HardwareConfidence,
    HardwareIdentity,
    HardwareObservation,
    HardwareType,
)
from universal_vendor.hardware.plugin import UniversalHardwarePlugin


class _PlcPluginBase(UniversalHardwarePlugin):
    """Industrial/PLC plugins — passive-first by contract (§22)."""

    category = HardwareType.PLC
    discovery_methods = ["network"]
    passive_first = True
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
            signals.append(IdentitySignal("hostname", str(context["asset_id"]), "passive"))
        return resolver.build_identity(
            signals=signals, manufacturer=self.manufacturer,
            model=str(context.get("model") or self.product),
            device_type=HardwareType.PLC.value,
            firmware=context.get("firmware"), source=self.plugin_id)

    def inventory(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        return [self._raw(
            asset_id=context.get("asset_id", "plc"),
            model=context.get("model") or self.product,
            firmware=context.get("firmware"),
            vendor_specific={"passive_protocol_metadata": context.get("protocol_metadata")})]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        crypto = context.get("crypto")
        if not crypto:
            return []
        return [self._raw(asset_id=context.get("asset_id", "plc"),
                          algorithm="ot-crypto", crypto=crypto,
                          passive_only=True)]

    def discover_firmware(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        if not context.get("firmware"):
            return []
        return [self._raw(asset_id=context.get("asset_id", "plc"),
                          firmware_component="NETWORK_APPLIANCE",
                          version=context["firmware"])]

    def discover_capabilities(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        capabilities = context.get("capabilities")
        if not capabilities:
            return []
        return [self._raw(asset_id=context.get("asset_id", "plc"),
                          algorithm="capability", capabilities=capabilities)]

    def normalize(self, raw: dict[str, Any]) -> HardwareObservation:
        return HardwareObservation(
            asset_id=str(raw.get("asset_id") or "plc"),
            manufacturer=self.manufacturer,
            model=str(raw.get("model") or self.product),
            device_type=HardwareType.PLC.value,
            firmware=raw.get("firmware"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", HardwareConfidence.MEDIUM.value),
            firmware_components=dict(raw.get("firmware_components") or {}),
            vendor_specific=self._canonical_vendor_specific(raw),
        )


class SiemensPlcPlugin(_PlcPluginBase):
    plugin_id = "hw_siemens_plc"
    manufacturer = "Siemens"
    product = "SIMATIC S7"
    _patterns = [
        (r"siemens.*(simatic|s7)|simatic|s7-1[25]\d\d", "Siemens", "SIMATIC S7"),
    ]


class RockwellPlcPlugin(_PlcPluginBase):
    plugin_id = "hw_rockwell_plc"
    manufacturer = "Rockwell"
    product = "ControlLogix"
    _patterns = [
        (r"rockwell.*(controllogix|compactlogix)|controllogix|compactlogix",
         "Rockwell", "ControlLogix"),
    ]


class SchneiderPlcPlugin(_PlcPluginBase):
    plugin_id = "hw_schneider_plc"
    manufacturer = "Schneider"
    product = "Modicon"
    _patterns = [
        (r"schneider.*(modicon|m340|m580)|modicon|m340|m580", "Schneider", "Modicon"),
    ]


class AbbPlcPlugin(_PlcPluginBase):
    plugin_id = "hw_abb_plc"
    manufacturer = "ABB"
    product = "AC500"
    _patterns = [
        (r"abb.*(ac500|800xa)|ac500|800xa", "ABB", "AC500"),
    ]
