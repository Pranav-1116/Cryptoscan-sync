"""Security hardware plugins — HSMs (Thales Luna, Entrust nShield, Utimaco).

Metadata only, integrated with the vendor HSM plugins (§7).
"""

from __future__ import annotations

from typing import Any

from universal_vendor.hardware.models import (
    HardwareConfidence,
    HardwareIdentity,
    HardwareObservation,
    HardwareType,
)
from universal_vendor.hardware.plugin import UniversalHardwarePlugin


class _HsmHwPluginBase(UniversalHardwarePlugin):
    category = HardwareType.HSM
    discovery_methods = ["api", "network"]
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
            signals.append(IdentitySignal("serial", str(context["serial"]), "hsm-api"))
        if context.get("asset_id"):
            signals.append(IdentitySignal("hostname", str(context["asset_id"]), "hsm-api"))
        return resolver.build_identity(
            signals=signals, manufacturer=self.manufacturer,
            model=str(context.get("model") or self.product),
            device_type=HardwareType.HSM.value,
            firmware=context.get("firmware"),
            environment=context.get("environment"), source=self.plugin_id)

    def inventory(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        return [self._raw(
            asset_id=context.get("asset_id") or context.get("serial") or "hsm",
            serial_reference=context.get("serial"),
            firmware=context.get("firmware"),
            model=context.get("model") or self.product,
            supported_algorithms=list(context.get("supported_algorithms") or []),
            pqc_capability=context.get("pqc_capability", "UNKNOWN"),
            crypto_capabilities=list(context.get("crypto_capabilities") or []),
            partition_metadata=context.get("partition_metadata"),
            vendor_specific={
                "partition_metadata": context.get("partition_metadata"),
                "crypto_capabilities": context.get("crypto_capabilities"),
            })]

    def discover_firmware(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        if not context.get("firmware"):
            return []
        return [self._raw(asset_id=context.get("asset_id", "hsm"),
                          firmware_component="HSM",
                          version=context["firmware"])]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        algorithms = context.get("supported_algorithms") or []
        if not algorithms:
            return []
        return [self._raw(asset_id=context.get("asset_id", "hsm"),
                          algorithm="HSM",
                          supported_algorithms=list(algorithms),
                          pqc_capability=context.get("pqc_capability", "UNKNOWN"))]

    def discover_capabilities(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        capabilities = context.get("crypto_capabilities") or []
        if not capabilities:
            return []
        return [self._raw(asset_id=context.get("asset_id", "hsm"),
                          algorithm="capability", capabilities=list(capabilities))]

    def normalize(self, raw: dict[str, Any]) -> HardwareObservation:
        return HardwareObservation(
            asset_id=str(raw.get("asset_id") or "hsm"),
            manufacturer=self.manufacturer,
            model=str(raw.get("model") or self.product),
            serial_reference=raw.get("serial_reference"),
            device_type=HardwareType.HSM.value,
            firmware=raw.get("firmware"),
            environment=raw.get("environment"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", HardwareConfidence.HIGH.value),
            hsm={k: v for k, v in raw.items()
                 if k in ("supported_algorithms", "pqc_capability",
                          "crypto_capabilities", "partition_metadata")},
            firmware_components=dict(raw.get("firmware_components") or {}),
            vendor_specific=self._canonical_vendor_specific(raw),
        )


class ThalesLunaHwPlugin(_HsmHwPluginBase):
    plugin_id = "hw_thales_luna"
    manufacturer = "Thales"
    product = "Luna HSM"
    _patterns = [
        (r"thales.*luna", "Thales", "Luna HSM"),
        (r"luna (k[567]|sa|network)", "Thales", "Luna HSM"),
    ]


class EntrustNshieldHwPlugin(_HsmHwPluginBase):
    plugin_id = "hw_entrust_nshield"
    manufacturer = "Entrust"
    product = "nShield HSM"
    _patterns = [
        (r"entrust.*nshield", "Entrust", "nShield HSM"),
        (r"nshield", "Entrust", "nShield HSM"),
    ]


class UtimacoHwPlugin(_HsmHwPluginBase):
    plugin_id = "hw_utimaco"
    manufacturer = "Utimaco"
    product = "SecurityServer"
    _patterns = [
        (r"utimaco.*securityserver", "Utimaco", "SecurityServer"),
        (r"utimaco", "Utimaco", "SecurityServer"),
    ]
