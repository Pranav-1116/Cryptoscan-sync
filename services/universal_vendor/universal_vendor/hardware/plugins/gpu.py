"""GPU hardware plugins — NVIDIA, AMD, Intel accelerators."""

from __future__ import annotations

from typing import Any

from universal_vendor.hardware.models import (
    HardwareConfidence,
    HardwareIdentity,
    HardwareObservation,
    HardwareType,
)
from universal_vendor.hardware.plugin import UniversalHardwarePlugin


class _GpuPluginBase(UniversalHardwarePlugin):
    category = HardwareType.GPU
    discovery_methods = ["agent", "api"]
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
            signals.append(IdentitySignal("hostname", str(context["asset_id"]), "agent"))
        return resolver.build_identity(
            signals=signals, manufacturer=self.manufacturer,
            model=str(context.get("model") or self.product),
            device_type=HardwareType.GPU.value,
            firmware=context.get("firmware"), source=self.plugin_id)

    def inventory(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        return [self._raw(
            asset_id=context.get("asset_id", "gpu"),
            model=context.get("model") or self.product,
            vendor_specific={"pci": context.get("pci")})]

    def discover_capabilities(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        capabilities = context.get("capabilities")
        if not capabilities:
            return []
        return [self._raw(asset_id=context.get("asset_id", "gpu"),
                          algorithm="capability", capabilities=capabilities)]

    def discover_firmware(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        if not context.get("firmware"):
            return []
        return [self._raw(asset_id=context.get("asset_id", "gpu"),
                          firmware_component="GPU", version=context["firmware"])]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        crypto = context.get("crypto")
        if not crypto:
            return []
        return [self._raw(asset_id=context.get("asset_id", "gpu"),
                          algorithm="gpu-crypto", crypto=crypto)]

    def normalize(self, raw: dict[str, Any]) -> HardwareObservation:
        return HardwareObservation(
            asset_id=str(raw.get("asset_id") or "gpu"),
            manufacturer=self.manufacturer,
            model=str(raw.get("model") or self.product),
            device_type=HardwareType.GPU.value,
            firmware=raw.get("firmware"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", HardwareConfidence.MEDIUM.value),
            firmware_components=dict(raw.get("firmware_components") or {}),
            vendor_specific=self._canonical_vendor_specific(raw),
        )


class NvidiaGpuPlugin(_GpuPluginBase):
    plugin_id = "hw_nvidia_gpu"
    manufacturer = "NVIDIA"
    product = "Tesla"
    _patterns = [
        (r"nvidia.*(tesla|a100|h100|v100)", "NVIDIA", "Tesla"),
        (r"nvidia", "NVIDIA", "Tesla"),
    ]


class AmdGpuPlugin(_GpuPluginBase):
    plugin_id = "hw_amd_gpu"
    manufacturer = "AMD"
    product = "Instinct"
    _patterns = [
        (r"amd.*instinct|radeon instinct", "AMD", "Instinct"),
    ]


class IntelGpuPlugin(_GpuPluginBase):
    plugin_id = "hw_intel_gpu"
    manufacturer = "Intel"
    product = "Data Center GPU"
    _patterns = [
        (r"intel.*(data center gpu|max series|flex)", "Intel", "Data Center GPU"),
    ]
