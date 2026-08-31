"""Virtualization, IoT and industrial (PLC/OT) hardware plugins."""

from __future__ import annotations

from typing import Any

from universal_vendor.hardware.models import (
    HardwareConfidence,
    HardwareIdentity,
    HardwareObservation,
    HardwareType,
)
from universal_vendor.hardware.plugin import UniversalHardwarePlugin


class _VirtHostPluginBase(UniversalHardwarePlugin):
    category = HardwareType.HYPERVISOR_HOST
    discovery_methods = ["api", "agent"]
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
            signals.append(IdentitySignal("hostname", str(context["asset_id"]), "api"))
        return resolver.build_identity(
            signals=signals, manufacturer=self.manufacturer,
            model=str(context.get("model") or self.product),
            device_type=HardwareType.HYPERVISOR_HOST.value,
            firmware=context.get("firmware"), source=self.plugin_id)

    def inventory(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        return [self._raw(
            asset_id=context.get("asset_id", "hypervisor"),
            model=context.get("model") or self.product,
            vendor_specific={"guests": context.get("guests"),
                             "cpu": context.get("cpu")})]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        tpm = context.get("tpm")
        records = []
        if tpm:
            from universal_vendor.hardware.tpm import TpmScanner

            records.append(self._raw(asset_id=context.get("asset_id", "hypervisor"),
                                     algorithm="TPM",
                                     tpm=TpmScanner().parse(tpm).to_dict()))
        return records

    def discover_firmware(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        if not context.get("firmware"):
            return []
        return [self._raw(asset_id=context.get("asset_id", "hypervisor"),
                          firmware_component="UEFI", version=context["firmware"])]

    def discover_capabilities(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        capabilities = context.get("capabilities")
        if not capabilities:
            return []
        return [self._raw(asset_id=context.get("asset_id", "hypervisor"),
                          algorithm="capability", capabilities=capabilities)]

    def normalize(self, raw: dict[str, Any]) -> HardwareObservation:
        return HardwareObservation(
            asset_id=str(raw.get("asset_id") or "hypervisor"),
            manufacturer=self.manufacturer,
            model=str(raw.get("model") or self.product),
            device_type=HardwareType.HYPERVISOR_HOST.value,
            firmware=raw.get("firmware"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", HardwareConfidence.MEDIUM.value),
            tpm=raw.get("tpm"),
            firmware_components=dict(raw.get("firmware_components") or {}),
            vendor_specific=self._canonical_vendor_specific(raw),
        )


class VmwareEsxiHwPlugin(_VirtHostPluginBase):
    plugin_id = "hw_vmware_esxi"
    manufacturer = "VMware"
    product = "ESXi"
    _patterns = [
        (r"vmware esxi|esxi", "VMware", "ESXi"),
    ]


class HyperVHostPlugin(_VirtHostPluginBase):
    plugin_id = "hw_hyperv"
    manufacturer = "Microsoft"
    product = "Hyper-V"
    _patterns = [
        (r"hyper-v|hyperv", "Microsoft", "Hyper-V"),
    ]


class KvmHostPlugin(_VirtHostPluginBase):
    plugin_id = "hw_kvm"
    manufacturer = "Linux"
    product = "KVM"
    _patterns = [
        (r"kvm|qemu", "Linux", "KVM"),
    ]
