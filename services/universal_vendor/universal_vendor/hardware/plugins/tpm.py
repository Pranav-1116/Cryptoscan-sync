"""TPM hardware plugins (§6) — generic TPM 2.0, Intel PTT, AMD fTPM."""

from __future__ import annotations

from typing import Any

from universal_vendor.hardware.models import (
    HardwareConfidence,
    HardwareIdentity,
    HardwareObservation,
    HardwareType,
    TpmInfo,
)
from universal_vendor.hardware.plugin import UniversalHardwarePlugin
from universal_vendor.hardware.tpm import TpmScanner


class _TpmPluginBase(UniversalHardwarePlugin):
    category = HardwareType.TPM
    discovery_methods = ["agent", "api"]
    _patterns: list[tuple[str, str, str]] = []

    def detect(self, context: dict[str, Any]) -> dict[str, Any]:
        if context.get("tpm") or context.get("tpm_present"):
            return {"detected": True, "manufacturer": self.manufacturer,
                    "model": self.product,
                    "confidence": HardwareConfidence.HIGH.value}
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
            model=self.product, device_type=HardwareType.TPM.value,
            firmware=(context.get("tpm") or {}).get("firmware"),
            source=self.plugin_id)

    def inventory(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        tpm = context.get("tpm") or {}
        return [self._raw(
            asset_id=context.get("asset_id", "tpm"),
            tpm=TpmScanner().parse(tpm).to_dict(),
            vendor_specific={"note": "public TPM metadata only"})]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        tpm = context.get("tpm") or {}
        return [self._raw(
            asset_id=context.get("asset_id", "tpm"),
            algorithm="TPM", tpm=TpmScanner().parse(tpm).to_dict())]

    def discover_capabilities(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        tpm = context.get("tpm") or {}
        return [self._raw(
            asset_id=context.get("asset_id", "tpm"),
            algorithm="capability",
            capabilities={"supported_algorithms": tpm.get("supported_algorithms") or []})]

    def discover_firmware(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        tpm = context.get("tpm") or {}
        if not tpm.get("firmware"):
            return []
        return [self._raw(asset_id=context.get("asset_id", "tpm"),
                          firmware_component="TPM", version=tpm["firmware"])]

    def normalize(self, raw: dict[str, Any]) -> HardwareObservation:
        return HardwareObservation(
            asset_id=str(raw.get("asset_id") or "tpm"),
            manufacturer=self.manufacturer,
            model=self.product,
            device_type=HardwareType.TPM.value,
            firmware=(raw.get("tpm") or {}).get("firmware"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", HardwareConfidence.HIGH.value),
            tpm=raw.get("tpm"),
            firmware_components=dict(raw.get("firmware_components") or {}),
            vendor_specific=self._canonical_vendor_specific(raw),
        )


class TpmGenericPlugin(_TpmPluginBase):
    plugin_id = "hw_tpm_generic"
    manufacturer = "TPM"
    product = "TPM 2.0"
    _patterns = [
        (r"tpm.?2\.0", "TPM", "TPM 2.0"),
    ]


class IntelPlatformTpmPlugin(_TpmPluginBase):
    plugin_id = "hw_tpm_intel_ptt"
    manufacturer = "Intel"
    product = "Platform Trust Technology"
    _patterns = [
        (r"intel.*ptt|platform trust technology", "Intel", "Platform Trust Technology"),
    ]


class AmdFirmwareTpmPlugin(_TpmPluginBase):
    plugin_id = "hw_tpm_amd_ftpm"
    manufacturer = "AMD"
    product = "fTPM"
    _patterns = [
        (r"amd.*ftpm|firmware tpm", "AMD", "fTPM"),
    ]
