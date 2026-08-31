"""Compute hardware plugins — servers (Dell, HPE, IBM, Lenovo, Supermicro)."""

from __future__ import annotations

from typing import Any

from universal_vendor.hardware.models import (
    HardwareConfidence,
    HardwareIdentity,
    HardwareObservation,
    HardwareType,
)
from universal_vendor.hardware.plugin import UniversalHardwarePlugin


class _ServerPluginBase(UniversalHardwarePlugin):
    category = HardwareType.SERVER
    discovery_methods = ["agent", "api", "network"]

    _patterns: list[tuple[str, str, str]] = []

    def detect(self, context: dict[str, Any]) -> dict[str, Any]:
        return self._detect_banner(context, self._patterns)

    def identify(self, context: dict[str, Any]) -> HardwareIdentity:
        from universal_vendor.hardware.identity import HardwareIdentityResolver

        resolver = HardwareIdentityResolver()
        dmi = context.get("dmi") or {}
        signals = []
        if dmi.get("serial"):
            signals.append(__import__(
                "universal_vendor.hardware.identity",
                fromlist=["IdentitySignal"]).IdentitySignal(
                "serial", str(dmi["serial"]), "dmi"))
        if context.get("asset_id"):
            signals.append(__import__(
                "universal_vendor.hardware.identity",
                fromlist=["IdentitySignal"]).IdentitySignal(
                "hostname", str(context["asset_id"]), "agent"))
        return resolver.build_identity(
            signals=signals,
            manufacturer=self.manufacturer,
            model=str(dmi.get("product") or self.product),
            device_type=HardwareType.SERVER.value,
            firmware=dmi.get("bios_version"),
            environment=context.get("environment"),
            source=self.plugin_id,
        )

    def inventory(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        dmi = context.get("dmi") or {}
        if not dmi:
            return []
        return [self._raw(
            asset_id=context.get("asset_id") or dmi.get("serial") or "server",
            serial_reference=dmi.get("serial"),
            firmware=dmi.get("bios_version"),
            hardware_revision=dmi.get("hardware_revision"),
            vendor_specific={"dmi": dmi, "bmc": context.get("bmc")},
        )]

    def discover_firmware(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        dmi = context.get("dmi") or {}
        records = []
        if dmi.get("bios_version"):
            records.append(self._raw(
                asset_id=context.get("asset_id", "server"),
                firmware_component="BIOS", version=dmi["bios_version"]))
        bmc = context.get("bmc") or {}
        if isinstance(bmc, dict) and bmc.get("firmware"):
            records.append(self._raw(
                asset_id=context.get("asset_id", "server"),
                firmware_component="BMC", version=bmc["firmware"]))
        return records

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        cpu = context.get("cpu")
        tpm = context.get("tpm")
        records = []
        if cpu:
            from universal_vendor.hardware.cpu import CpuDiscovery

            parsed = CpuDiscovery().parse(cpu)
            records.append(self._raw(
                asset_id=context.get("asset_id", "server"),
                algorithm="CPU", cpu=parsed.to_dict(),
                capability_only=True))
        if tpm:
            from universal_vendor.hardware.tpm import TpmScanner

            records.append(self._raw(
                asset_id=context.get("asset_id", "server"),
                algorithm="TPM", tpm=TpmScanner().parse(tpm).to_dict()))
        return records

    def discover_capabilities(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        capabilities = context.get("capabilities")
        if not capabilities:
            return []
        return [self._raw(
            asset_id=context.get("asset_id", "server"),
            algorithm="capability", capabilities=capabilities)]

    def normalize(self, raw: dict[str, Any]) -> HardwareObservation:
        return HardwareObservation(
            asset_id=str(raw.get("asset_id") or "server"),
            manufacturer=self.manufacturer,
            model=str(raw.get("model") or self.product),
            serial_reference=raw.get("serial_reference"),
            device_type=HardwareType.SERVER.value,
            firmware=raw.get("firmware"),
            hardware_revision=raw.get("hardware_revision"),
            environment=raw.get("environment"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", HardwareConfidence.HIGH.value),
            cpu=raw.get("cpu"),
            tpm=raw.get("tpm"),
            capabilities=raw.get("capabilities"),
            firmware_components=dict(raw.get("firmware_components") or {}),
            vendor_specific=self._canonical_vendor_specific(raw),
        )


class DellServerPlugin(_ServerPluginBase):
    plugin_id = "hw_dell_poweredge"
    manufacturer = "Dell"
    product = "PowerEdge"
    _patterns = [
        (r"dell.*poweredge", "Dell", "PowerEdge"),
        (r"poweredge", "Dell", "PowerEdge"),
    ]


class HpeServerPlugin(_ServerPluginBase):
    plugin_id = "hw_hpe_proliant"
    manufacturer = "HPE"
    product = "ProLiant"
    _patterns = [
        (r"hpe.*proliant|hewlett.?packard.*proliant", "HPE", "ProLiant"),
        (r"proliant", "HPE", "ProLiant"),
    ]


class IbmServerPlugin(_ServerPluginBase):
    plugin_id = "hw_ibm"
    manufacturer = "IBM"
    product = "Power"
    _patterns = [
        (r"ibm.*(power|system)", "IBM", "Power"),
    ]


class LenovoServerPlugin(_ServerPluginBase):
    plugin_id = "hw_lenovo_thinksystem"
    manufacturer = "Lenovo"
    product = "ThinkSystem"
    _patterns = [
        (r"lenovo.*thinksystem", "Lenovo", "ThinkSystem"),
        (r"thinksystem", "Lenovo", "ThinkSystem"),
    ]


class SupermicroServerPlugin(_ServerPluginBase):
    plugin_id = "hw_supermicro"
    manufacturer = "Supermicro"
    product = "Supermicro"
    _patterns = [
        (r"supermicro", "Supermicro", "Supermicro"),
    ]
