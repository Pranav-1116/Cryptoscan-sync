"""Network hardware plugins — Cisco, Juniper, Arista, Fortinet chassis."""

from __future__ import annotations

from typing import Any

from universal_vendor.hardware.models import (
    HardwareConfidence,
    HardwareIdentity,
    HardwareObservation,
    HardwareType,
)
from universal_vendor.hardware.plugin import UniversalHardwarePlugin


class _NetworkHwPluginBase(UniversalHardwarePlugin):
    category = HardwareType.SWITCH
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
        snmp = context.get("snmp") or {}
        signals = []
        if snmp.get("serial"):
            signals.append(IdentitySignal("serial", str(snmp["serial"]), "snmp"))
        if snmp.get("sysname"):
            signals.append(IdentitySignal("hostname", str(snmp["sysname"]), "snmp"))
        if context.get("mac_oui"):
            signals.append(IdentitySignal("mac", str(context["mac_oui"]), "snmp"))
        return resolver.build_identity(
            signals=signals, manufacturer=self.manufacturer,
            model=str(snmp.get("model") or self.product),
            device_type=HardwareType.SWITCH.value,
            firmware=snmp.get("firmware"),
            environment=context.get("environment"), source=self.plugin_id)

    def inventory(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        snmp = context.get("snmp") or {}
        if not snmp:
            return []
        return [self._raw(
            asset_id=context.get("asset_id") or snmp.get("sysname") or "switch",
            serial_reference=snmp.get("serial"),
            firmware=snmp.get("firmware"),
            vendor_specific={"snmp_sysdescr": snmp.get("sysdescr"),
                             "lldp": context.get("lldp"),
                             "cdp": context.get("cdp")})]

    def discover_firmware(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        snmp = context.get("snmp") or {}
        if not snmp.get("firmware"):
            return []
        return [self._raw(
            asset_id=context.get("asset_id", "switch"),
            firmware_component="NETWORK_APPLIANCE",
            version=snmp["firmware"])]

    def discover_crypto(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        crypto = context.get("crypto")
        if not crypto:
            return []
        return [self._raw(asset_id=context.get("asset_id", "switch"),
                          algorithm="network-crypto", crypto=crypto)]

    def discover_capabilities(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        capabilities = context.get("capabilities")
        if not capabilities:
            return []
        return [self._raw(asset_id=context.get("asset_id", "switch"),
                          algorithm="capability", capabilities=capabilities)]

    def normalize(self, raw: dict[str, Any]) -> HardwareObservation:
        return HardwareObservation(
            asset_id=str(raw.get("asset_id") or "switch"),
            manufacturer=self.manufacturer,
            model=str(raw.get("model") or self.product),
            serial_reference=raw.get("serial_reference"),
            device_type=HardwareType.SWITCH.value,
            firmware=raw.get("firmware"),
            environment=raw.get("environment"),
            source=raw.get("source", self.plugin_id),
            confidence=raw.get("confidence", HardwareConfidence.HIGH.value),
            firmware_components=dict(raw.get("firmware_components") or {}),
            vendor_specific=self._canonical_vendor_specific(raw),
        )


class CiscoHwPlugin(_NetworkHwPluginBase):
    plugin_id = "hw_cisco"
    manufacturer = "Cisco"
    product = "Catalyst"
    category = HardwareType.SWITCH
    _patterns = [
        (r"cisco.*(catalyst|nexus|asa|ios)", "Cisco", "Catalyst"),
        (r"cisco", "Cisco", "Catalyst"),
    ]


class JuniperHwPlugin(_NetworkHwPluginBase):
    plugin_id = "hw_juniper"
    manufacturer = "Juniper"
    product = "EX"
    category = HardwareType.SWITCH
    _patterns = [
        (r"juniper.*(ex|mx|srx)", "Juniper", "EX"),
        (r"juniper", "Juniper", "EX"),
    ]


class AristaHwPlugin(_NetworkHwPluginBase):
    plugin_id = "hw_arista"
    manufacturer = "Arista"
    product = "DCS"
    category = HardwareType.SWITCH
    _patterns = [
        (r"arista.*(dcs|7050|7280)", "Arista", "DCS"),
        (r"arista", "Arista", "DCS"),
    ]


class FortinetHwPlugin(_NetworkHwPluginBase):
    plugin_id = "hw_fortinet"
    manufacturer = "Fortinet"
    product = "FortiGate"
    category = HardwareType.FIREWALL
    _patterns = [
        (r"fortinet.*fortigate", "Fortinet", "FortiGate"),
        (r"fortigate", "Fortinet", "FortiGate"),
    ]
