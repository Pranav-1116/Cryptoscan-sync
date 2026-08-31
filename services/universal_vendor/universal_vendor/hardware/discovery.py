"""Three discovery methods (§2) — agent-based, network-based, API-based.

The scanner never relies on one method: an orchestrator runs all three
(authorized) collectors and merges their evidence into canonical
HardwareObservations.
"""

from __future__ import annotations

from typing import Any, Iterable

from universal_vendor.hardware.models import (
    CloudVisibility,
    DiscoveryMethod,
    HardwareConfidence,
    HardwareObservation,
    HardwareType,
)


class AgentBasedDiscovery:
    """§2 agent-based: OS/BMC, PCI/USB, DMI/SMBIOS on authorized machines."""

    method = DiscoveryMethod.AGENT.value

    def collect(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        dmi = context.get("dmi") or {}
        records: list[dict[str, Any]] = []
        if dmi:
            records.append({
                "asset_id": context.get("asset_id") or dmi.get("serial") or "agent-host",
                "manufacturer": dmi.get("manufacturer", ""),
                "model": dmi.get("product", ""),
                "serial_reference": dmi.get("serial"),
                "device_type": context.get("device_type", HardwareType.SERVER.value),
                "firmware": dmi.get("bios_version"),
                "source": self.method,
                "confidence": HardwareConfidence.HIGH.value,
                "vendor_specific": {
                    "dmi": dmi,
                    "pci_devices": context.get("pci_devices") or [],
                    "usb_devices": context.get("usb_devices") or [],
                    "bmc": context.get("bmc"),
                },
            })
        if context.get("pci_devices") and not dmi:
            records.append({
                "asset_id": context.get("asset_id", "agent-host"),
                "manufacturer": context.get("manufacturer", ""),
                "model": context.get("model", ""),
                "device_type": context.get("device_type", HardwareType.SERVER.value),
                "source": self.method,
                "confidence": HardwareConfidence.MEDIUM.value,
                "vendor_specific": {"pci_devices": context["pci_devices"]},
            })
        return records


class NetworkBasedDiscovery:
    """§2 network-based: SNMP, SSH, LLDP, CDP, vendor APIs, passive data."""

    method = DiscoveryMethod.NETWORK.value

    def collect(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        snmp = context.get("snmp") or {}
        if snmp:
            records.append({
                "asset_id": context.get("asset_id") or snmp.get("sysname")
                or snmp.get("sysdescr", "network-host"),
                "manufacturer": snmp.get("manufacturer", ""),
                "model": snmp.get("model", ""),
                "serial_reference": snmp.get("serial"),
                "device_type": context.get("device_type", HardwareType.SWITCH.value),
                "firmware": snmp.get("firmware"),
                "source": self.method,
                "confidence": HardwareConfidence.HIGH.value,
                "vendor_specific": {
                    "snmp_sysdescr": snmp.get("sysdescr"),
                    "lldp": context.get("lldp"),
                    "cdp": context.get("cdp"),
                    "mac_oui": context.get("mac_oui"),
                },
            })
        if context.get("passive_observation"):
            records.append({
                "asset_id": context.get("asset_id", "passive-host"),
                "manufacturer": context.get("manufacturer", ""),
                "model": context.get("model", ""),
                "device_type": context.get("device_type", HardwareType.OTHER.value),
                "source": self.method,
                "confidence": HardwareConfidence.LOW.value,
                "visibility": CloudVisibility.INFERRED.value,
                "vendor_specific": {"passive": context["passive_observation"]},
            })
        return records


class ApiBasedDiscovery:
    """§2 API-based: server management, virtualization, storage, cloud APIs."""

    method = DiscoveryMethod.API.value

    def collect(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        metadata = context.get("api_metadata")
        if isinstance(metadata, str):
            import json

            try:
                metadata = json.loads(metadata)
            except Exception:
                metadata = {}
        metadata = metadata if isinstance(metadata, dict) else {}
        records: list[dict[str, Any]] = []
        for device in metadata.get("devices") or []:
            records.append({
                "asset_id": device.get("asset_id") or device.get("name")
                or device.get("instance_id"),
                "manufacturer": device.get("manufacturer", ""),
                "model": device.get("model", "") or device.get("instance_type", ""),
                "serial_reference": device.get("serial"),
                "device_type": device.get("device_type", HardwareType.SERVER.value),
                "firmware": device.get("firmware"),
                "environment": device.get("environment"),
                "region": device.get("region"),
                "source": self.method,
                "confidence": HardwareConfidence.HIGH.value,
                "visibility": device.get("visibility", CloudVisibility.PROVIDER_DECLARED.value),
                "vendor_specific": device,
            })
        return records


class HardwareDiscoveryOrchestrator:
    """Runs all authorized collectors and merges by asset_id."""

    def __init__(self, *collectors: Any) -> None:
        self.collectors = list(collectors) or [
            AgentBasedDiscovery(), NetworkBasedDiscovery(), ApiBasedDiscovery(),
        ]

    def discover(self, contexts: Iterable[dict[str, Any]]) -> list[HardwareObservation]:
        merged: dict[str, dict[str, Any]] = {}
        for context in contexts:
            for collector in self.collectors:
                for raw in collector.collect(context):
                    asset_id = raw.get("asset_id") or "unknown"
                    existing = merged.get(asset_id)
                    if existing is None:
                        merged[asset_id] = raw
                        continue
                    # merge: keep higher-confidence source, union vendor_specific
                    if _confidence_rank(raw.get("confidence")) > _confidence_rank(
                            existing.get("confidence")):
                        merged[asset_id] = raw
                    existing.setdefault("vendor_specific", {}).update(
                        raw.get("vendor_specific") or {})
        observations = []
        for raw in merged.values():
            observations.append(HardwareObservation(
                asset_id=str(raw.get("asset_id", "unknown")),
                manufacturer=str(raw.get("manufacturer") or ""),
                model=str(raw.get("model") or ""),
                serial_reference=raw.get("serial_reference"),
                device_type=str(raw.get("device_type") or HardwareType.OTHER.value),
                firmware=raw.get("firmware"),
                environment=raw.get("environment"),
                region=raw.get("region"),
                source=str(raw.get("source") or "unknown"),
                confidence=str(raw.get("confidence") or HardwareConfidence.LOW.value),
                visibility=str(raw.get("visibility") or CloudVisibility.OBSERVED.value),
                vendor_specific=dict(raw.get("vendor_specific") or {}),
            ))
        return observations


def _confidence_rank(value: Any) -> int:
    return {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(str(value or ""), 0)
