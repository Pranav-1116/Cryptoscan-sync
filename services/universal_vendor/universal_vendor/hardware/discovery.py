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
                    # DMI describes the chassis and the firmware, not what is
                    # inside it. Memory modules, disks and NICs are separate
                    # reads on the same host and must survive the merge.
                    "memory_modules": context.get("memory_modules") or [],
                    "disks": context.get("disks") or [],
                    "nics": context.get("nics") or [],
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
        # NETCONF and RESTCONF produce the same facts as SNMP under a different
        # key. Reading only "snmp" here is how a firewall reached the collector
        # and stopped: the transport was implemented and the merge never asked
        # for it.
        device = context.get("network_device") or {}
        if device:
            records.append({
                "asset_id": context.get("asset_id") or device.get("sysname")
                or "network-device",
                "manufacturer": device.get("manufacturer")
                or context.get("manufacturer", ""),
                "model": device.get("model") or context.get("model", ""),
                "serial_reference": device.get("serial"),
                "device_type": context.get("device_type", HardwareType.SWITCH.value),
                "firmware": device.get("firmware"),
                "source": self.method,
                "confidence": HardwareConfidence.HIGH.value,
                "vendor_specific": {
                    "protocol": device.get("protocol"),
                    "sysname": device.get("sysname"),
                    "location": device.get("location"),
                    "security_mode": device.get("security_mode"),
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
                        merged[asset_id] = _seed_merge_record(raw)
                    else:
                        merged[asset_id] = _merge_discovery_record(existing, raw)
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
                discovery_sources=list(raw.get("discovery_sources") or []),
                identity_conflicts=dict(raw.get("identity_conflicts") or {}),
                vendor_specific=dict(raw.get("vendor_specific") or {}),
            ))
        return observations


_CANONICAL_IDENTITY_FIELDS = (
    "manufacturer", "model", "serial_reference", "device_type",
    "firmware", "environment", "region", "visibility",
)


def _seed_merge_record(raw: dict[str, Any]) -> dict[str, Any]:
    record = dict(raw)
    record["discovery_sources"] = [str(raw.get("source") or "unknown")]
    record["identity_conflicts"] = {}
    record["vendor_specific"] = dict(raw.get("vendor_specific") or {})
    return record


def _meaningful(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip()) and value.strip().lower() not in {"unknown", "n/a", "none", "null", "-"}
    return bool(value)


def _identity_values_conflict(field: str, old_value: Any, new_value: Any) -> bool:
    old_text, new_text = str(old_value).strip().casefold(), str(new_value).strip().casefold()
    if old_text == new_text:
        return False
    # A vendor plugin or management API may report a product family while DMI
    # reports the more specific SKU. Treat that as corroboration, not a false
    # identity conflict; unrelated names remain explicit conflicts.
    if field == "model" and (old_text.startswith(new_text) or new_text.startswith(old_text)):
        return False
    return True


def _merge_discovery_record(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    """Merge source observations without losing weaker evidence or conflicts."""
    old_source = str(existing.get("source") or "unknown")
    new_source = str(incoming.get("source") or "unknown")
    old_rank = _confidence_rank(existing.get("confidence"))
    new_rank = _confidence_rank(incoming.get("confidence"))
    # Ties keep the first source for deterministic canonical output; all source
    # evidence is still retained below.
    winner = dict(incoming if new_rank > old_rank else existing)
    conflicts = {
        key: [dict(item) for item in values]
        for key, values in (existing.get("identity_conflicts") or {}).items()
    }
    for key in _CANONICAL_IDENTITY_FIELDS:
        old_value = existing.get(key)
        new_value = incoming.get(key)
        if (_meaningful(old_value) and _meaningful(new_value)
                and _identity_values_conflict(key, old_value, new_value)):
            rows = conflicts.setdefault(key, [])
            for source, value in ((old_source, old_value), (new_source, new_value)):
                if not any(item.get("source") == source and str(item.get("value")) == str(value)
                           for item in rows):
                    rows.append({"source": source, "value": value})
        # Do not replace a useful winner field with an absent/placeholder field.
        if not _meaningful(winner.get(key)):
            winner[key] = new_value if _meaningful(new_value) else old_value

    vendor_specific = dict(existing.get("vendor_specific") or {})
    for key, value in (incoming.get("vendor_specific") or {}).items():
        if key not in vendor_specific or vendor_specific[key] in (None, "", {}, []):
            vendor_specific[key] = value
        elif vendor_specific[key] != value:
            # Preserve both observations under a provenance namespace rather
            # than allowing the later source to erase the earlier one.
            evidence = vendor_specific.setdefault("discovery_evidence", {})
            evidence.setdefault(old_source, {})[key] = vendor_specific[key]
            evidence.setdefault(new_source, {})[key] = value
    sources = sorted(set(existing.get("discovery_sources") or [old_source]) | {new_source})
    winner["discovery_sources"] = sources
    winner["identity_conflicts"] = conflicts
    winner["vendor_specific"] = vendor_specific
    return winner


def _confidence_rank(value: Any) -> int:
    return {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(str(value or ""), 0)
