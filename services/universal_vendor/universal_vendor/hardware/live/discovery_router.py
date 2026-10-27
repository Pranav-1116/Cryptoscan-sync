"""Live hardware discovery mechanisms (§5).

Deterministic catalog mapping every hardware type to its discovery
mechanism — never one method for everything:

    Physical Server    → Agent / DMI / SMBIOS / PCI
    Network Hardware   → Telemetry / SNMPv3 / Management API
    HSM                → Authorized HSM Management Interface
    TPM                → Local OS / TPM Interface
    Storage            → OS / Storage Management API
    Virtualization     → Hypervisor API
    OT/ICS             → PASSIVE-FIRST discovery (the default, §22)
    IoT                → PASSIVE-FIRST discovery

``LiveDiscoveryRouter.execute`` runs ONLY the mechanism appropriate for the
device type, refuses active probing for OT/ICS unless the context explicitly
carries authorization, and is gated by the SafetyController (read-only,
authorized scope, rate limits) — every denial is audited.
"""

from __future__ import annotations

from typing import Any, Optional

from universal_vendor.hardware.discovery import (
    AgentBasedDiscovery,
    ApiBasedDiscovery,
    NetworkBasedDiscovery,
)

# device type -> mechanism (deterministic catalog, §5)
_MECHANISM_CATALOG: dict[str, str] = {
    # compute
    "server": "agent_dmi_smbios_pci",
    "workstation": "agent_dmi_smbios_pci",
    "laptop": "agent_dmi_smbios_pci",
    "blade_server": "agent_dmi_smbios_pci",
    "rack_server": "agent_dmi_smbios_pci",
    "gpu": "agent_dmi_smbios_pci",
    "accelerator": "agent_dmi_smbios_pci",
    # virtualization
    "hypervisor_host": "hypervisor_api",
    "virtualization": "hypervisor_api",
    # network
    "router": "telemetry_snmpv3_management_api",
    "switch": "telemetry_snmpv3_management_api",
    "firewall": "telemetry_snmpv3_management_api",
    "wireless_controller": "telemetry_snmpv3_management_api",
    "access_point": "telemetry_snmpv3_management_api",
    "load_balancer": "telemetry_snmpv3_management_api",
    "network_appliance": "telemetry_snmpv3_management_api",
    "security_appliance": "telemetry_snmpv3_management_api",
    # security hardware
    "hsm": "authorized_hsm_management_interface",
    "tpm": "local_os_tpm_interface",
    "smart_card": "local_os_smart_card_interface",
    "secure_element": "local_os_secure_element_interface",
    # storage
    "san": "os_storage_management_api",
    "nas": "os_storage_management_api",
    "raid_controller": "os_storage_management_api",
    "storage_appliance": "os_storage_management_api",
    "disk_encryption_controller": "os_storage_management_api",
    # OT/ICS + IoT — passive-first is the default (§22)
    "iot_gateway": "passive_first",
    "industrial_controller": "passive_first",
    "plc": "passive_first",
    "ot_appliance": "passive_first",
    "embedded": "passive_first",
    "other": "agent_dmi_smbios_pci",
}

# mechanisms that may NEVER actively probe a device
_PASSIVE_ONLY = frozenset({"passive_first"})


def discovery_mechanism(device_type: str) -> str:
    """§5 mechanism for a hardware type (deterministic catalog)."""
    return _MECHANISM_CATALOG.get(str(device_type).lower(), "agent_dmi_smbios_pci")


class LiveDiscoveryRouter:
    """Executes the §5 mechanism for one device type, safety-gated."""

    def __init__(self, safety: Optional[Any] = None) -> None:
        self.safety = safety  # SafetyController (optional; honors read-only/scope)
        self._collectors = {
            "agent_dmi_smbios_pci": AgentBasedDiscovery(),
            "telemetry_snmpv3_management_api": NetworkBasedDiscovery(),
            "authorized_hsm_management_interface": ApiBasedDiscovery(),
            "local_os_tpm_interface": AgentBasedDiscovery(),
            "local_os_smart_card_interface": AgentBasedDiscovery(),
            "local_os_secure_element_interface": AgentBasedDiscovery(),
            "os_storage_management_api": ApiBasedDiscovery(),
            "hypervisor_api": ApiBasedDiscovery(),
            "passive_first": NetworkBasedDiscovery(),
        }
        self._audit: list[dict[str, Any]] = []

    def mechanism(self, device_type: str) -> str:
        return discovery_mechanism(device_type)

    def execute(self, *, device_type: str, context: dict[str, Any],
                asset_id: str = "") -> dict[str, Any]:
        """Run ONLY the mechanism for this device type.

        OT/ICS (passive_first) never probes actively: the SNMP/SSH/credential
        parts of the context are ignored and only passive observations are
        used. Safety gating runs first — out-of-scope assets are refused and
        audited, never scanned.
        """
        mechanism = discovery_mechanism(device_type)
        target = asset_id or str(context.get("asset_id") or "unknown")

        if self.safety is not None:
            allowed, reason = self.safety.can_scan(asset_id=target, vendor="")
            if not allowed:
                self._audit.append({
                    "asset_id": target, "device_type": device_type,
                    "mechanism": mechanism, "outcome": "BLOCKED", "reason": reason,
                })
                return {"device_type": device_type, "mechanism": mechanism,
                        "observations": [], "blocked": True, "reason": reason}

        collector = self._collectors[mechanism]
        if mechanism in _PASSIVE_ONLY:
            # passive-first: strip everything that could probe the device
            passive_context = {
                "asset_id": target,
                "device_type": device_type,
                "passive_observation": context.get("passive_observation"),
                "manufacturer": context.get("manufacturer"),
                "model": context.get("model"),
            }
            records = collector.collect(passive_context)
        else:
            records = collector.collect(context)

        observations = []
        for raw in records:
            raw.setdefault("device_type", device_type)
            observations.append(raw)

        self._audit.append({
            "asset_id": target, "device_type": device_type,
            "mechanism": mechanism, "outcome": "ALLOWED",
            "observations": len(observations),
        })
        return {"device_type": device_type, "mechanism": mechanism,
                "observations": observations, "blocked": False,
                "passive_only": mechanism in _PASSIVE_ONLY}

    def audit(self) -> list[dict[str, Any]]:
        return list(self._audit)

    def catalog(self) -> dict[str, str]:
        """Full §5 mechanism catalog (device type -> mechanism)."""
        return dict(sorted(_MECHANISM_CATALOG.items()))
