"""Change-triggered targeted re-discovery (§6).

The 24/7 engine never rescans everything on a timer. Instead:

    EVENT → WHAT CHANGED? → WHICH HARDWARE? → WHAT INFORMATION IS AFFECTED?
    → RUN ONLY THE REQUIRED DISCOVERY

This module maps every canonical hardware event to the *minimum* set of
targeted discovery/verification actions, and explicitly lists what is NOT
affected (e.g. a BIOS update never triggers a storage rescan). The catalog
is deterministic — no heuristics.
"""

from __future__ import annotations

from typing import Any, Optional

from universal_vendor.hardware.live.events import ChangeClass, classify_change

# event type -> targeted verification actions (deterministic catalog).
# The §6 example: BIOS_UPDATED → BIOS verification → hardware capability
# verification → crypto capability verification → PQC reassessment.
_REACTION_CATALOG: dict[str, dict[str, Any]] = {
    "HARDWARE_DISCOVERED": {
        "required_actions": ["full_inventory", "capability_verification",
                             "crypto_capability_verification", "pqc_reassessment",
                             "hbom_update"],
        "affected_information": ["inventory", "capabilities", "crypto capabilities",
                                 "PQC readiness", "HBOM"],
        "explicitly_not_affected": [],
    },
    "HARDWARE_REMOVED": {
        "required_actions": ["confirm_removal", "dependency_impact_analysis",
                             "hbom_update"],
        "affected_information": ["inventory", "HBOM", "software dependencies",
                                 "network relationships"],
        "explicitly_not_affected": ["capability re-verification"],
    },
    "HARDWARE_REPLACED": {
        "required_actions": ["identity_reverification", "capability_verification",
                             "crypto_capability_verification", "pqc_reassessment",
                             "dependency_impact_analysis", "hbom_update"],
        "affected_information": ["identity", "capabilities", "crypto capabilities",
                                 "PQC readiness", "dependencies", "HBOM"],
        "explicitly_not_affected": ["unrelated asset re-scan"],
    },
    "BIOS_CHANGED": {
        "required_actions": ["bios_verification", "hardware_capability_verification",
                             "crypto_capability_verification", "pqc_reassessment"],
        "affected_information": ["BIOS", "hardware capabilities",
                                 "crypto capabilities", "PQC readiness"],
        "explicitly_not_affected": ["storage re-scan", "network re-scan",
                                    "unrelated device re-scan"],
    },
    "UEFI_CHANGED": {
        "required_actions": ["uefi_verification", "secure_boot_verification",
                             "hardware_capability_verification",
                             "crypto_capability_verification", "pqc_reassessment"],
        "affected_information": ["UEFI", "secure boot", "capabilities",
                                 "crypto capabilities", "PQC readiness"],
        "explicitly_not_affected": ["storage re-scan", "unrelated device re-scan"],
    },
    "BMC_CHANGED": {
        "required_actions": ["bmc_verification", "bmc_capability_verification"],
        "affected_information": ["BMC firmware", "BMC capabilities"],
        "explicitly_not_affected": ["storage re-scan", "application re-scan"],
    },
    "FIRMWARE_CHANGED": {
        "required_actions": ["firmware_verification", "capability_verification",
                             "crypto_capability_verification", "pqc_reassessment"],
        "affected_information": ["firmware", "capabilities", "crypto capabilities",
                                 "PQC readiness"],
        "explicitly_not_affected": ["unrelated component re-scan"],
    },
    "NIC_CHANGED": {
        "required_actions": ["nic_verification", "network_relationship_analysis",
                             "capability_verification"],
        "affected_information": ["NIC", "network relationships", "capabilities"],
        "explicitly_not_affected": ["storage re-scan", "BIOS re-verification"],
    },
    "STORAGE_CHANGED": {
        "required_actions": ["storage_verification", "storage_capability_verification"],
        "affected_information": ["storage controller", "storage capabilities"],
        "explicitly_not_affected": ["network re-scan", "BIOS re-verification"],
    },
    "TPM_AVAILABLE": {
        "required_actions": ["tpm_verification", "crypto_capability_verification",
                             "pqc_reassessment"],
        "affected_information": ["TPM", "crypto capabilities", "PQC readiness"],
        "explicitly_not_affected": ["storage re-scan"],
    },
    "TPM_UNAVAILABLE": {
        "required_actions": ["tpm_verification", "security_drift_check",
                             "crypto_capability_verification"],
        "affected_information": ["TPM", "security posture", "crypto capabilities"],
        "explicitly_not_affected": ["storage re-scan"],
    },
    "TPM_CHANGED": {
        "required_actions": ["tpm_verification", "crypto_capability_verification",
                             "pqc_reassessment"],
        "affected_information": ["TPM", "crypto capabilities", "PQC readiness"],
        "explicitly_not_affected": ["storage re-scan"],
    },
    "TPM_CONFIGURATION_CHANGED": {
        "required_actions": ["tpm_configuration_verification",
                             "crypto_capability_verification"],
        "affected_information": ["TPM configuration", "crypto capabilities"],
        "explicitly_not_affected": ["storage re-scan"],
    },
    "TPM_FIRMWARE_CHANGED": {
        "required_actions": ["tpm_firmware_verification",
                             "crypto_capability_verification", "pqc_reassessment"],
        "affected_information": ["TPM firmware", "crypto capabilities",
                                 "PQC readiness"],
        "explicitly_not_affected": ["storage re-scan"],
    },
    "HSM_ONLINE": {
        "required_actions": ["hsm_health_verification", "hsm_capability_verification",
                             "crypto_capability_verification"],
        "affected_information": ["HSM health", "HSM capabilities",
                                 "crypto capabilities"],
        "explicitly_not_affected": ["storage re-scan"],
    },
    "HSM_OFFLINE": {
        "required_actions": ["hsm_health_verification", "dependency_impact_analysis",
                             "crypto_capability_verification"],
        "affected_information": ["HSM health", "dependencies", "crypto capabilities"],
        "explicitly_not_affected": ["storage re-scan"],
    },
    "HSM_CHANGED": {
        "required_actions": ["hsm_verification", "hsm_capability_verification",
                             "crypto_capability_verification", "pqc_reassessment"],
        "affected_information": ["HSM", "HSM capabilities", "crypto capabilities",
                                 "PQC readiness"],
        "explicitly_not_affected": ["storage re-scan"],
    },
    "HSM_CAPABILITY_CHANGED": {
        "required_actions": ["hsm_capability_verification",
                             "crypto_capability_verification", "pqc_reassessment"],
        "affected_information": ["HSM capabilities", "crypto capabilities",
                                 "PQC readiness"],
        "explicitly_not_affected": ["storage re-scan", "network re-scan"],
    },
    "HSM_CONFIGURATION_CHANGED": {
        "required_actions": ["hsm_configuration_verification",
                             "crypto_capability_verification"],
        "affected_information": ["HSM configuration", "crypto capabilities"],
        "explicitly_not_affected": ["storage re-scan"],
    },
    "CRYPTO_CAPABILITY_CHANGED": {
        "required_actions": ["crypto_capability_verification", "pqc_reassessment",
                             "dependency_impact_analysis"],
        "affected_information": ["crypto capabilities", "PQC readiness",
                                 "software dependencies"],
        "explicitly_not_affected": ["storage re-scan", "BIOS re-verification"],
    },
    "HARDWARE_CAPABILITY_CHANGED": {
        "required_actions": ["capability_verification",
                             "crypto_capability_verification", "pqc_reassessment"],
        "affected_information": ["capabilities", "crypto capabilities",
                                 "PQC readiness"],
        "explicitly_not_affected": ["storage re-scan"],
    },
    "HARDWARE_CHANGED": {
        "required_actions": ["state_verification", "capability_verification"],
        "affected_information": ["hardware state", "capabilities"],
        "explicitly_not_affected": ["unrelated device re-scan"],
    },
}

_DEFAULT_REACTION: dict[str, Any] = {
    "required_actions": ["state_verification"],
    "affected_information": ["hardware state"],
    "explicitly_not_affected": [],
}


class ChangeReactionPlanner:
    """Plans the minimum targeted discovery for a hardware change (§6)."""

    def plan(
        self,
        *,
        event_type: str,
        change_class: Optional[str] = None,
        asset_id: str = "",
        payload: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        canonical = event_type
        from universal_vendor.hardware.live.state import _EVENT_ALIASES
        canonical = _EVENT_ALIASES.get(event_type, event_type)

        entry = _REACTION_CATALOG.get(canonical, _DEFAULT_REACTION)
        cls = change_class or classify_change(_event_stub(canonical, asset_id))
        return {
            "event_type": canonical,
            "asset_id": asset_id,
            "change_class": cls,
            "required_actions": list(entry["required_actions"]),
            "affected_information": list(entry["affected_information"]),
            "explicitly_not_affected": list(entry["explicitly_not_affected"]),
            "scope": "TARGETED" if entry["required_actions"] else "NONE",
            "rationale": f"{canonical} affects only: "
                         f"{', '.join(entry['affected_information'])}",
        }

    def known_event(self, event_type: str) -> bool:
        from universal_vendor.hardware.live.state import _EVENT_ALIASES
        canonical = _EVENT_ALIASES.get(event_type, event_type)
        return canonical in _REACTION_CATALOG


def _event_stub(event_type: str, asset_id: str):
    """Minimal event object for classification (avoids import cycle at top)."""
    from universal_vendor.hardware.live.events import HardwareEvent, HardwareEventType

    try:
        etype = HardwareEventType(event_type)
    except ValueError:
        etype = HardwareEventType.HARDWARE_CHANGED
    return HardwareEvent(event_type=etype, asset_id=asset_id)
