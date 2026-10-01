"""Universal hardware event model + real-time event pipeline (§2).

Canonical hardware event taxonomy (HARDWARE_DISCOVERED … HSM_CONFIGURATION_CHANGED),
a publish/subscribe event bus, and the four-stage pipeline every event goes
through:

    Event → Identity Resolution → Change Classification →
    Impact Analysis → Targeted Scan Plan

The pipeline is fully deterministic (catalog-driven): classification and
impact rules are explicit tables, never heuristics or learned models.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field

from universal_vendor.hardware.identity import HardwareIdentityResolver
from universal_vendor.hardware.live.state import _HARDWARE_EVENT_TYPES, _EVENT_ALIASES


class HardwareEventType(str, Enum):
    """§2 taxonomy — discovery/lifecycle, firmware, crypto capability,
    TPM (§8) and HSM (§9) lifecycle events."""

    HARDWARE_DISCOVERED = "HARDWARE_DISCOVERED"
    HARDWARE_REMOVED = "HARDWARE_REMOVED"
    HARDWARE_REPLACED = "HARDWARE_REPLACED"
    HARDWARE_CHANGED = "HARDWARE_CHANGED"
    HARDWARE_CAPABILITY_CHANGED = "HARDWARE_CAPABILITY_CHANGED"
    FIRMWARE_CHANGED = "FIRMWARE_CHANGED"
    BIOS_CHANGED = "BIOS_CHANGED"
    UEFI_CHANGED = "UEFI_CHANGED"
    BMC_CHANGED = "BMC_CHANGED"
    NIC_CHANGED = "NIC_CHANGED"
    STORAGE_CHANGED = "STORAGE_CHANGED"
    CRYPTO_CAPABILITY_CHANGED = "CRYPTO_CAPABILITY_CHANGED"
    TPM_CHANGED = "TPM_CHANGED"
    TPM_AVAILABLE = "TPM_AVAILABLE"
    TPM_UNAVAILABLE = "TPM_UNAVAILABLE"
    TPM_CONFIGURATION_CHANGED = "TPM_CONFIGURATION_CHANGED"
    TPM_FIRMWARE_CHANGED = "TPM_FIRMWARE_CHANGED"
    HSM_CHANGED = "HSM_CHANGED"
    HSM_ONLINE = "HSM_ONLINE"
    HSM_OFFLINE = "HSM_OFFLINE"
    HSM_CAPABILITY_CHANGED = "HSM_CAPABILITY_CHANGED"
    HSM_CONFIGURATION_CHANGED = "HSM_CONFIGURATION_CHANGED"


class HardwareEvent(BaseModel):
    """One canonical hardware event. Metadata only — payloads never carry
    secrets, key material or private TPM/HSM data (enforced upstream by the
    TPM/HSM scanners)."""

    event_type: HardwareEventType
    asset_id: str = ""
    agent_id: Optional[str] = None
    source: str = "unknown"          # agent | snmp | management_api | passive | hypervisor_api | local_os
    observed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    serial_reference: Optional[str] = None
    hardware_revision: Optional[str] = None
    device_type: Optional[str] = None
    component: Optional[str] = None
    version: Optional[str] = None
    firmware: Optional[dict[str, Any]] = None
    tpm: Optional[dict[str, Any]] = None
    hsm: Optional[dict[str, Any]] = None
    capabilities: Optional[dict[str, Any]] = None
    crypto_capabilities: Optional[dict[str, Any]] = None
    payload: dict[str, Any] = Field(default_factory=dict)

    def to_state_event(self) -> dict[str, Any]:
        """Shape accepted by HardwareStateEngine.apply_event."""
        return {
            "event_type": self.event_type.value,
            "asset_id": self.asset_id,
            "agent_id": self.agent_id,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "serial_reference": self.serial_reference,
            "hardware_revision": self.hardware_revision,
            "device_type": self.device_type,
            "component": self.component,
            "version": self.version,
            "firmware": self.firmware,
            "tpm": self.tpm,
            "hsm": self.hsm,
            "capabilities": self.capabilities,
            "crypto_capabilities": self.crypto_capabilities,
        }


class HardwareEventBus:
    """Publish/subscribe bus. Subscribers are deterministic callables."""

    def __init__(self) -> None:
        self._subscribers: list[Callable[[HardwareEvent], None]] = []
        self._seen: list[HardwareEvent] = []

    def subscribe(self, fn: Callable[[HardwareEvent], None]) -> None:
        self._subscribers.append(fn)

    def emit(self, event: HardwareEvent) -> HardwareEvent:
        self._seen.append(event)
        for fn in list(self._subscribers):
            try:
                fn(event)
            except Exception as _handler_exc:  # one bad subscriber never breaks the bus
                logger.warning(
                    "exception_suppressed",
                    extra={"error_type": type(_handler_exc).__name__},
                )
                continue
        return event

    def events(self) -> list[HardwareEvent]:
        return list(self._seen)

    def count(self) -> int:
        return len(self._seen)


# ── §2 change classification ────────────────────────────────────────────

class ChangeClass(str, Enum):
    NEW_DISCOVERY = "NEW_DISCOVERY"
    REMOVAL = "REMOVAL"
    REPLACEMENT = "REPLACEMENT"
    FIRMWARE_CHANGE = "FIRMWARE_CHANGE"
    SECURITY_HARDWARE_CHANGE = "SECURITY_HARDWARE_CHANGE"
    CAPABILITY_CHANGE = "CAPABILITY_CHANGE"
    CONFIGURATION_CHANGE = "CONFIGURATION_CHANGE"
    NO_EFFECT = "NO_EFFECT"


# event type -> change class (deterministic catalog)
_CLASSIFICATION_CATALOG: dict[str, str] = {
    "HARDWARE_DISCOVERED": ChangeClass.NEW_DISCOVERY.value,
    "DEVICE_ADDED": ChangeClass.NEW_DISCOVERY.value,
    "HARDWARE_REMOVED": ChangeClass.REMOVAL.value,
    "DEVICE_REMOVED": ChangeClass.REMOVAL.value,
    "HARDWARE_REPLACED": ChangeClass.REPLACEMENT.value,
    "FIRMWARE_CHANGED": ChangeClass.FIRMWARE_CHANGE.value,
    "BIOS_CHANGED": ChangeClass.FIRMWARE_CHANGE.value,
    "UEFI_CHANGED": ChangeClass.FIRMWARE_CHANGE.value,
    "BMC_CHANGED": ChangeClass.FIRMWARE_CHANGE.value,
    "TPM_FIRMWARE_CHANGED": ChangeClass.FIRMWARE_CHANGE.value,
    "TPM_AVAILABLE": ChangeClass.SECURITY_HARDWARE_CHANGE.value,
    "TPM_UNAVAILABLE": ChangeClass.SECURITY_HARDWARE_CHANGE.value,
    "TPM_CHANGED": ChangeClass.SECURITY_HARDWARE_CHANGE.value,
    "TPM_CONFIGURATION_CHANGED": ChangeClass.SECURITY_HARDWARE_CHANGE.value,
    "HSM_ONLINE": ChangeClass.SECURITY_HARDWARE_CHANGE.value,
    "HSM_OFFLINE": ChangeClass.SECURITY_HARDWARE_CHANGE.value,
    "HSM_CHANGED": ChangeClass.SECURITY_HARDWARE_CHANGE.value,
    "HSM_CAPABILITY_CHANGED": ChangeClass.CAPABILITY_CHANGE.value,
    "HSM_CONFIGURATION_CHANGED": ChangeClass.CONFIGURATION_CHANGE.value,
    "CRYPTO_CAPABILITY_CHANGED": ChangeClass.CAPABILITY_CHANGE.value,
    "HARDWARE_CAPABILITY_CHANGED": ChangeClass.CAPABILITY_CHANGE.value,
    "NIC_CHANGED": ChangeClass.CONFIGURATION_CHANGE.value,
    "STORAGE_CHANGED": ChangeClass.CONFIGURATION_CHANGE.value,
    "HARDWARE_CHANGED": ChangeClass.CONFIGURATION_CHANGE.value,
}

# Change class -> severity for impact analysis
_CLASS_SEVERITY: dict[str, str] = {
    "NEW_DISCOVERY": "INFO",
    "REMOVAL": "HIGH",
    "REPLACEMENT": "HIGH",
    "FIRMWARE_CHANGE": "MEDIUM",
    "SECURITY_HARDWARE_CHANGE": "HIGH",
    "CAPABILITY_CHANGE": "MEDIUM",
    "CONFIGURATION_CHANGE": "LOW",
    "NO_EFFECT": "INFO",
}

# Change class -> affected subsystems (impact scope)
_CLASS_IMPACT: dict[str, list[str]] = {
    "NEW_DISCOVERY": ["inventory", "capabilities", "crypto_capabilities", "hbom"],
    "REMOVAL": ["inventory", "hbom", "software_dependencies", "network_relationships"],
    "REPLACEMENT": ["inventory", "capabilities", "crypto_capabilities", "hbom",
                    "software_dependencies", "pqc"],
    "FIRMWARE_CHANGE": ["firmware", "capabilities", "crypto_capabilities", "pqc"],
    "SECURITY_HARDWARE_CHANGE": ["security_hardware", "capabilities",
                                 "crypto_capabilities", "pqc"],
    "CAPABILITY_CHANGE": ["capabilities", "crypto_capabilities", "pqc"],
    "CONFIGURATION_CHANGE": ["configuration", "capabilities"],
    "NO_EFFECT": [],
}


def classify_change(event: HardwareEvent) -> str:
    """§2 change classification — event type -> class (catalog)."""
    name = _EVENT_ALIASES.get(event.event_type.value, event.event_type.value)
    return _CLASSIFICATION_CATALOG.get(name, ChangeClass.NO_EFFECT.value)


def analyze_impact(event: HardwareEvent, change_class: str) -> dict[str, Any]:
    """§2 impact analysis — which subsystems are affected + severity."""
    return {
        "severity": _CLASS_SEVERITY.get(change_class, "INFO"),
        "affected_subsystems": list(_CLASS_IMPACT.get(change_class, [])),
        "crypto_affected": change_class in (
            ChangeClass.FIRMWARE_CHANGE.value, ChangeClass.SECURITY_HARDWARE_CHANGE.value,
            ChangeClass.CAPABILITY_CHANGE.value, ChangeClass.REPLACEMENT.value,
        ),
        "pqc_affected": change_class in (
            ChangeClass.FIRMWARE_CHANGE.value, ChangeClass.SECURITY_HARDWARE_CHANGE.value,
            ChangeClass.CAPABILITY_CHANGE.value, ChangeClass.REPLACEMENT.value,
            ChangeClass.NEW_DISCOVERY.value,
        ),
    }


@dataclass
class HardwareEventEnvelope:
    """The full §2 pipeline result for one event."""

    event: HardwareEvent
    asset_id: str
    change_class: str
    impact: dict[str, Any]
    targeted_actions: list[str] = field(default_factory=list)
    identity_signals: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event.event_type.value,
            "asset_id": self.asset_id,
            "source": self.event.source,
            "observed_at": self.event.observed_at,
            "change_class": self.change_class,
            "impact": self.impact,
            "targeted_actions": list(self.targeted_actions),
            "identity_signals": list(self.identity_signals),
        }


class HardwareEventPipeline:
    """Event → Identity Resolution → Change Classification → Impact →
    Targeted Scan Plan (§2). Deterministic; produces an envelope."""

    def __init__(
        self,
        identity: Optional[HardwareIdentityResolver] = None,
        reaction_planner: Optional[Any] = None,
    ) -> None:
        self._identity = identity or HardwareIdentityResolver()
        self._reaction = reaction_planner  # optional; injected by controller

    def resolve_identity(self, event: HardwareEvent) -> tuple[str, list[str]]:
        """Identity resolution from multi-signal evidence (§3, §2)."""
        resolved = self._identity.resolve(
            serial=event.serial_reference,
            mac=(event.payload or {}).get("mac"),
            dmi_uuid=(event.payload or {}).get("dmi_uuid"),
            asset_tag=(event.payload or {}).get("asset_tag"),
            bmc=(event.payload or {}).get("bmc"),
            hostname=(event.payload or {}).get("hostname"),
            cloud_resource=(event.payload or {}).get("cloud_resource"),
        )
        if resolved is not None:
            # signals that matched this identity (deterministic, sorted)
            matched = sorted(
                sig for sig, aid in self._identity._by_signal.items() if aid == resolved.asset_id
            )
            return resolved.asset_id, matched
        if event.asset_id:
            return event.asset_id, []
        # no identity signals at all -> stable fallback key. Python's built-in
        # hash is intentionally randomized between processes, so it cannot be
        # used as an asset identity or timeline join key.
        import hashlib
        import json

        # Include the immutable event shape so two anonymous events emitted at
        # the same timestamp/source do not collapse merely because their
        # process-local hash seed happened to differ. Hash only the canonical
        # envelope; do not expose payload contents in the fallback identity.
        seed = json.dumps({
            "observed_at": event.observed_at,
            "source": event.source,
            "event_type": event.event_type.value,
            "component": event.component,
            "version": event.version,
            "device_type": event.device_type,
            "payload": event.payload,
        }, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        fallback = f"hw-unknown-{hashlib.sha256(seed).hexdigest()[:12]}"
        return fallback, []

    def process(self, event: HardwareEvent) -> HardwareEventEnvelope:
        asset_id, signals = self.resolve_identity(event)
        change_class = classify_change(event)
        impact = analyze_impact(event, change_class)
        actions: list[str] = []
        if self._reaction is not None:
            plan = self._reaction.plan(
                event_type=event.event_type.value,
                change_class=change_class,
                asset_id=asset_id,
                payload=event.payload,
            )
            actions = plan.get("required_actions", [])
        return HardwareEventEnvelope(
            event=event, asset_id=asset_id, change_class=change_class,
            impact=impact, targeted_actions=actions, identity_signals=signals,
        )


def canonical_event_types() -> list[str]:
    """All canonical §2/§8/§9 event names."""
    return [t.value for t in HardwareEventType]


def normalize_event_type(name: str) -> str:
    """Legacy alias -> canonical name; unknown names raise ValueError."""
    canonical = _EVENT_ALIASES.get(name, name)
    if canonical not in _HARDWARE_EVENT_TYPES:
        raise ValueError(f"unknown hardware event type {name!r}")
    return canonical
