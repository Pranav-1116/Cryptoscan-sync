"""§18/§19 Live platform event bus — one event stream across all five
domains, feeding a per-asset state engine with change detection and
targeted rescan dispatch.

Events are deterministic facts (``NEW_DEVICE``, ``CERTIFICATE_CHANGED``,
``FIRMWARE_CHANGED``, …). Nothing is inferred by a model; change detection
is field comparison against the previous state, and every change carries
the targeted rescan plan for the owning domain's scanner.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional


class PlatformEventType(str, Enum):
    """§19 platform event types (network / crypto / hardware / cloud / vendor)."""

    NEW_DEVICE = "NEW_DEVICE"
    DEVICE_CHANGED = "DEVICE_CHANGED"
    DEVICE_REMOVED = "DEVICE_REMOVED"
    NEW_CERTIFICATE = "NEW_CERTIFICATE"
    CERTIFICATE_CHANGED = "CERTIFICATE_CHANGED"
    LIBRARY_CHANGED = "LIBRARY_CHANGED"
    ALGORITHM_CHANGED = "ALGORITHM_CHANGED"
    TLS_CHANGED = "TLS_CHANGED"
    SSH_CHANGED = "SSH_CHANGED"
    FIRMWARE_CHANGED = "FIRMWARE_CHANGED"
    HSM_CHANGED = "HSM_CHANGED"
    CLOUD_RESOURCE_CHANGED = "CLOUD_RESOURCE_CHANGED"
    VENDOR_CONFIGURATION_CHANGED = "VENDOR_CONFIGURATION_CHANGED"
    CRYPTO_CAPABILITY_CHANGED = "CRYPTO_CAPABILITY_CHANGED"
    KEY_ROTATED = "KEY_ROTATED"


#: owning domain per event type — dispatch target for targeted rescan
EVENT_DOMAIN: dict[PlatformEventType, str] = {
    PlatformEventType.NEW_DEVICE: "network",
    PlatformEventType.DEVICE_CHANGED: "network",
    PlatformEventType.DEVICE_REMOVED: "network",
    PlatformEventType.NEW_CERTIFICATE: "crypto",
    PlatformEventType.CERTIFICATE_CHANGED: "crypto",
    PlatformEventType.LIBRARY_CHANGED: "crypto",
    PlatformEventType.ALGORITHM_CHANGED: "crypto",
    PlatformEventType.TLS_CHANGED: "network",
    PlatformEventType.SSH_CHANGED: "network",
    PlatformEventType.FIRMWARE_CHANGED: "hardware",
    PlatformEventType.HSM_CHANGED: "hardware",
    PlatformEventType.CLOUD_RESOURCE_CHANGED: "cloud",
    PlatformEventType.VENDOR_CONFIGURATION_CHANGED: "vendor",
    PlatformEventType.CRYPTO_CAPABILITY_CHANGED: "hardware",
    PlatformEventType.KEY_ROTATED: "crypto",
}

#: per-domain targeted analysis steps (deterministic, no AI)
TARGETED_ANALYSIS: dict[str, list[str]] = {
    "network": ["device_reinventory", "tls_recheck", "route_recheck"],
    "crypto": ["algorithm_reclassify", "quantum_recheck", "cbom_update"],
    "hardware": ["capability_recheck", "firmware_recheck", "hbom_update"],
    "cloud": ["resource_recheck", "cert_recheck", "kms_recheck"],
    "vendor": ["product_recheck", "support_recheck", "risk_recheck"],
}


@dataclass
class PlatformEvent:
    event_type: PlatformEventType
    asset_identity: str
    domain: str
    payload: dict[str, Any] = field(default_factory=dict)
    observed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat())
    previous_state: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type.value,
            "asset_identity": self.asset_identity,
            "domain": self.domain,
            "payload": self.payload,
            "observed_at": self.observed_at,
            "previous_state": self.previous_state,
        }


class PlatformStateEngine:
    """Per-asset state with change detection (field comparison, no AI)."""

    def __init__(self) -> None:
        self._states: dict[str, dict[str, Any]] = {}

    def state(self, asset_identity: str) -> dict[str, Any]:
        return self._states.setdefault(asset_identity, {})

    def apply(self, asset_identity: str, state: dict[str, Any]) -> bool:
        """Store state; return True when it changed vs the previous snapshot."""
        previous = self._states.get(asset_identity)
        self._states[asset_identity] = dict(state)
        return previous != state


class PlatformEventBus:
    """Routes platform events to domain handlers with targeted rescan plans."""

    def __init__(self, state_engine: Optional[PlatformStateEngine] = None,
                 handlers: Optional[dict[str, Callable[[PlatformEvent], Any]]] = None,
                 scanner_engines: Optional[dict[str, Any]] = None) -> None:
        self.state_engine = state_engine or PlatformStateEngine()
        self.handlers = handlers or {}
        #: optional domain scanner engines (crypto/hardware/… live engines)
        self.scanner_engines = scanner_engines or {}
        self.journal: list[dict[str, Any]] = []
        self.changes: list[dict[str, Any]] = []

    def register(self, domain: str, handler: Callable[[PlatformEvent], Any]) -> None:
        self.handlers[domain] = handler

    def emit(self, event: PlatformEvent) -> dict[str, Any]:
        """Apply the event: state update, change detection, targeted rescan."""
        changed = self.state_engine.apply(
            event.asset_identity,
            dict(event.payload, domain=event.domain,
                 event_type=event.event_type.value))
        event.previous_state = None
        entry = {
            "event": event.to_dict(),
            "changed": changed,
            "targeted_analysis": TARGETED_ANALYSIS.get(event.domain, []),
            "rescan_targets": [event.asset_identity],
        }
        if changed:
            # dispatch to the owning domain's live engine when available
            handler = self.handlers.get(event.domain) \
                or self.scanner_engines.get(event.domain)
            if handler:
                try:
                    entry["handler_result"] = handler(event)
                except Exception as exc:  # deterministic engines, but isolate
                    entry["handler_error"] = f"{type(exc).__name__}: {exc}"
            self.changes.append(entry)
        self.journal.append(entry)
        return entry

    def dispatch(self, event_type: PlatformEventType, asset_identity: str,
                 payload: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Convenience emit by type — domain is derived from the catalog."""
        domain = EVENT_DOMAIN[event_type]
        return self.emit(PlatformEvent(
            event_type=event_type, asset_identity=asset_identity,
            domain=domain, payload=payload or {}))

    def replay(self, at: Optional[str] = None) -> list[dict[str, Any]]:
        """Reconstruct the event stream (optionally up to a timestamp)."""
        events = list(self.journal)
        if at:
            events = [e for e in events if e["event"]["observed_at"] <= at]
        return events
