"""ZELNX Live Cloud Intelligence Engine — live event-sourced CBOM (§18).

The live CBOM is a materialized projection of the event log:

    CLOUD EVENT → EVENT LOG → STATE TRANSITION → CBOM MATERIALIZER →
    LIVE CLOUD CBOM

Event kinds: RESOURCE_DISCOVERED / RESOURCE_CHANGED / RESOURCE_REMOVED /
KEY_CHANGED / CERTIFICATE_CHANGED / TLS_CHANGED / NETWORK_CHANGED /
DEPENDENCY_CHANGED.

Because every CBOM component carries the events that created it, any
historical CBOM can be reconstructed — ``SHOW CLOUD CBOM AT
2026-05-01 10:00``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cloud_scanner.enterprise.live.event_schema import CloudEvent

CBOM_EVENT_TYPES = (
    "RESOURCE_DISCOVERED", "RESOURCE_CHANGED", "RESOURCE_REMOVED",
    "KEY_CHANGED", "CERTIFICATE_CHANGED", "TLS_CHANGED", "NETWORK_CHANGED",
    "DEPENDENCY_CHANGED",
)

COMPONENT_KINDS = ("crypto_asset", "certificate", "tls_endpoint",
                   "dependency", "key", "network_asset")


def cbom_kind_for_event(event_type: str) -> str:
    if event_type in ("KEY_CHANGED", "KEY_CREATED", "KEY_ROTATED"):
        return "key"
    if event_type in ("CERTIFICATE_CHANGED", "CERTIFICATE_CREATED",
                      "CERTIFICATE_RENEWED", "CERTIFICATE_REPLACED"):
        return "certificate"
    if event_type in ("TLS_CHANGED", "TLS_TERMINATION_CHANGE"):
        return "tls_endpoint"
    if event_type in ("NETWORK_CHANGED", "NETWORK_PEERING_CHANGE",
                      "ROUTE_CHANGE", "VPN_CHANGE", "NEW_PUBLIC_ENDPOINT"):
        return "network_asset"
    if event_type == "DEPENDENCY_CHANGED":
        return "dependency"
    return "crypto_asset"


@dataclass
class CBOMComponent:
    """One component in the live cloud CBOM, annotated with event history."""

    component_id: str
    kind: str
    provider: str = ""
    account_id: str = ""
    region: str = ""
    name: str = ""
    version: str = ""
    state: str = "ACTIVE"  # ACTIVE | CHANGED | REMOVED
    crypto_properties: dict[str, Any] = field(default_factory=dict)
    events: list[str] = field(default_factory=list)  # event_ids that touched it
    first_seen: str = ""
    last_seen: str = ""
    last_change_event: str = ""
    last_change_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "component_id": self.component_id,
            "kind": self.kind,
            "provider": self.provider,
            "account_id": self.account_id,
            "region": self.region,
            "name": self.name,
            "version": self.version,
            "state": self.state,
            "crypto_properties": dict(self.crypto_properties),
            "events": list(self.events),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "last_change_event": self.last_change_event,
            "last_change_at": self.last_change_at,
        }


@dataclass
class LiveCloudCBOM:
    """Materialized CBOM snapshot, reconstructible at any time."""

    materialized_at: str = ""
    components: list[CBOMComponent] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "materialized_at": self.materialized_at,
            "components": [component.to_dict() for component in self.components],
            "counts": self.counts(),
        }

    def counts(self) -> dict[str, int]:
        return {
            "components": len(self.components),
            "active": sum(1 for c in self.components if c.state == "ACTIVE"),
            "removed": sum(1 for c in self.components if c.state == "REMOVED"),
            "by_kind": {
                kind: sum(1 for c in self.components if c.kind == kind)
                for kind in COMPONENT_KINDS
            },
            "by_provider": {
                provider: sum(1 for c in self.components if c.provider == provider)
                for provider in ("aws", "azure", "gcp")
            },
        }


class LiveEventSourcedCBOM:
    """Event-sourced live cloud CBOM with historical reconstruction."""

    def __init__(self) -> None:
        self._log: list[CloudEvent] = []
        self._components: dict[str, CBOMComponent] = {}
        self._materialized: LiveCloudCBOM = LiveCloudCBOM()

    # ------------------------------------------------------------------ ingest

    def ingest(self, event: CloudEvent, *, version: str = "",
               crypto_properties: dict[str, Any] | None = None,
               timestamp: str = "") -> CBOMComponent | None:
        """Apply one CBOM-relevant event to the projection."""
        if not event.resource_id:
            return None
        self._log.append(event)
        stamp = timestamp or event.timestamp
        component_id = event.resource_id
        kind = cbom_kind_for_event(event.event_type)
        existing = self._components.get(component_id)
        if event.event_type == "RESOURCE_REMOVED" or \
                (event.change_type == "DELETED_RESOURCE" and existing is not None):
            existing.state = "REMOVED"
            existing.last_change_event = event.event_id
            existing.last_change_at = stamp
            existing.last_seen = stamp
            existing.events.append(event.event_id)
            return existing
        if existing is None:
            component = CBOMComponent(
                component_id=component_id,
                kind=kind,
                provider=event.provider,
                account_id=event.account_id,
                region=event.region,
                name=str(event.provider_metadata.get("name") or event.resource_id),
                version=version,
                crypto_properties=dict(crypto_properties or {}),
                events=[event.event_id],
                first_seen=stamp,
                last_seen=stamp,
                last_change_event=event.event_id,
                last_change_at=stamp,
            )
            self._components[component_id] = component
            return component
        existing.version = version or existing.version
        existing.crypto_properties = dict(crypto_properties or existing.crypto_properties)
        existing.state = "ACTIVE" if existing.state == "REMOVED" else "CHANGED"
        existing.last_seen = stamp
        existing.last_change_event = event.event_id
        existing.last_change_at = stamp
        existing.events.append(event.event_id)
        return existing

    # ---------------------------------------------------------------- materialize

    def materialize(self, *, at: str = "") -> LiveCloudCBOM:
        self._materialized = LiveCloudCBOM(
            materialized_at=at or "",
            components=[component for component in self._components.values()
                        if component.state != "REMOVED"],
        )
        return self._materialized

    # ------------------------------------------------------------- reconstruction

    def reconstruct(self, *, at: str) -> LiveCloudCBOM:
        """``SHOW CLOUD CBOM AT <timestamp>`` — rebuild from the event log.

        Only events at-or-before ``at`` are replayed; the resulting state
        reflects exactly what the CBOM looked like at that instant.
        """
        replay: dict[str, CBOMComponent] = {}
        for event in self._log:
            if event.timestamp and at and event.timestamp > at:
                continue
            if not event.resource_id:
                continue
            component_id = event.resource_id
            kind = cbom_kind_for_event(event.event_type)
            if event.event_type == "RESOURCE_REMOVED" or \
                    (event.change_type == "DELETED_RESOURCE" and component_id in replay):
                replay.pop(component_id, None)
                continue
            if component_id not in replay:
                replay[component_id] = CBOMComponent(
                    component_id=component_id,
                    kind=kind,
                    provider=event.provider,
                    account_id=event.account_id,
                    region=event.region,
                    name=str(event.provider_metadata.get("name") or component_id),
                    events=[event.event_id],
                    first_seen=event.timestamp,
                    last_seen=event.timestamp,
                    last_change_event=event.event_id,
                    last_change_at=event.timestamp,
                    crypto_properties=dict(event.provider_metadata.get("crypto_properties") or {}),
                )
            else:
                replay[component_id].last_seen = event.timestamp
                replay[component_id].last_change_event = event.event_id
                replay[component_id].last_change_at = event.timestamp
                replay[component_id].events.append(event.event_id)
        return LiveCloudCBOM(
            materialized_at=at,
            components=list(replay.values()),
        )

    # ------------------------------------------------------------------- access

    def events(self) -> list[CloudEvent]:
        return list(self._log)

    def event_count(self) -> int:
        return len(self._log)

    def components(self) -> list[CBOMComponent]:
        return list(self._components.values())

    def summary(self) -> dict[str, Any]:
        return {
            "events": len(self._log),
            "components": len(self._components),
            "active": sum(1 for c in self._components.values() if c.state == "ACTIVE"),
            "changed": sum(1 for c in self._components.values() if c.state == "CHANGED"),
            "removed": sum(1 for c in self._components.values() if c.state == "REMOVED"),
        }
