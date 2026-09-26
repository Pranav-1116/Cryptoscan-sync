"""Live Vendor Monitoring Modes (§1) + vendor live connectors (§4–§8).

Seven modes run simultaneously, tuned per vendor surface so the system
operates 24/7 without unnecessary load on customer infrastructure:

1. REAL_TIME_TELEMETRY         streaming telemetry, syslog, event streams
2. VENDOR_EVENT_MONITORING     vendor-generated change events
3. MANAGEMENT_API_MONITORING   NETCONF/RESTCONF/iControl/vCenter API polling
4. PASSIVE_NETWORK_OBSERVATION passive observation of vendor protocols
5. LIGHTWEIGHT_PERIODIC_POLLING cheap config-fingerprint polling
6. CHANGE_TRIGGERED_DEEP_SCANNING deep scan only when a change is detected
7. SCHEDULED_RECONCILIATION    full reconciliation on a schedule
"""

from __future__ import annotations

from dataclasses import field
from enum import Enum
from typing import Any, Optional

from universal_vendor.live.events import UniversalVendorEvent


class MonitorMode(str, Enum):
    REAL_TIME_TELEMETRY = "REAL_TIME_TELEMETRY"
    VENDOR_EVENT_MONITORING = "VENDOR_EVENT_MONITORING"
    MANAGEMENT_API_MONITORING = "MANAGEMENT_API_MONITORING"
    PASSIVE_NETWORK_OBSERVATION = "PASSIVE_NETWORK_OBSERVATION"
    LIGHTWEIGHT_PERIODIC_POLLING = "LIGHTWEIGHT_PERIODIC_POLLING"
    CHANGE_TRIGGERED_DEEP_SCANNING = "CHANGE_TRIGGERED_DEEP_SCANNING"
    SCHEDULED_RECONCILIATION = "SCHEDULED_RECONCILIATION"


class LiveConnector:
    """A live connector talks to one vendor surface through one mechanism.

    ``collect()`` returns canonical events; ``snapshot()`` returns a
    fingerprintable state snapshot (used by the config-fingerprint engine).
    Connectors are read-only and never carry credentials (see live/credentials).
    """

    vendor: str = ""
    product: str = ""
    mechanism: str = "unknown"  # syslog | netconf | restconf | snmpv3 | api | telemetry | passive
    modes: list[MonitorMode] = field(default_factory=list)

    def __init__(self, asset_id: str = "", **options: Any) -> None:
        self.asset_id = asset_id
        self.options = options

    def collect(self) -> list[UniversalVendorEvent]:
        """Pull/parse new vendor events. Returns [] when nothing new."""
        return []

    def snapshot(self) -> dict[str, Any]:
        """Current observable state — hashed for change detection."""
        return {}

    def heartbeat(self) -> dict[str, Any]:
        """Connector liveness metadata (spec §20)."""
        return {"vendor": self.vendor, "product": self.product,
                "mechanism": self.mechanism, "ok": True}


class LiveVendorMonitor:
    """Runs a set of connectors and fans their output into the gateway.

    Modes may be enabled per connector; CHANGE_TRIGGERED_DEEP_SCANNING means
    a fingerprint change raises a deep-scan request instead of deep-scanning
    on every poll.
    """

    def __init__(self) -> None:
        self._connectors: list[LiveConnector] = []

    def register(self, connector: LiveConnector) -> LiveConnector:
        self._connectors.append(connector)
        return connector

    def connectors(self) -> list[LiveConnector]:
        return list(self._connectors)

    def collect(self, mode: Optional[MonitorMode] = None) -> list[UniversalVendorEvent]:
        events: list[UniversalVendorEvent] = []
        for connector in self._connectors:
            if mode is not None and mode not in connector.modes:
                continue
            try:
                events.extend(connector.collect())
            except Exception as exc:  # one broken connector never kills the loop
                events.append(UniversalVendorEvent(
                    vendor=connector.vendor, product=connector.product,
                    asset_id=connector.asset_id or None,
                    event_type="HEALTH_CHANGED", change_type="UPDATED",
                    source=connector.mechanism,
                    vendor_metadata={"error": f"{type(exc).__name__}: {exc}"},
                ))
        return events

    def snapshots(self) -> dict[str, dict[str, Any]]:
        return {connector.asset_id: connector.snapshot()
                for connector in self._connectors}
