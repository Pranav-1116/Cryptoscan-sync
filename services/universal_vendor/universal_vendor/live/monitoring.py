"""Live Vendor Monitoring Modes (§1) + source orchestration.

The monitor is a source coordinator, not a fixture store. Production sources
are built by :meth:`from_configurations` from persisted connector metadata or
by :meth:`from_environment` when an edge process is configured through the
runtime environment. No method in this module manufactures a vendor event
when no source is available.
"""

from __future__ import annotations

import json
import os
from enum import Enum
from typing import Any, ClassVar, Mapping, Optional

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

    vendor: ClassVar[str] = ""
    product: ClassVar[str] = ""
    mechanism: ClassVar[str] = "unknown"  # syslog | netconf | restconf | snmpv3 | api | telemetry | passive
    modes: ClassVar[list[MonitorMode]] = []

    def __init__(self, asset_id: str = "", **options: Any) -> None:
        self.asset_id = asset_id
        self.options = options

    def collect(self) -> list[UniversalVendorEvent]:
        """Pull/parse events from a concrete configured source.

        The base connector intentionally has no empty-success implementation;
        a subclass must bind to an API, telemetry stream, or event source.
        """
        raise NotImplementedError("live connector has no configured source")

    def snapshot(self) -> dict[str, Any]:
        """Current observable state — hashed for change detection."""
        return {}

    def heartbeat(self) -> dict[str, Any]:
        """Connector liveness metadata (spec §20)."""
        return {"vendor": self.vendor, "product": self.product,
                "mechanism": self.mechanism, "ok": False,
                "status": "UNAVAILABLE",
                "error": "live connector has no configured source"}


class LiveVendorMonitor:
    """Run configured connectors and fan their output into the gateway.

    ``events=...`` fixture arguments used by older vendor monitor unit tests
    remain isolated in those test-only adapters. Production construction goes
    through configured API/event-stream sources and reports configuration
    availability explicitly instead of silently producing an empty success.
    """

    def __init__(self, *, tenant_id: str | None = None,
                 configuration_errors: list[str] | None = None) -> None:
        self.tenant_id = tenant_id
        self._connectors: list[LiveConnector] = []
        self._configuration_errors = list(configuration_errors or [])

    @classmethod
    def from_environment(cls, *, tenant_id: str | None = None) -> "LiveVendorMonitor":
        """Build edge sources from operator configuration.

        ``CRYPTOSCAN_LIVE_VENDOR_ENDPOINTS`` is a JSON array of non-secret
        connector records.  For a single source the equivalent variables are
        ``CRYPTOSCAN_LIVE_VENDOR_ENDPOINT``, ``..._VENDOR``, ``..._PRODUCT``,
        and ``..._ASSET_ID``.  Missing configuration is an explicit unavailable
        status, never an invented connector or observation.
        """
        monitor = cls(tenant_id=tenant_id)
        raw = os.environ.get("CRYPTOSCAN_LIVE_VENDOR_ENDPOINTS", "").strip()
        records: list[Mapping[str, Any]] = []
        if raw:
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError as exc:
                monitor._configuration_errors.append(f"invalid CRYPTOSCAN_LIVE_VENDOR_ENDPOINTS: {exc.msg}")
                return monitor
            if not isinstance(parsed, list):
                monitor._configuration_errors.append("CRYPTOSCAN_LIVE_VENDOR_ENDPOINTS must be a JSON array")
                return monitor
            records = [item for item in parsed if isinstance(item, Mapping)]
            if len(records) != len(parsed):
                monitor._configuration_errors.append("one or more live vendor source records are not objects")
        elif os.environ.get("CRYPTOSCAN_LIVE_VENDOR_ENDPOINT"):
            records = [{
                "endpoint": os.environ.get("CRYPTOSCAN_LIVE_VENDOR_ENDPOINT"),
                "vendor": os.environ.get("CRYPTOSCAN_LIVE_VENDOR_VENDOR", ""),
                "product": os.environ.get("CRYPTOSCAN_LIVE_VENDOR_PRODUCT", ""),
                "asset_id": os.environ.get("CRYPTOSCAN_LIVE_VENDOR_ASSET_ID", ""),
                "auth_env": os.environ.get("CRYPTOSCAN_LIVE_VENDOR_AUTH_ENV", ""),
            }]
        else:
            monitor._configuration_errors.append("no live vendor source is configured")
        monitor._register_configurations(records, tenant_id=tenant_id)
        return monitor

    @classmethod
    def from_configurations(
        cls,
        configurations: list[Mapping[str, Any]],
        *,
        tenant_id: str | None = None,
        credential_resolvers: Mapping[str, Any] | None = None,
    ) -> "LiveVendorMonitor":
        """Build sources from tenant-scoped persisted connector metadata.

        ``credential_resolvers`` maps an operator-supplied non-secret auth
        reference to a callable returning a short-lived token.  The token is
        used only to make the source request and is never copied to events.
        """
        monitor = cls(tenant_id=tenant_id)
        monitor._register_configurations(
            configurations, tenant_id=tenant_id,
            credential_resolvers=credential_resolvers,
        )
        if not configurations:
            monitor._configuration_errors.append("tenant has no configured live vendor source")
        return monitor

    def _register_configurations(
        self,
        configurations: list[Mapping[str, Any]],
        *,
        tenant_id: str | None = None,
        credential_resolvers: Mapping[str, Any] | None = None,
    ) -> None:
        from universal_vendor.live.connectors import build_connector

        for index, config in enumerate(configurations):
            # DB connector rows have a config object plus identity/method
            # columns; environment records are already flat.
            row = dict(config)
            nested = row.get("config")
            if isinstance(nested, Mapping):
                merged = dict(nested)
                for key in ("vendor", "product", "asset_id", "asset", "method", "name", "status", "authorized", "auth_ref", "auth_status", "auth_updated_at"):
                    if row.get(key) is not None and (key not in merged or merged.get(key) is None):
                        merged[key] = row[key]
                row = merged
            if "authorized" in row and row.get("authorized") is not True:
                self._configuration_errors.append(
                    f"source {index} is outside the tenant's authorized scope"
                )
                continue
            status = str(row.get("status") or "configured").lower()
            if status not in {"configured", "connected", "active", "pending"}:
                self._configuration_errors.append(
                    f"source {index} is not usable because connector status is {status!r}"
                )
                continue
            if not (row.get("endpoint") or row.get("api_endpoint") or row.get("event_file")
                    or row.get("syslog_path") or row.get("telemetry_file")
                    or row.get("listen_port") or row.get("syslog_port")
                    or row.get("telemetry_port")):
                self._configuration_errors.append(f"source {index} has no endpoint or event stream path")
                continue
            auth_ref = str(row.get("auth_ref") or row.get("vault_ref") or "").strip()
            resolver = (credential_resolvers or {}).get(auth_ref) if auth_ref else None
            if auth_ref and not callable(resolver):
                self._configuration_errors.append(
                    f"source {index} auth reference {auth_ref!r} has no active credential resolver"
                )
                continue
            try:
                connector = build_connector(
                    row, credential_resolver=resolver,
                    tenant_id=tenant_id,
                )
            except (OSError, TypeError, ValueError, KeyError) as exc:
                self._configuration_errors.append(f"source {index} is invalid: {type(exc).__name__}: {exc}")
                continue
            self.register(connector)

    def register(self, connector: LiveConnector) -> LiveConnector:
        self._connectors.append(connector)
        return connector

    def connectors(self) -> list[LiveConnector]:
        return list(self._connectors)

    def configuration_errors(self) -> list[str]:
        return list(self._configuration_errors)

    def add_configuration_error(self, message: str) -> None:
        self._configuration_errors.append(str(message))

    def status(self) -> dict[str, Any]:
        if self._connectors:
            return {
                "status": "CONFIGURED",
                "configured_sources": len(self._connectors),
                "configuration_errors": self.configuration_errors(),
            }
        return {
            "status": "UNAVAILABLE",
            "configured_sources": 0,
            "configuration_errors": self.configuration_errors() or ["no live vendor source is configured"],
        }

    def collect(self, mode: Optional[MonitorMode] = None) -> list[UniversalVendorEvent]:
        events: list[UniversalVendorEvent] = []
        for connector in self._connectors:
            if mode is not None and mode not in connector.modes:
                continue
            try:
                collected = connector.collect()
                for event in collected:
                    if self.tenant_id is not None and event.tenant_id is None:
                        event = event.model_copy(update={"tenant_id": self.tenant_id})
                    elif (self.tenant_id is not None and event.tenant_id != self.tenant_id):
                        raise PermissionError("connector emitted an event for another tenant")
                    events.append(event)
            except Exception as exc:  # one broken connector never kills the loop
                events.append(UniversalVendorEvent(
                    vendor=connector.vendor, product=connector.product,
                    asset_id=connector.asset_id or None,
                    event_type="HEALTH_CHANGED", change_type="UPDATED",
                    source=connector.mechanism,
                    tenant_id=self.tenant_id,
                    vendor_metadata={"availability": "UNAVAILABLE",
                                     "error": f"{type(exc).__name__}: {exc}"},
                ))
        return events

    def snapshots(self) -> dict[str, dict[str, Any]]:
        return {connector.asset_id: connector.snapshot()
                for connector in self._connectors}

    def heartbeats(self) -> list[dict[str, Any]]:
        return [connector.heartbeat() for connector in self._connectors]
