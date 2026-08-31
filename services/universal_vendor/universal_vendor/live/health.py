"""Vendor Monitoring Health (24/7 spec §20).

The monitoring platform monitors itself: heartbeat, connection status,
authentication status, API latency, API errors, rate limit, event lag, last
successful discovery, last successful crypto scan, plugin health.

States: HEALTHY | DEGRADED | AUTH_FAILED | RATE_LIMITED | EVENT_DELAYED |
UNREACHABLE | FAILED | MAINTENANCE.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class HealthState(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    AUTH_FAILED = "AUTH_FAILED"
    RATE_LIMITED = "RATE_LIMITED"
    EVENT_DELAYED = "EVENT_DELAYED"
    UNREACHABLE = "UNREACHABLE"
    FAILED = "FAILED"
    MAINTENANCE = "MAINTENANCE"


@dataclass
class ConnectorHealth:
    connector_id: str
    vendor: str = ""
    product: str = ""
    state: HealthState = HealthState.HEALTHY

    last_heartbeat: Optional[str] = None
    connection_status: str = "connected"     # connected | disconnected
    authentication_status: str = "authenticated"
    api_latency_ms: Optional[int] = None
    api_errors: int = 0
    rate_limit_remaining: Optional[int] = None
    event_lag_seconds: Optional[int] = None
    last_successful_discovery: Optional[str] = None
    last_successful_crypto_scan: Optional[str] = None
    plugin_health: str = "ok"                # ok | degraded | failing
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"connector_id": self.connector_id, "vendor": self.vendor,
                "product": self.product, "state": self.state.value,
                "last_heartbeat": self.last_heartbeat,
                "connection_status": self.connection_status,
                "authentication_status": self.authentication_status,
                "api_latency_ms": self.api_latency_ms,
                "api_errors": self.api_errors,
                "rate_limit_remaining": self.rate_limit_remaining,
                "event_lag_seconds": self.event_lag_seconds,
                "last_successful_discovery": self.last_successful_discovery,
                "last_successful_crypto_scan": self.last_successful_crypto_scan,
                "plugin_health": self.plugin_health,
                "notes": list(self.notes)}


class HealthMonitor:
    """Tracks connector health and derives the state from signals."""

    def __init__(self) -> None:
        self._health: dict[str, ConnectorHealth] = {}
        self._history: list[dict[str, Any]] = []

    def register(self, connector_id: str, *, vendor: str = "",
                 product: str = "") -> ConnectorHealth:
        health = ConnectorHealth(connector_id=connector_id, vendor=vendor,
                                 product=product)
        self._health[connector_id] = health
        return health

    def heartbeat(self, connector_id: str, **signals: Any) -> ConnectorHealth:
        health = self._health.setdefault(
            connector_id, ConnectorHealth(connector_id=connector_id))
        health.last_heartbeat = datetime.now(timezone.utc).isoformat()
        health.connection_status = str(signals.get("connection_status",
                                                   health.connection_status))
        health.authentication_status = str(signals.get("authentication_status",
                                                       health.authentication_status))
        if signals.get("api_latency_ms") is not None:
            health.api_latency_ms = int(signals["api_latency_ms"])
        health.api_errors = int(signals.get("api_errors", health.api_errors))
        if signals.get("rate_limit_remaining") is not None:
            health.rate_limit_remaining = int(signals["rate_limit_remaining"])
        if signals.get("event_lag_seconds") is not None:
            health.event_lag_seconds = int(signals["event_lag_seconds"])
        if signals.get("last_successful_discovery"):
            health.last_successful_discovery = str(signals["last_successful_discovery"])
        if signals.get("last_successful_crypto_scan"):
            health.last_successful_crypto_scan = str(signals["last_successful_crypto_scan"])
        health.plugin_health = str(signals.get("plugin_health", health.plugin_health))

        previous = health.state
        health.state = self._derive(health)
        if health.state != previous:
            self._history.append({"connector_id": connector_id,
                                  "previous": previous.value,
                                  "state": health.state.value,
                                  "timestamp": datetime.now(timezone.utc).isoformat()})
        return health

    @staticmethod
    def _derive(health: ConnectorHealth) -> HealthState:
        if health.plugin_health == "maintenance":
            return HealthState.MAINTENANCE
        if health.authentication_status in ("failed", "expired", "unauthorized"):
            return HealthState.AUTH_FAILED
        if health.rate_limit_remaining is not None and health.rate_limit_remaining <= 0:
            return HealthState.RATE_LIMITED
        if health.connection_status == "unreachable":
            return HealthState.UNREACHABLE
        if health.plugin_health == "failing":
            return HealthState.FAILED
        if health.event_lag_seconds is not None and health.event_lag_seconds > 300:
            return HealthState.EVENT_DELAYED
        if (health.api_errors > 5 or health.plugin_health == "degraded"
                or health.connection_status == "degraded"):
            return HealthState.DEGRADED
        return HealthState.HEALTHY

    def state(self, connector_id: str) -> Optional[HealthState]:
        health = self._health.get(connector_id)
        return health.state if health else None

    def all(self) -> list[ConnectorHealth]:
        return list(self._health.values())

    def history(self) -> list[dict[str, Any]]:
        return list(self._history)
