"""ZELNX Live Cloud Intelligence Engine — continuous cloud network
monitoring (§10).

Detects network changes and drives the crypto-path pipeline:

    NETWORK CHANGE → TOPOLOGY UPDATE → DEPENDENCY GRAPH UPDATE →
    CRYPTO PATH ANALYSIS → RISK RECALCULATION

Detected kinds: new public/private endpoint, load balancer change, TLS
termination change, API gateway change, VPN change, route change, security
policy change, network peering change, cross-cloud connection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cloud_scanner.enterprise.live.event_schema import CloudEvent

NETWORK_EVENT_TYPES = (
    "NEW_PUBLIC_ENDPOINT", "NEW_PRIVATE_ENDPOINT", "LOAD_BALANCER_CHANGE",
    "TLS_TERMINATION_CHANGE", "API_GATEWAY_CHANGE", "VPN_CHANGE", "ROUTE_CHANGE",
    "SECURITY_POLICY_CHANGE", "NETWORK_PEERING_CHANGE", "CROSS_CLOUD_CONNECTION",
)

NETWORK_SEVERITY = {
    "NEW_PUBLIC_ENDPOINT": "HIGH",
    "TLS_TERMINATION_CHANGE": "HIGH",
    "SECURITY_POLICY_CHANGE": "HIGH",
    "VPN_CHANGE": "MEDIUM",
    "CROSS_CLOUD_CONNECTION": "MEDIUM",
    "NEW_PRIVATE_ENDPOINT": "LOW",
    "LOAD_BALANCER_CHANGE": "LOW",
    "API_GATEWAY_CHANGE": "LOW",
    "ROUTE_CHANGE": "LOW",
    "NETWORK_PEERING_CHANGE": "LOW",
}


def is_network_event(event_type: str) -> bool:
    return str(event_type or "") in NETWORK_EVENT_TYPES


@dataclass
class NetworkChange:
    """One detected network change with crypto-path impact."""

    resource_id: str
    event_type: str = ""
    provider: str = ""
    region: str = ""
    affected_paths: list[list[str]] = field(default_factory=list)
    risk_recalculated: bool = False
    severity: str = "LOW"

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "event_type": self.event_type,
            "provider": self.provider,
            "region": self.region,
            "affected_paths": [list(path) for path in self.affected_paths],
            "risk_recalculated": self.risk_recalculated,
            "severity": self.severity,
        }


class LiveNetworkMonitor:
    """Watch network events; find affected crypto paths (injectable)."""

    def __init__(self, *, find_paths=None) -> None:
        self._find_paths = find_paths or (lambda resource_id: [])
        self._changes: list[NetworkChange] = []

    def watch(self, event: CloudEvent) -> NetworkChange | None:
        if not is_network_event(event.event_type):
            return None
        paths = [list(path) for path in (self._find_paths(event.resource_id) or [])]
        change = NetworkChange(
            resource_id=event.resource_id,
            event_type=event.event_type,
            provider=event.provider,
            region=event.region,
            affected_paths=paths,
            risk_recalculated=bool(paths),
            severity=NETWORK_SEVERITY.get(event.event_type, "LOW"),
        )
        self._changes.append(change)
        return change

    def changes(self) -> list[NetworkChange]:
        return list(self._changes)

    def summary(self) -> dict[str, Any]:
        return {
            "changes": len(self._changes),
            "by_type": {
                event_type: sum(1 for c in self._changes if c.event_type == event_type)
                for event_type in NETWORK_EVENT_TYPES
            },
        }
