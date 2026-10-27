"""Live Network Topology Monitoring.

The topology is dynamic.  Detect:

    NEW_CONNECTION · REMOVED_CONNECTION · ROUTE_CHANGED · VPN_CREATED ·
    VPN_REMOVED · LOAD_BALANCER_CHANGED · NETWORK_SEGMENT_CHANGED ·
    FIREWALL_PATH_CHANGED

and keep the live network graph → dependency graph → crypto dependency
graph chain current.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

TOPOLOGY_CHANGE_KINDS = (
    "NEW_CONNECTION", "REMOVED_CONNECTION", "ROUTE_CHANGED", "VPN_CREATED",
    "VPN_REMOVED", "LOAD_BALANCER_CHANGED", "NETWORK_SEGMENT_CHANGED",
    "FIREWALL_PATH_CHANGED",
)

# relationship → change kind for new/removed edges
_ADDED_KIND: dict[str, str] = {
    "CONNECTED_TO": "NEW_CONNECTION",
    "ROUTES_TO": "ROUTE_CHANGED",
    "USES_VPN": "VPN_CREATED",
    "USES_IPSEC": "VPN_CREATED",
    "PROTECTS": "FIREWALL_PATH_CHANGED",
}
_REMOVED_KIND: dict[str, str] = {
    "CONNECTED_TO": "REMOVED_CONNECTION",
    "ROUTES_TO": "ROUTE_CHANGED",
    "USES_VPN": "VPN_REMOVED",
    "USES_IPSEC": "VPN_REMOVED",
    "PROTECTS": "FIREWALL_PATH_CHANGED",
}


@dataclass
class TopologyChange:
    kind: str
    source: str
    target: str
    relationship: str = ""
    segment: str = ""
    observed_at: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "source": self.source, "target": self.target,
                "relationship": self.relationship, "segment": self.segment,
                "observed_at": self.observed_at}


def _edge_key(source: str, target: str, relationship: str) -> tuple[str, str, str]:
    return (str(source), str(target), str(relationship))


class TopologyMonitor:
    """Diffs successive topology snapshots into typed change events.

    The first observation establishes the baseline (returns no changes);
    every later observation is diffed against it.
    """

    def __init__(self, *,
                 baseline: dict[str, Any] | None = None,
                 clock: Callable[[], Any] | None = None,
                 lb_keywords: tuple[str, ...] = ("lb", "loadbalancer", "load-balancer")) -> None:
        self._last: set[tuple[str, str, str]] = set()
        self._changes: list[TopologyChange] = []
        self._baseline_established = False
        self._lb_keywords = lb_keywords
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        if baseline is not None:
            self.observe(baseline)

    def changes(self) -> list[TopologyChange]:
        return list(self._changes)

    # ------------------------------------------------------------- ingest

    def observe(self, snapshot: dict[str, Any], *,
                now: Any | None = None) -> list[TopologyChange]:
        """Feed a graph snapshot dict (``{"edges": [...]}`` or a NetworkGraph
        ``to_dict()``) and get the topology changes vs the previous view."""
        edges = snapshot.get("edges", []) if isinstance(snapshot, dict) else []
        current: set[tuple[str, str, str]] = set()
        for edge in edges:
            source = str(edge.get("source") or edge.get("from") or "")
            target = str(edge.get("target") or edge.get("to") or "")
            relationship = str(edge.get("relationship") or "CONNECTED_TO")
            if source and target:
                current.add(_edge_key(source, target, relationship))

        if not self._baseline_established:
            self._baseline_established = True
            self._last = current
            return []

        now = now if now is not None else self._clock()
        changes: list[TopologyChange] = []
        segments = {self._segment_of(s) for s, _, _ in current}
        prev_segments = {self._segment_of(s) for s, _, _ in self._last}

        for source, target, relationship in sorted(current - self._last):
            kind = _ADDED_KIND.get(relationship, "NEW_CONNECTION")
            changes.append(TopologyChange(
                kind=kind, source=source, target=target,
                relationship=relationship, observed_at=now))
            if self._is_lb(source) or self._is_lb(target):
                changes.append(TopologyChange(
                    kind="LOAD_BALANCER_CHANGED", source=source, target=target,
                    relationship=relationship, observed_at=now))
        for source, target, relationship in sorted(self._last - current):
            kind = _REMOVED_KIND.get(relationship, "REMOVED_CONNECTION")
            changes.append(TopologyChange(
                kind=kind, source=source, target=target,
                relationship=relationship, observed_at=now))
            if self._is_lb(source) or self._is_lb(target):
                changes.append(TopologyChange(
                    kind="LOAD_BALANCER_CHANGED", source=source, target=target,
                    relationship=relationship, observed_at=now))
        for segment in segments ^ prev_segments:
            changes.append(TopologyChange(
                kind="NETWORK_SEGMENT_CHANGED", source=segment, target="",
                segment=segment, observed_at=now))

        self._last = current
        self._changes.extend(changes)
        return changes

    def reset(self, snapshot: dict[str, Any] | None = None) -> None:
        self._last = set()
        self._changes = []
        self._baseline_established = False
        if snapshot is not None:
            self.observe(snapshot)

    # ------------------------------------------------------------- helpers

    @staticmethod
    def _segment_of(node: str) -> str:
        parts = str(node).split(".")
        return ".".join(parts[:2]) if len(parts) >= 2 else str(node)

    def _is_lb(self, node: str) -> bool:
        lowered = str(node).lower()
        return any(k in lowered for k in self._lb_keywords)
