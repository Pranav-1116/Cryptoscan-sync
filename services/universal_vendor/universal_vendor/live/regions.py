"""Distributed Global Architecture (24/7 spec §22).

Control plane + regional edges (UAE, EU, USA). Regional agents continue
operating if the central control plane is temporarily unavailable — each edge
owns its local gateway/state/cbom and syncs when reachable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from universal_vendor.live.offline import LocalEventQueue, LocalEvidenceStore, SecureSync


@dataclass
class RegionalEdge:
    region: str
    control_plane_url: str = ""
    online: bool = True
    event_queue: Optional[LocalEventQueue] = None
    evidence_store: Optional[LocalEvidenceStore] = None

    def sync(self) -> dict[str, Any]:
        """Flush the local queue to the control plane when online."""
        if not self.online:
            return {"region": self.region, "synced": False, "reason": "offline"}
        if self.event_queue is None:
            return {"region": self.region, "synced": False, "reason": "no queue"}
        secure = SecureSync()
        return secure.sync(
            self.event_queue,
            self.evidence_store or LocalEvidenceStore(),
            network_available=True,
            endpoint=self.control_plane_url or "control-plane",
        )


class ControlPlane:
    def __init__(self) -> None:
        self._edges: dict[str, RegionalEdge] = {}

    def add_edge(self, region: str, *, online: bool = True,
                 control_plane_url: str = "") -> RegionalEdge:
        edge = RegionalEdge(region=region, online=online,
                            control_plane_url=control_plane_url)
        self._edges[region] = edge
        return edge

    def edge(self, region: str) -> Optional[RegionalEdge]:
        return self._edges.get(region)

    def regions(self) -> list[str]:
        return sorted(self._edges)

    def sync_all(self) -> list[dict[str, Any]]:
        return [edge.sync() for edge in self._edges.values()]

    def summary(self) -> dict[str, Any]:
        return {
            "regions": self.regions(),
            "online_edges": sum(1 for e in self._edges.values() if e.online),
            "total_edges": len(self._edges),
        }
