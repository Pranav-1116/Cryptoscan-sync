"""Distributed hardware architecture (§24).

Control plane + regional edges (Region A/B/C). Edge collectors continue
collecting during temporary central-platform outages:

    Hardware Event → Local Durable Queue → Local Evidence → Central Sync
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from universal_vendor.live.offline import (
    LocalEventQueue,
    LocalEvidenceStore,
    SecureSync,
)


@dataclass
class HardwareEdge:
    region: str
    online: bool = True
    control_plane_url: str = ""
    event_queue: Optional[LocalEventQueue] = None
    evidence_store: Optional[LocalEvidenceStore] = None

    def sync(self) -> dict[str, Any]:
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


class HardwareControlPlane:
    def __init__(self) -> None:
        self._edges: dict[str, HardwareEdge] = {}

    def add_edge(self, region: str, *, online: bool = True,
                 control_plane_url: str = "") -> HardwareEdge:
        edge = HardwareEdge(region=region, online=online,
                            control_plane_url=control_plane_url)
        self._edges[region] = edge
        return edge

    def edge(self, region: str) -> Optional[HardwareEdge]:
        return self._edges.get(region)

    def regions(self) -> list[str]:
        return sorted(self._edges)

    def sync_all(self) -> list[dict[str, Any]]:
        return [edge.sync() for edge in self._edges.values()]

    def summary(self) -> dict[str, Any]:
        return {"regions": self.regions(),
                "online_edges": sum(1 for e in self._edges.values() if e.online),
                "total_edges": len(self._edges)}
