from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class BlastRadiusResult:
    start: str
    systems: list[dict[str, Any]] = field(default_factory=list)
    hops: int = 5
    nodes_visited: int = 0
    backend: str = "memory"

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": self.start,
            "systems": self.systems,
            "hops": self.hops,
            "nodes_visited": self.nodes_visited,
            "backend": self.backend,
        }
