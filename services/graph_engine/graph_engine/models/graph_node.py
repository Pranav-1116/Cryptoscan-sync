from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class GraphNode:
    id: str
    kind: str
    properties: dict[str, Any] = field(default_factory=dict)

    def vis(self) -> dict[str, Any]:
        label = self.properties.get("name") or self.properties.get("algorithm") or self.id
        return {"id": self.id, "label": label, "group": self.kind, "kind": self.kind, **self.properties}
