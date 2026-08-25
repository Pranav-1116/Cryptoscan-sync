from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class GraphRelationship:
    src: str
    dst: str
    relation: str
    properties: dict[str, Any] = field(default_factory=dict)

    def vis(self) -> dict[str, Any]:
        return {"from": self.src, "to": self.dst, "label": self.relation, **self.properties}
