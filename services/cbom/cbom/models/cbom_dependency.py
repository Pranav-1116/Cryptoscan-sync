"""CycloneDX dependency edge."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CbomDependency:
    ref: str
    depends_on: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"ref": self.ref, "dependsOn": list(self.depends_on)}

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "CbomDependency":
        return cls(ref=str(payload.get("ref") or ""), depends_on=list(payload.get("dependsOn") or []))
