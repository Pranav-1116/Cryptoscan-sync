"""CycloneDX metadata model."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CbomMetadata:
    timestamp: str | None = None
    component: dict[str, Any] = field(default_factory=dict)
    tools: list[dict[str, Any]] = field(default_factory=list)
    properties: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "timestamp": self.timestamp,
            "component": dict(self.component),
            "tools": list(self.tools),
        }
        if self.properties:
            payload["properties"] = list(self.properties)
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any] | None) -> "CbomMetadata":
        data = payload or {}
        return cls(
            timestamp=data.get("timestamp"),
            component=dict(data.get("component") or {}),
            tools=list(data.get("tools") or []),
            properties=list(data.get("properties") or []),
        )
