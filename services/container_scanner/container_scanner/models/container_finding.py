"""Container-scanner finding envelope."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ContainerFinding:
    finding_id: str | None = None
    scanner_id: str = "container-scanner-v1.0"
    scanner_version: str = "1.0.0"
    source: dict[str, Any] = field(default_factory=dict)
    crypto: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    vulnerability: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "finding_id": self.finding_id,
            "scanner_id": self.scanner_id,
            "scanner_version": self.scanner_version,
            "source": dict(self.source),
            "crypto": dict(self.crypto),
            "metadata": dict(self.metadata),
        }
        if self.vulnerability:
            payload["vulnerability"] = dict(self.vulnerability)
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ContainerFinding":
        return cls(
            finding_id=payload.get("finding_id"),
            scanner_id=str(payload.get("scanner_id") or "container-scanner-v1.0"),
            scanner_version=str(payload.get("scanner_version") or "1.0.0"),
            source=dict(payload.get("source") or {}),
            crypto=dict(payload.get("crypto") or {}),
            metadata=dict(payload.get("metadata") or {}),
            vulnerability=payload.get("vulnerability"),
        )
