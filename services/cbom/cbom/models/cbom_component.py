"""CycloneDX cryptographic-asset component."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CbomComponent:
    name: str
    type: str = "cryptographic-asset"
    bom_ref: str | None = None
    crypto_properties: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    properties: list[dict[str, Any]] = field(default_factory=list)
    version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "type": self.type,
            "name": self.name,
            "bom-ref": self.bom_ref,
            "cryptoProperties": dict(self.crypto_properties),
            "evidence": dict(self.evidence),
        }
        if self.properties:
            payload["properties"] = list(self.properties)
        if self.version:
            payload["version"] = self.version
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "CbomComponent":
        return cls(
            name=str(payload.get("name") or "UNKNOWN"),
            type=str(payload.get("type") or "cryptographic-asset"),
            bom_ref=payload.get("bom-ref"),
            crypto_properties=dict(payload.get("cryptoProperties") or {}),
            evidence=dict(payload.get("evidence") or {}),
            properties=list(payload.get("properties") or []),
            version=payload.get("version"),
        )
