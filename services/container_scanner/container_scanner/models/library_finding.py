"""Library fingerprint finding."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class LibraryFinding:
    name: str
    version: str | None = None
    manager: str | None = None
    vendor: str | None = None
    algorithms: list[str] = field(default_factory=list)
    manifest: str | None = None
    deprecated: bool = False
    language: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "manager": self.manager,
            "vendor": self.vendor,
            "algorithms": list(self.algorithms),
            "manifest": self.manifest,
            "deprecated": self.deprecated,
            "language": self.language,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "LibraryFinding":
        return cls(
            name=str(payload.get("name") or "unknown"),
            version=payload.get("version"),
            manager=payload.get("manager"),
            vendor=payload.get("vendor"),
            algorithms=list(payload.get("algorithms") or []),
            manifest=payload.get("manifest"),
            deprecated=bool(payload.get("deprecated")),
            language=payload.get("language"),
        )
