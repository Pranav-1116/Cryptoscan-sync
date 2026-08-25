"""JSON catalog fingerprint — not an ORM table."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class CryptoLibraryFingerprint:
    name: str
    canonical: str | None = None
    vendor: str | None = None
    algorithms: list[str] = field(default_factory=list)
    versions: list[str] = field(default_factory=list)
    sha256: str | None = None
    language: str | None = None
    deprecated: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_catalog(cls, name: str, payload: dict[str, Any] | None = None) -> "CryptoLibraryFingerprint":
        data = dict(payload or {})
        return cls(
            name=name,
            canonical=data.get("canonical") or name,
            vendor=data.get("vendor"),
            algorithms=list(data.get("algorithms") or []),
            versions=list(data.get("versions") or []),
            sha256=data.get("sha256"),
            language=data.get("language"),
            deprecated=bool(data.get("deprecated")),
            extra={key: value for key, value in data.items() if key not in {
                "canonical",
                "vendor",
                "algorithms",
                "versions",
                "sha256",
                "language",
                "deprecated",
            }},
        )
