"""Normalized CVE row from local / OSV / NVD lookups."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CveFinding:
    cve: str
    package: str | None = None
    version: str | None = None
    severity: str = "UNKNOWN"
    summary: str | None = None
    manifest: str | None = None
    source: str = "local"
    aliases: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve": self.cve,
            "package": self.package,
            "version": self.version,
            "severity": self.severity,
            "summary": self.summary,
            "manifest": self.manifest,
            "source": self.source,
            "aliases": list(self.aliases),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "CveFinding":
        return cls(
            cve=str(payload.get("cve") or payload.get("id") or "UNKNOWN"),
            package=payload.get("package"),
            version=payload.get("version"),
            severity=str(payload.get("severity") or "UNKNOWN"),
            summary=payload.get("summary") or payload.get("description"),
            manifest=payload.get("manifest"),
            source=str(payload.get("source") or "local"),
            aliases=list(payload.get("aliases") or []),
        )
