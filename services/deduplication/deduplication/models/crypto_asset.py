"""In-memory crypto asset produced by the deduplication engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CryptoAsset:
    algorithm: str
    purpose: str | None = None
    file_path: str | None = None
    line_number: int = 0
    confidence: str = "LOW"
    mode: str | None = None
    key_size: int | None = None
    scanner_ids: list[str] = field(default_factory=list)
    libraries: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    occurrence_count: int = 1
    is_hardcoded_key: bool = False
    source_language: str | None = None
    dedup_key: str | None = None
    primary_evidence_id: str | None = None
    members: list[dict[str, Any]] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "algorithm": self.algorithm,
            "purpose": self.purpose,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "confidence": self.confidence,
            "mode": self.mode,
            "key_size": self.key_size,
            "scanner_ids": list(self.scanner_ids),
            "libraries": list(self.libraries),
            "evidence_ids": list(self.evidence_ids),
            "occurrence_count": self.occurrence_count,
            "is_hardcoded_key": self.is_hardcoded_key,
            "source_language": self.source_language,
            "dedup_key": self.dedup_key,
            "primary_evidence_id": self.primary_evidence_id,
            "members": list(self.members),
        }
        if self.extra:
            payload["extra"] = dict(self.extra)
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "CryptoAsset":
        known = {
            "algorithm",
            "purpose",
            "file_path",
            "line_number",
            "confidence",
            "mode",
            "key_size",
            "scanner_ids",
            "libraries",
            "evidence_ids",
            "occurrence_count",
            "is_hardcoded_key",
            "source_language",
            "dedup_key",
            "primary_evidence_id",
            "members",
        }
        extra = {key: value for key, value in payload.items() if key not in known and key != "extra"}
        extra.update(payload.get("extra") or {})
        return cls(
            algorithm=str(payload.get("algorithm") or "UNKNOWN"),
            purpose=payload.get("purpose"),
            file_path=payload.get("file_path"),
            line_number=int(payload.get("line_number") or 0),
            confidence=str(payload.get("confidence") or "LOW"),
            mode=payload.get("mode"),
            key_size=payload.get("key_size"),
            scanner_ids=list(payload.get("scanner_ids") or []),
            libraries=list(payload.get("libraries") or []),
            evidence_ids=list(payload.get("evidence_ids") or []),
            occurrence_count=int(payload.get("occurrence_count") or 1),
            is_hardcoded_key=bool(payload.get("is_hardcoded_key")),
            source_language=payload.get("source_language"),
            dedup_key=payload.get("dedup_key"),
            primary_evidence_id=payload.get("primary_evidence_id"),
            members=list(payload.get("members") or []),
            extra=extra,
        )
