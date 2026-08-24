"""Integrity proof attached to an evidence record."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field

from evidence.hashing.content_hasher import ContentHasher


class IntegrityProof(BaseModel):
    hash_algorithm: str = "SHA-256"
    content_hash: str
    chain_hash: Optional[str] = None
    previous_hash: Optional[str] = None
    chain_position: int = 0
    canonical_form: str = "sorted-json-utf8"

    def verify(self, finding: dict[str, Any]) -> bool:
        return ContentHasher.verify_hash(finding, self.content_hash)

    @classmethod
    def from_finding(
        cls,
        finding: dict[str, Any],
        *,
        chain_hash: str | None = None,
        previous_hash: str | None = None,
        chain_position: int = 0,
    ) -> "IntegrityProof":
        return cls(
            content_hash=ContentHasher.compute_hash(finding),
            chain_hash=chain_hash,
            previous_hash=previous_hash,
            chain_position=chain_position,
        )


class IntegrityMetadata(BaseModel):
    hash_algorithm: str = "SHA-256"
    canonical_form: str = "sorted-json-utf8"
    hash_includes: list[str] = Field(default_factory=lambda: ["finding"])
    hash_excludes: list[str] = Field(default_factory=lambda: ["evidence_id", "created_at"])
