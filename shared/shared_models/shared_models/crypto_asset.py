"""Shared DTO for a discovered cryptographic asset."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class CryptoAsset(BaseModel):
    model_config = {"extra": "allow"}

    id: Optional[str] = None
    algorithm: str
    purpose: Optional[str] = None
    mode: Optional[str] = None
    key_size: Optional[int] = None
    file_path: str
    line_number: int = 0
    source_language: Optional[str] = None
    confidence: str = "LOW"
    is_hardcoded_key: bool = False
    occurrence_count: int = 1
    scanner_ids: list[str] = Field(default_factory=list)
    libraries: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
