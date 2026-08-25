from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class AssetResponse(BaseModel):
    id: str
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
    scanner_ids: Optional[list] = None
    libraries: Optional[list] = None
    evidence_ids: list[str] = Field(default_factory=list)


class AssetListResponse(BaseModel):
    assets: list[AssetResponse]
    total_count: int
    page: int
    page_size: int
