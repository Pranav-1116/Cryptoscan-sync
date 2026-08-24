"""Shared evidence DTO."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class EvidenceRecordDTO(BaseModel):
    evidence_id: str
    scan_id: str
    content_hash: str
    chain_hash: Optional[str] = None
    chain_position: int = 0
    previous_hash: Optional[str] = None
    finding: dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[str] = None
