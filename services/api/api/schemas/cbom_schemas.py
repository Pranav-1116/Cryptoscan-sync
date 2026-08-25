from __future__ import annotations

from pydantic import BaseModel, Field


class CustomCbomRequest(BaseModel):
    asset_ids: list[str] = Field(default_factory=list)
    include_vulnerabilities: bool = True
    include_evidence: bool = True
    name: str = "custom-selection"
