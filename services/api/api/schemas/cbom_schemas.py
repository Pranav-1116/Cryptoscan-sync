from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class CustomCbomRequest(BaseModel):
    asset_ids: list[str] = Field(default_factory=list)
    include_vulnerabilities: bool = True
    include_evidence: bool = True
    name: str = "custom-selection"


class IngestCbomRequest(BaseModel):
    bom: dict[str, Any]
    system_name: str | None = Field(default=None, max_length=200)
    owner: str | None = Field(default=None, max_length=200)
    environment: str | None = Field(default=None, max_length=50)


class CbomRef(BaseModel):
    system_id: str | None = None
    scan_id: str | None = None
    bom: dict[str, Any] | None = None


class DiffCbomRequest(BaseModel):
    left: CbomRef
    right: CbomRef
