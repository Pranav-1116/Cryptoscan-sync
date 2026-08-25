"""Cloud scan request/response schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class CloudScanRequest(BaseModel):
    path: str
    live: bool = False


class CloudScanResult(BaseModel):
    findings: list[dict] = Field(default_factory=list)
    resources: int = 0
    issues: int = 0
    providers: list[str] = Field(default_factory=list)
