"""Network scan request/response schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class HostScanRequest(BaseModel):
    hosts: list[str] = Field(default_factory=list)
    live: bool = True
    timeout: float = 5.0


class NetworkScanResult(BaseModel):
    findings: list[dict] = Field(default_factory=list)
    certificates: list[dict] = Field(default_factory=list)
    scanned: int = 0
