from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class SystemCreateRequest(BaseModel):
    name: str
    description: Optional[str] = None
    owner: Optional[str] = None
    environment: Optional[str] = None
    compliance_scopes: list[str] = Field(default_factory=list)


class SystemResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    owner: Optional[str] = None
    environment: Optional[str] = None
    compliance_scopes: Optional[list[str]] = None


class SystemListResponse(BaseModel):
    systems: list[SystemResponse]
    total_count: int
    page: int
    page_size: int


class AttachAssetRequest(BaseModel):
    asset_id: str


class DependencyCreateRequest(BaseModel):
    child_id: str
    relation: Optional[str] = "depends-on"
