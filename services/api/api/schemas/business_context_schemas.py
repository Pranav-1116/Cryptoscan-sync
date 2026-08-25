"""Business context schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class BusinessImpact(BaseModel):
    start: str | None = None
    total_revenue_at_risk: float = 0
    total_customers_at_risk: int = 0
    affected_processes: list[str] = Field(default_factory=list)
    business_owners: list[str] = Field(default_factory=list)
    compliance_scopes: list[str] = Field(default_factory=list)
