from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class BusinessImpactResult:
    start: str
    total_revenue_at_risk: float = 0.0
    total_customers_at_risk: int = 0
    affected_processes: list[str] = field(default_factory=list)
    business_owners: list[str] = field(default_factory=list)
    compliance_scopes: list[str] = field(default_factory=list)
    systems: list[dict[str, Any]] = field(default_factory=list)
    backend: str = "memory"

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": self.start,
            "total_revenue_at_risk": self.total_revenue_at_risk,
            "total_customers_at_risk": self.total_customers_at_risk,
            "affected_processes": self.affected_processes,
            "business_owners": self.business_owners,
            "compliance_scopes": self.compliance_scopes,
            "systems": self.systems,
            "backend": self.backend,
        }
