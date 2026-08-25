"""Named priority-score object wrapping the scorer helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from business_context.prioritization.scorer import priority_label, priority_score


@dataclass(frozen=True)
class PriorityScore:
    value: float
    label: str
    compliance_fail: bool = False
    revenue_daily: float = 0
    customer_count: int = 0
    technical_severity: str = "MEDIUM"

    @classmethod
    def compute(
        cls,
        *,
        revenue_daily: float = 0,
        customer_count: int = 0,
        compliance_fail: bool = False,
        technical_severity: str = "MEDIUM",
    ) -> "PriorityScore":
        value = priority_score(
            revenue_daily=revenue_daily,
            customer_count=customer_count,
            compliance_fail=compliance_fail,
            technical_severity=technical_severity,
        )
        return cls(
            value=value,
            label=priority_label(value, compliance_fail=compliance_fail, revenue_daily=float(revenue_daily)),
            compliance_fail=compliance_fail,
            revenue_daily=float(revenue_daily),
            customer_count=int(customer_count),
            technical_severity=technical_severity,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "priority_score": self.value,
            "priority": self.label,
            "compliance_fail": self.compliance_fail,
            "revenue_daily": self.revenue_daily,
            "customer_count": self.customer_count,
            "technical_severity": self.technical_severity,
        }
