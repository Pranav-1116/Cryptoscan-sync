"""ZELNX Live Cloud Intelligence Engine — cloud monitoring priority engine
(§21).

Prioritization factors (policy-configurable):

    business criticality + internet exposure + cryptographic risk +
    data sensitivity + compliance importance + change frequency

Example: internet-facing banking API → HIGH; internal development test
storage → LOWER.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

PRIORITIES = ("LOWER", "LOW", "MEDIUM", "HIGH", "CRITICAL")

CRITICALITY_WEIGHTS = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "STANDARD": 0, "LOW": 0}
EXPOSURE_WEIGHTS = {"public_internet": 2, "private_network": 1, "internal": 0}
RISK_WEIGHTS = {"CRITICAL": 2, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
DATA_WEIGHTS = {"REGULATED": 2, "PII": 2, "SENSITIVE": 1, "INTERNAL": 1, "PUBLIC": 0}
COMPLIANCE_WEIGHTS = {"HIPAA": 2, "PCI_DSS": 2, "GDPR": 2, "SOC2": 1, "ISO27001": 1}
CHANGE_FREQUENCY_WEIGHTS = {"frequent": 1, "normal": 0, "rare": 0}


def priority_from_score(score: int) -> str:
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    if score >= 2:
        return "LOW"
    return "LOWER"


@dataclass
class PriorityEvaluation:
    """Priority evaluation of one monitored resource."""

    resource_id: str
    priority: str = "LOWER"
    score: int = 0
    factors: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "priority": self.priority,
            "score": self.score,
            "factors": dict(self.factors),
        }


class CloudPriorityEngine:
    """Score monitored resources by the configured factor weights."""

    def __init__(self, *, weights: dict[str, dict[str, int]] | None = None) -> None:
        self._weights = weights or {
            "criticality": CRITICALITY_WEIGHTS,
            "exposure": EXPOSURE_WEIGHTS,
            "crypto_risk": RISK_WEIGHTS,
            "data_sensitivity": DATA_WEIGHTS,
            "compliance": COMPLIANCE_WEIGHTS,
            "change_frequency": CHANGE_FREQUENCY_WEIGHTS,
        }

    def evaluate(self, *, resource_id: str,
                 criticality: str = "STANDARD",
                 exposure: str = "internal",
                 crypto_risk: str = "LOW",
                 data_sensitivity: str = "PUBLIC",
                 compliance: str | list[str] | None = None,
                 change_frequency: str = "normal") -> PriorityEvaluation:
        weights = self._weights
        compliance = [compliance] if isinstance(compliance, str) else (compliance or [])
        criticality_score = weights["criticality"].get(str(criticality).upper(), 0)
        exposure_score = weights["exposure"].get(str(exposure).lower(), 0)
        risk_score = weights["crypto_risk"].get(str(crypto_risk).upper(), 0)
        data_score = weights["data_sensitivity"].get(str(data_sensitivity).upper(), 0)
        compliance_score = sum(weights["compliance"].get(str(c).upper(), 0)
                               for c in compliance)
        change_score = weights["change_frequency"].get(str(change_frequency).lower(), 0)
        score = (criticality_score * 2 + exposure_score * 2 + risk_score * 2 +
                 data_score + compliance_score + change_score)
        priority = priority_from_score(score)
        return PriorityEvaluation(
            resource_id=resource_id,
            priority=priority,
            score=score,
            factors={
                "criticality": criticality_score,
                "exposure": exposure_score,
                "crypto_risk": risk_score,
                "data_sensitivity": data_score,
                "compliance": compliance_score,
                "change_frequency": change_score,
                "breakdown": {
                    "business_criticality": criticality,
                    "internet_exposure": exposure,
                    "cryptographic_risk": crypto_risk,
                    "data_sensitivity": data_sensitivity,
                    "compliance": list(compliance),
                    "change_frequency": change_frequency,
                },
            },
        )

    def reweight(self, factor: str, key: str, weight: int) -> None:
        """Policy-configurable weights (§21)."""
        self._weights.setdefault(factor, {})[key] = weight
