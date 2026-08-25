"""Attached revenue / customer / priority context for an asset."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class BusinessContext:
    total_revenue_at_risk: float = 0
    total_customers_at_risk: int = 0
    total_transaction_volume: float = 0
    min_sla_uptime: float | None = None
    affected_processes: list[str] = field(default_factory=list)
    business_owners: list[str] = field(default_factory=list)
    compliance_scopes: list[str] = field(default_factory=list)
    data_classifications: list[str] = field(default_factory=list)
    priority_score: float = 0
    priority: str = "P2"

    @classmethod
    def from_mapping(cls, data: dict[str, Any] | None) -> "BusinessContext":
        payload = dict(data or {})
        return cls(
            total_revenue_at_risk=float(payload.get("total_revenue_at_risk") or 0),
            total_customers_at_risk=int(payload.get("total_customers_at_risk") or 0),
            total_transaction_volume=float(payload.get("total_transaction_volume") or 0),
            min_sla_uptime=payload.get("min_sla_uptime"),
            affected_processes=list(payload.get("affected_processes") or []),
            business_owners=list(payload.get("business_owners") or []),
            compliance_scopes=list(payload.get("compliance_scopes") or []),
            data_classifications=list(payload.get("data_classifications") or []),
            priority_score=float(payload.get("priority_score") or 0),
            priority=str(payload.get("priority") or "P2"),
        )

    @classmethod
    def from_asset(cls, asset: dict[str, Any]) -> "BusinessContext":
        extra = asset.get("extra") if isinstance(asset.get("extra"), dict) else {}
        raw = extra.get("business_context") or asset.get("business_context") or {}
        return cls.from_mapping(raw if isinstance(raw, dict) else {})

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
