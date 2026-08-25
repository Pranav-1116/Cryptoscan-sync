"""Service-level business process DTO (not an ORM table)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class BusinessProcess:
    name: str
    id: str | None = None
    description: str | None = None
    process_type: str | None = None
    revenue_daily: float = 0
    customer_count: int = 0
    sla_uptime: float | None = None
    executive_sponsor: str | None = None
    data_classifications: list[str] = field(default_factory=list)
    system_ids: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, data: dict[str, Any] | Any) -> "BusinessProcess":
        if hasattr(data, "to_dict"):
            payload = data.to_dict()
        elif isinstance(data, dict):
            payload = dict(data)
        else:
            payload = {
                "id": getattr(data, "id", None),
                "name": getattr(data, "name", ""),
                "description": getattr(data, "description", None),
                "process_type": getattr(data, "process_type", None),
                "revenue_daily": getattr(data, "revenue_daily", 0),
                "customer_count": getattr(data, "customer_count", 0),
                "sla_uptime": getattr(data, "sla_uptime", None),
                "executive_sponsor": getattr(data, "executive_sponsor", None),
                "data_classifications": getattr(data, "data_classifications", None),
                "system_ids": getattr(data, "system_ids", None),
                "extra": getattr(data, "extra", None),
            }
        return cls(
            name=str(payload.get("name") or ""),
            id=payload.get("id"),
            description=payload.get("description"),
            process_type=payload.get("process_type"),
            revenue_daily=float(payload.get("revenue_daily") or 0),
            customer_count=int(payload.get("customer_count") or 0),
            sla_uptime=payload.get("sla_uptime"),
            executive_sponsor=payload.get("executive_sponsor"),
            data_classifications=list(payload.get("data_classifications") or []),
            system_ids=list(payload.get("system_ids") or []),
            extra=dict(payload.get("extra") or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
