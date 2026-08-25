"""Service-level business owner DTO (not an ORM table)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class BusinessOwner:
    name: str
    id: str | None = None
    email: str | None = None
    role: str | None = None
    department: str | None = None
    escalation_contact: str | None = None
    system_ids: list[str] = field(default_factory=list)

    @classmethod
    def from_mapping(cls, data: dict[str, Any] | Any) -> "BusinessOwner":
        if hasattr(data, "to_dict"):
            payload = data.to_dict()
        elif isinstance(data, dict):
            payload = dict(data)
        else:
            payload = {
                "id": getattr(data, "id", None),
                "name": getattr(data, "name", ""),
                "email": getattr(data, "email", None),
                "role": getattr(data, "role", None),
                "department": getattr(data, "department", None),
                "escalation_contact": getattr(data, "escalation_contact", None),
                "system_ids": getattr(data, "system_ids", None),
            }
        return cls(
            name=str(payload.get("name") or ""),
            id=payload.get("id"),
            email=payload.get("email"),
            role=payload.get("role"),
            department=payload.get("department"),
            escalation_contact=payload.get("escalation_contact"),
            system_ids=list(payload.get("system_ids") or []),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
