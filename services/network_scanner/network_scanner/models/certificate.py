"""Certificate dataclass."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Certificate:
    fingerprint_sha256: str | None = None
    subject: str | None = None
    issuer: str | None = None
    not_after: str | None = None
    days_until_expiry: int | None = None
    expiry_status: str | None = None
    san: list[str] = field(default_factory=list)
    endpoint: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Certificate":
        return cls(
            fingerprint_sha256=data.get("fingerprint_sha256"),
            subject=data.get("subject"),
            issuer=data.get("issuer"),
            not_after=data.get("not_after"),
            days_until_expiry=data.get("days_until_expiry"),
            expiry_status=data.get("expiry_status"),
            san=list(data.get("san") or []),
            endpoint=data.get("endpoint"),
        )
