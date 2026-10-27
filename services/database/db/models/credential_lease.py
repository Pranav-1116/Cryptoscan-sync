"""Short-lived vault-lease audit record (reference-only, never a secret).

A lease records that a scanner component was authorized to fetch a credential
from the out-of-band vault for a bounded TTL and scope. It stores only the
vault locator (secret_ref) — no key material is ever written here.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class CredentialLease(BaseModel, TenantScoped):
    __tablename__ = "credential_leases"

    handle: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    credential_name: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    secret_ref: Mapped[str] = mapped_column(Text, nullable=False)
    component: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    scope: Mapped[str | None] = mapped_column(Text, nullable=True)
    ttl_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    issued_by: Mapped[str] = mapped_column(String(100), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="ACTIVE", index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "handle": self.handle,
            "credential_name": self.credential_name,
            "secret_ref": self.secret_ref,
            "component": self.component,
            "scope": self.scope,
            "ttl_seconds": self.ttl_seconds,
            "issued_at": self.issued_at.isoformat() if self.issued_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "released_at": self.released_at.isoformat() if self.released_at else None,
            "issued_by": self.issued_by,
            "status": self.status,
        }
