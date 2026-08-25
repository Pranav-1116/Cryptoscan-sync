"""Certificate inventory schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class CertificateOut(BaseModel):
    fingerprint_sha256: str | None = None
    subject: str | None = None
    issuer: str | None = None
    not_after: str | None = None
    days_until_expiry: int | None = None
    expiry_status: str | None = None
    revocation_status: str | None = None


class CertificateList(BaseModel):
    certificates: list[CertificateOut] = Field(default_factory=list)
    total_count: int = 0
