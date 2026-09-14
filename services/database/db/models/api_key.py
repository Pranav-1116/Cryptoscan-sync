"""Machine API keys: non-interactive principals for CI pipelines and SIEM pulls.

Keys are shown once at creation and stored only as SHA-256 hashes. A key carries
its own role set (subset of the human VALID_ROLES) so a CI bot can be an auditor
without ever owning a browser session.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.models.user import VALID_ROLES

KEY_PREFIX = "csk_"  # raw keys look like csk_<43 urlsafe chars>


class ApiKey(BaseModel):
    __tablename__ = "api_keys"

    name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    key_prefix: Mapped[str] = mapped_column(String(16), nullable=False)  # display: csk_ab12…
    created_by: Mapped[str] = mapped_column(String(100), nullable=False, default="admin")
    roles: Mapped[str] = mapped_column(String(200), nullable=False, default="viewer")
    # Multi-tenant SaaS: a key minted inside a tenant context is bound to that
    # tenant — every request it makes is scoped to the tenant, regardless of
    # headers. NULL = platform key (single-tenant/on-prem estate).
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # --- P2 API-key platform: endpoint scoping, method allowlist, quota ---
    # Comma-separated allowed path prefixes (e.g. "/findings,/scans"). Empty
    # means "all endpoints the roles allow". Stored as text for SQLite/PG parity.
    scopes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Comma-separated allowed HTTP methods (e.g. "GET"). Empty = all methods.
    allowed_methods: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    # Requests-per-minute cap (0 = no key-level cap; global limiter still applies).
    rate_per_minute: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Lifetime usage counters (best-effort, stamped alongside last_used_at).
    request_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    denied_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Optional per-key IP allowlist (comma/space-separated IPv4/IPv6 or CIDRs,
    # e.g. "10.0.0.0/8,203.0.113.4"). Empty = no network restriction.
    allowed_ips: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Rotation bookkeeping: how many days the key may live before it should
    # be rotated (deterministic reminder; not hard-enforced).
    rotate_after_days: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    @property
    def role_list(self) -> list[str]:
        return [r for r in (self.roles or "").split(",") if r]

    @property
    def scopes_list(self) -> list[str]:
        return [s.strip() for s in (self.scopes or "").split(",") if s.strip()]

    @property
    def ip_allowlist(self) -> list[str]:
        raw = (self.allowed_ips or "").replace(";", ",").replace(" ", ",")
        return [s.strip() for s in raw.split(",") if s.strip()]

    @property
    def method_list(self) -> list[str]:
        return [m.strip().upper() for m in (self.allowed_methods or "").split(",") if m.strip()]

    @property
    def is_active_key(self) -> bool:
        from db.models.base import utcnow

        if self.revoked_at is not None:
            return False
        if self.expires_at is not None and self.expires_at <= utcnow():
            return False
        return True

    @staticmethod
    def valid_roles() -> tuple[str, ...]:
        return VALID_ROLES
