"""Users, sessions, and audit trail (multi-user RBAC support)."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel

VALID_ROLES = ("admin", "auditor", "viewer")


class User(BaseModel):
    __tablename__ = "users"

    username: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    display_name: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    email: Mapped[Optional[str]] = mapped_column(String(320), nullable=True)
    password_hash: Mapped[str] = mapped_column(String(500), nullable=False)
    roles: Mapped[str] = mapped_column(String(200), nullable=False, default="viewer")
    is_active: Mapped[bool] = mapped_column(default=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    mfa_secret: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    @property
    def role_list(self) -> list[str]:
        return [r.strip() for r in (self.roles or "").split(",") if r.strip()]

    def has_role(self, *allowed: str) -> bool:
        roles = set(self.role_list)
        return bool(roles & set(allowed))


class UserSession(BaseModel):
    """Server-side session records enabling token revocation and inventory."""

    __tablename__ = "user_sessions"

    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    username: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    created_at_ts: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)


class AuditLog(BaseModel):
    """Who did what, when — required for a compliance system."""

    __tablename__ = "audit_log"

    actor: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    target_type: Mapped[Optional[str]] = mapped_column(String(60), nullable=True)
    target_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    outcome: Mapped[str] = mapped_column(String(20), nullable=False, default="SUCCESS")
    # hash chain (W57-58): tampering with any row breaks every later entry_hash
    chain_sequence: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    previous_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    entry_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)


class MfaRecoveryCode(BaseModel):
    """One-time MFA recovery code — only the hash is stored."""

    __tablename__ = "mfa_recovery_codes"

    user_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    code_hash: Mapped[str] = mapped_column(String(500), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
