"""Durable security bookkeeping — the two monitors that must survive restarts.

A suspicious-access flag that erases when the process restarts is a flag
an attacker can clear by waiting for a deploy. A vault staleness watch
that forgets what the process has been running on since boot reports
fresh forever. Both were process-local lists (migration 0163 / gap C of
the durability round): these tables keep the same bookkeeping across
restarts — the in-memory window remains the fast path, these rows are
what it is rebuilt from.

Platform-security tables, not tenant estates: auth probing is keyed by
(user, source) and vault references are platform-wide, so neither carries
a tenant_id — deliberate, same as the migration.
"""

from __future__ import annotations

from sqlalchemy import Float, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel


class SecurityAuthEvent(BaseModel):
    """One failed authentication, durable across restarts.

    ``occurred_at`` is an epoch float, not a DateTime: the auth monitor's
    window math is float-epoch arithmetic, and hydrating the exact stamps
    is what makes a restarted window identical to an unbroken one.
    """

    __tablename__ = "security_auth_events"
    __table_args__ = (
        Index("ix_security_auth_events_key_time", "user_key", "source",
              "occurred_at"),
    )

    user_key: Mapped[str] = mapped_column(String(200), nullable=False)
    source: Mapped[str] = mapped_column(String(120), nullable=False)
    occurred_at: Mapped[float] = mapped_column(Float, nullable=False)


class VaultResolutionRecord(BaseModel):
    """One secret-resolution observation for the rotation-staleness watch.

    ``resolved_at`` stays the ISO string the in-memory log compares with
    ``max()`` on — hydration restores exactly what the process knew.
    """

    __tablename__ = "vault_resolution_records"
    __table_args__ = (
        Index("ix_vault_resolution_ref_kind", "reference", "kind",
              "resolved_at"),
    )

    provider: Mapped[str] = mapped_column(String(80), nullable=False)
    reference: Mapped[str] = mapped_column(String(400), nullable=False)
    outcome: Mapped[str] = mapped_column(String(40), nullable=False)
    kind: Mapped[str] = mapped_column(String(40), nullable=False,
                                      default="probe")
    resolved_at: Mapped[str] = mapped_column(String(60), nullable=False)
