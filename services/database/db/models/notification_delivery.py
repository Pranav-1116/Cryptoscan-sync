"""Durable per-destination notification receipts; no exactly-once HTTP claim.

No FK/cascade: a delivered receipt must survive journal/integration retention.
The immutable minimal event envelope lets pending retries survive journal
retention too. No endpoint credentials or transport secrets are copied here.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, CheckConstraint, DateTime, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class NotificationDelivery(BaseModel, TenantScoped):
    __tablename__ = "notification_deliveries"
    __table_args__ = (
        UniqueConstraint("scope_key", "event_id", "integration_id", "channel", name="uq_notification_destination"),
        UniqueConstraint("delivery_key", name="uq_notification_delivery_key"),
        Index("ix_notification_deliveries_due", "scope_key", "status", "next_attempt_at"),
        Index("ix_notification_deliveries_inspection", "scope_key", "created_at", "id"),
        CheckConstraint("status IN ('pending','inflight','delivered','failed','skipped','legacy_unknown')",
                        name="ck_notification_delivery_status"),
    )

    # Non-null discriminator makes NULL/platform dedup portable to PostgreSQL.
    scope_key: Mapped[str] = mapped_column(String(80), nullable=False)
    event_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    integration_id: Mapped[str] = mapped_column(String(36), nullable=False)
    channel: Mapped[str] = mapped_column(String(16), nullable=False)
    event_class: Mapped[str] = mapped_column(String(80), nullable=False)
    delivery_key: Mapped[str] = mapped_column(String(64), nullable=False)
    envelope: Mapped[dict] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    lease_token: Mapped[str | None] = mapped_column(String(36))
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(String(300))
    http_status: Mapped[int | None] = mapped_column(Integer)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
