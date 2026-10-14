"""Durable API-key quota windows (§4.8, round 59).

The API-key rate quota used to live in a process-local dict
(``apikeys.policy.FixedWindowQuota``): every replica counted separately,
so a limit of N/min became N×replicas/min the moment the API ran more
than one process. This table is the shared, durable counter — one row
per (key, window), incremented by ONE atomic upsert per request, so all
replicas enforce the same window.

Rows are short-lived (a window is 60s; cleanup is opportunistic on
write). The write is a single narrow-row upsert keyed by the
(key_id, window_start) unique constraint — deliberately NOT the wide
``api_keys`` row, whose hot-path writes are throttled elsewhere.
"""

from __future__ import annotations

from sqlalchemy import Float, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class ApiKeyQuotaWindow(BaseModel, TenantScoped):
    __tablename__ = "api_key_quota_windows"
    __table_args__ = (
        UniqueConstraint("key_id", "window_start", name="uq_api_key_quota_window"),
    )

    key_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    #: epoch-aligned window start (seconds) — floor(now / 60) * 60
    window_start: Mapped[float] = mapped_column(Float, nullable=False)
    hit_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
