"""One approved authority per collector plane.

Guide 116 found the same six questions answered by six different mechanisms in
eleven different planes, and five planes where the answers were only a shared
import. This table is the fix: a row per plane that states, in one place, what
the collector may touch, which approved revision of that target, in which window,
within which budget, under which permission — and who approved it.

The *shape* of each plane (its entry point, its permission, the kind of target it
accepts, the defaults) is code, in ``api.security.collector_authority``, so it is
reviewed with the routes. The *approval* is data, because it is a decision with an
owner and an expiry. A plane with no row here has not been approved by anyone, and
authority refuses it rather than falling back to a default nobody signed.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class CollectorAuthority(BaseModel, TenantScoped):
    """The approved authority for one collector plane in one estate."""

    __tablename__ = "collector_authorities"
    __table_args__ = (
        UniqueConstraint("tenant_id", "plane", name="uq_collector_authority_plane"),
    )

    plane: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    #: The route or adapter the authority is issued for, copied from the plane
    #: spec at approval time so a later spec change is visible in the diff.
    entry: Mapped[str] = mapped_column(String(200), nullable=False)
    permission: Mapped[str] = mapped_column(String(80), nullable=False)
    target_kind: Mapped[str] = mapped_column(String(40), nullable=False)

    #: Monotonic per plane. A collection names the revision it was authorized
    #: under; a row that has moved on refuses the stale name.
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    approved_by: Mapped[str] = mapped_column(String(120), nullable=False)
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(120), nullable=True)

    #: Rolling window budget. Usage resets when the window lapses.
    window_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=3600)
    window_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    max_targets: Mapped[int] = mapped_column(Integer, nullable=False, default=64)
    max_requests: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    max_runtime_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=900)
    requests_used: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    runtime_seconds_used: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    #: Optimistic concurrency for the counters: two collectors spending the same
    #: budget must not both believe they had the last unit.
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
