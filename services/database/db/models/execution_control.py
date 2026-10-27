"""Versioned approvals, shared limits, fenced attempts and publication outbox.

History is append-only by API: approvals are revoked/superseded, never edited.
Budget rows are platform-internal coordination state, never tenant-listed.
"""
from datetime import datetime
from sqlalchemy import DateTime, Integer, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from db.models.base import BaseModel
from db.tenancy import TenantScoped


class EstateExecutionPolicy(BaseModel, TenantScoped):
    __tablename__ = "estate_execution_policies"
    estate_key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    contract: Mapped[dict] = mapped_column(JSON, nullable=False)
    stopped: Mapped[bool] = mapped_column(default=False, nullable=False)


class ScanApproval(BaseModel, TenantScoped):
    __tablename__ = "scan_approvals"
    policy_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    contract: Mapped[dict] = mapped_column(JSON, nullable=False)
    requests_used: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    approved_by: Mapped[str] = mapped_column(String(36), nullable=False)
    supersedes_id: Mapped[str | None] = mapped_column(String(36))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ExecutionBudget(BaseModel):
    # platform-scope: internal cross-estate provider and estate reservation
    # coordination. API exposes only the selected estate's policy, never these
    # shared counters. All mutations use version/CAS, not process-local locks.
    __tablename__ = "execution_budgets"
    capacity: Mapped[int] = mapped_column(Integer, nullable=False)
    requests_per_second: Mapped[int] = mapped_column(Integer, nullable=False)
    active: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    schedule: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    request_times: Mapped[list] = mapped_column(JSON, default=list, nullable=False)


class ExecutionAttempt(BaseModel, TenantScoped):
    __tablename__ = "execution_attempts"
    __table_args__ = (UniqueConstraint("job_id", name="uq_execution_attempt_job"),)
    job_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    approval_id: Mapped[str] = mapped_column(String(36), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="RUNNING", nullable=False)
    checkpoint: Mapped[str] = mapped_column(String(80), default="claimed", nullable=False)
    deadline_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    budget_ids: Mapped[list] = mapped_column(JSON, nullable=False)
    # Fencing identity is private, never included in API results or messages.
    fence: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class ExecutionOutbox(BaseModel, TenantScoped):
    __tablename__ = "execution_outbox"
    __table_args__ = (UniqueConstraint("job_id", name="uq_execution_outbox_job"),)
    job_id: Mapped[str] = mapped_column(String(36), nullable=False)
    state: Mapped[str] = mapped_column(String(20), default="PENDING", nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ExecutionControlEvent(BaseModel, TenantScoped):
    __tablename__ = "execution_control_events"
    actor_id: Mapped[str] = mapped_column(String(36), nullable=False)
    action: Mapped[str] = mapped_column(String(40), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(36), nullable=False)
    detail: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
