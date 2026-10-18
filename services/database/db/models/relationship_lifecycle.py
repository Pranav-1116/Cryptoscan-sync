"""Source-owned lifecycle metadata and append-only application audit receipts."""
from __future__ import annotations
from sqlalchemy import CheckConstraint, DateTime, Integer, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from db.models.base import BaseModel
from db.tenancy import TenantScoped


class RelationshipLifecycle:
    lifecycle_state: Mapped[str] = mapped_column(String(20), nullable=False, default="ACTIVE", server_default="ACTIVE")
    lifecycle_source: Mapped[str] = mapped_column(String(120), nullable=False, default="manual", server_default="manual", index=True)
    lifecycle_revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    valid_until: Mapped[object | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_confirmed_at: Mapped[object | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lifecycle_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    lifecycle_evidence_ref: Mapped[str | None] = mapped_column(String(500), nullable=True)
    last_reconciliation_id: Mapped[str | None] = mapped_column(String(36), nullable=True)


class RelationshipSource(BaseModel, TenantScoped):
    __tablename__ = "relationship_sources"
    __table_args__ = (UniqueConstraint("scope_key", "record_kind", "source_id", name="uq_relationship_source"),
                      CheckConstraint("scope_key = CASE WHEN tenant_id IS NULL THEN 'platform' ELSE 'tenant:' || tenant_id END", name="ck_relationship_source_scope"))
    scope_key: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    record_kind: Mapped[str] = mapped_column(String(30), nullable=False)
    source_id: Mapped[str] = mapped_column(String(120), nullable=False)
    last_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class RelationshipCollection(BaseModel, TenantScoped):
    __tablename__ = "relationship_collections"
    __table_args__ = (
        UniqueConstraint("scope_key", "record_kind", "source_id", "collection_key", name="uq_relationship_collection_key"),
        UniqueConstraint("scope_key", "record_kind", "source_id", "sequence", name="uq_relationship_collection_sequence"),
        CheckConstraint("scope_key = CASE WHEN tenant_id IS NULL THEN 'platform' ELSE 'tenant:' || tenant_id END", name="ck_relationship_collection_scope"),
    )
    scope_key: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    record_kind: Mapped[str] = mapped_column(String(30), nullable=False)
    source_id: Mapped[str] = mapped_column(String(120), nullable=False)
    collection_key: Mapped[str] = mapped_column(String(120), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    outcome: Mapped[str] = mapped_column(String(20), nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    result: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_by: Mapped[str] = mapped_column(String(100), nullable=False)


class RelationshipLifecycleEvent(BaseModel, TenantScoped):
    __tablename__ = "relationship_lifecycle_events"
    __table_args__ = (CheckConstraint("scope_key = CASE WHEN tenant_id IS NULL THEN 'platform' ELSE 'tenant:' || tenant_id END", name="ck_relationship_event_scope"),)
    scope_key: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    record_kind: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    record_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    collection_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    identity: Mapped[dict] = mapped_column(JSON, nullable=False)
    before: Mapped[dict] = mapped_column(JSON, nullable=False)
    after: Mapped[dict] = mapped_column(JSON, nullable=False)
    reason: Mapped[str] = mapped_column(String(500), nullable=False)
    evidence_ref: Mapped[str] = mapped_column(String(500), nullable=False)
    created_by: Mapped[str] = mapped_column(String(100), nullable=False)
