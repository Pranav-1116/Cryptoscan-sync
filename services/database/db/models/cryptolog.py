"""CryptoLog event store (docs/cryptolog/01_PRODUCT_SPEC.md, Phase 2).

Canonical event records plus corrections. The database rule the schema
obeys: never overwrite an original event when a correction arrives — the
original row is immutable; corrections live in their own table with their
own provenance.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import JSON, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class CryptoLogEvent(BaseModel, TenantScoped):
    __tablename__ = "cryptolog_events"

    event_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    partition_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    deduplication_key: Mapped[Optional[str]] = mapped_column(String(200), nullable=True, index=True)

    event_type: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    logging_kind: Mapped[str] = mapped_column(String(20), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    investigation_status: Mapped[str] = mapped_column(String(40), nullable=False)
    telemetry_mode: Mapped[str] = mapped_column(String(20), nullable=False, default="EVENT")
    approval_ref: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)

    asset_id: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    business_system_id: Mapped[Optional[str]] = mapped_column(String(80), nullable=True, index=True)

    source: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    cryptographic_context: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    observation: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    relationships: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    processing: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    attributes: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    __table_args__ = (
        Index("ix_cryptolog_events_tenant_created", "tenant_id", "created_at"),
    )


class CryptoLogCorrection(BaseModel, TenantScoped):
    __tablename__ = "cryptolog_event_corrections"

    corrects_event_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    original_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    corrected_event: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    actor: Mapped[str] = mapped_column(String(120), nullable=False)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
