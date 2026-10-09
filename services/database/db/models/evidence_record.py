"""Evidence record ORM model."""

from __future__ import annotations

from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class EvidenceRecord(BaseModel, TenantScoped):
    __tablename__ = "evidence_records"
    __table_args__ = (
        Index("ix_evidence_scan_chain", "scan_id", "chain_position"),
        Index("ix_evidence_scan_status", "scan_id", "compliance_status"),
    )

    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    chain_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    chain_position: Mapped[int] = mapped_column(Integer, nullable=False)
    previous_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    algorithm: Mapped[str] = mapped_column(String(80), nullable=False, default="UNKNOWN", index=True)
    key_size: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    mode: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    padding: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    purpose: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    confidence: Mapped[str] = mapped_column(String(20), nullable=False, default="LOW")
    is_hardcoded_key: Mapped[bool] = mapped_column(Boolean, default=False)

    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    line_number: Mapped[int] = mapped_column(Integer, nullable=False)
    class_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    method_name: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)

    finding_data: Mapped[dict] = mapped_column(JSON, nullable=False)
    provenance: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    normalized_crypto: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    policy_evaluation: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    compliance_status: Mapped[Optional[str]] = mapped_column(String(20), nullable=True, index=True)

    # Soft-delete tombstone (migration 0075, audits 15/16): NULL = alive.
    # Consumption surfaces filter on deleted_at; chain verification and
    # exports do NOT — a tombstone stays in the hash chain it committed to,
    # which is the entire point (retracting a finding must never break the
    # integrity of the scan that recorded it).
    deleted_at: Mapped[Optional[object]] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    deleted_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    delete_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    scan = relationship("Scan", back_populates="evidence_records")

    @property
    def evidence_id(self) -> str:
        return self.id
