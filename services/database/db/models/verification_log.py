"""
VerificationLog ORM model - audit trail for evidence integrity verifications.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, CheckConstraint, ForeignKey, Index, Integer, String, Text
from sqlalchemy import text as sa_text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base


class VerificationLog(Base):
    """
    Records each integrity verification run against a scan's evidence chain.

    Every time evidence is verified (at load time, scheduled, or on-demand),
    a record is created here. This provides an audit trail proving that
    evidence has been checked and when any tampering was detected.
    """

    __tablename__ = "verification_log"
    __table_args__ = (
        CheckConstraint(
            "result IN ('PASS', 'FAIL', 'PARTIAL')",
            name="ck_verification_result",
        ),
        Index("idx_verification_log_scan_id", "scan_id"),
        Index(
            "idx_verification_log_result_fail",
            "result",
            postgresql_where=sa_text("result = 'FAIL'"),
        ),
    )

    # Primary key
    verification_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=sa_text("gen_random_uuid()"),
        doc="Unique identifier for this verification run",
    )

    # Foreign key to scan
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.scan_id", ondelete="CASCADE"),
        nullable=False,
        doc="The scan whose evidence was verified",
    )

    # Verification result
    verified_at: Mapped[datetime] = mapped_column(
        nullable=False,
        server_default=sa_text("NOW()"),
        doc="Timestamp when verification was performed",
    )
    verified_by: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        doc="System component or user who triggered verification",
    )
    result: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        doc="Overall result: PASS, FAIL, or PARTIAL",
    )

    # Detailed verification results
    chain_valid: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=sa_text("true"),
        doc="Whether the blockchain-style chain hash is intact",
    )
    content_hashes_valid: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=sa_text("true"),
        doc="Whether all content hashes match recomputed values",
    )
    manifest_valid: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
        doc="Whether the scan manifest hash is valid",
    )
    findings_count_verified: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        doc="Number of findings whose integrity was checked",
    )

    # Error details (for FAIL results)
    errors: Mapped[list[Any] | None] = mapped_column(
        JSONB,
        nullable=True,
        server_default=sa_text("'[]'"),
        doc="List of integrity errors found, if any",
    )
    details: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
        server_default=sa_text("'{}'"),
        doc="Additional verification metadata",
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        nullable=False,
        server_default=sa_text("NOW()"),
    )

    # Relationships
    scan = relationship("Scan", back_populates="verification_logs")

    def __repr__(self) -> str:
        return (
            f"<VerificationLog("
            f"verification_id={self.verification_id!r}, "
            f"scan_id={self.scan_id!r}, "
            f"result={self.result!r}, "
            f"verified_at={self.verified_at!r}"
            f")>"
        )

    @property
    def is_pass(self) -> bool:
        """Returns True if verification passed."""
        return self.result == "PASS"

    @property
    def is_fail(self) -> bool:
        """Returns True if verification failed (tampering detected)."""
        return self.result == "FAIL"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for API responses."""
        return {
            "verification_id": str(self.verification_id),
            "scan_id": str(self.scan_id),
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "verified_by": self.verified_by,
            "result": self.result,
            "chain_valid": self.chain_valid,
            "content_hashes_valid": self.content_hashes_valid,
            "manifest_valid": self.manifest_valid,
            "findings_count_verified": self.findings_count_verified,
            "errors": self.errors or [],
            "details": self.details or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }