"""Formal policy exceptions and their periodic reviews."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.models.base import BaseModel


class PolicyException(BaseModel):
    __tablename__ = "policy_exceptions"

    asset_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    system_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    policy_rule_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    exception_type: Mapped[str] = mapped_column(String(50), nullable=False, default="RISK_ACCEPTANCE")
    justification: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    risk_statement: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    compensating_controls: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    requested_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    requested_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    approval_signature: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    expiration_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    review_frequency: Mapped[str] = mapped_column(String(50), nullable=False, default="QUARTERLY")
    last_reviewed: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="PENDING", index=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    reviews = relationship(
        "ExceptionReview",
        back_populates="exception",
        cascade="all, delete-orphan",
        lazy="select",
    )


class ExceptionReview(BaseModel):
    __tablename__ = "exception_reviews"

    exception_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("policy_exceptions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    review_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    reviewer: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    still_valid: Mapped[bool] = mapped_column(Boolean, default=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    action_taken: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    exception = relationship("PolicyException", back_populates="reviews")
