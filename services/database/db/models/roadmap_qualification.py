"""Discovery qualification records and external validation filings.

* :class:`DiscoveryQualification` — the qualification state of one collector for
  one target family (:mod:`shared_models.discovery_qualification` decides what
  each state may claim). Fixture-only runs file ``FIXTURE_VERIFIED`` and nothing
  else; a revoked qualification is a row, never a deletion;
* :class:`ExternalValidation` — filings of acts performed OUTSIDE the platform
  (DR drills, pen tests, real HSM runs…). The platform never marks these done
  itself; a row here is evidence someone else filed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, DateTime, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel


class DiscoveryQualification(BaseModel):
    __tablename__ = "discovery_qualifications"
    __table_args__ = (
        Index("ix_discovery_qualification_collector_family", "collector", "family"),
    )

    collector: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    family: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    state: Mapped[str] = mapped_column(String(30), nullable=False)
    evidence_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    observed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True)
    reason: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)


class ExternalValidation(BaseModel):
    __tablename__ = "external_validations"
    __table_args__ = (
        Index("ix_external_validation_kind_performed", "kind", "performed_at"),
    )

    kind: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    performed_by: Mapped[str] = mapped_column(String(200), nullable=False)
    evidence_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    performed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False)
    scope: Mapped[str] = mapped_column(String(500), nullable=False)
    result: Mapped[str] = mapped_column(String(20), nullable=False, default="PASSED")
    note: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
