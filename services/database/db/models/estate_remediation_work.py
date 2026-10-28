"""Work the twin opens for itself, and the observation that would close it (spec 94 §23).

The twin could already *show* a conflict, a coverage loss and a simulation blocker. It
opened nothing from any of them, which meant the loop stopped at the finding: an operator
read a screen and then typed the ticket into another system, and no part of the product
could ever say whether the estate changed because of that ticket.

This table is the missing hand-off, and three columns carry the honesty:

* ``proof_kind`` / ``proof_expected`` — the observation that would prove the fix, written
  down **when the work is opened**, not when someone claims it is done. A work item with no
  machine-checkable predicate says ``HUMAN`` rather than being closed on an assertion;
* ``status`` — ``OPEN`` -> ``PROVEN`` only through ``api.estate_remediation.reconcile``,
  which reads a stored observation or a stored collector outcome. Nothing sets ``PROVEN`` by
  hand, and ``ABANDONED`` keeps the row so the estate keeps the memory of work that was
  started and dropped;
* ``proof_evidence_id`` — the record that closed it. A closure that cannot name one is not
  a closure.

``claim_key`` is content-derived from (source, subject, claim), so re-running the proposal
refreshes the same item instead of filing a second ticket for the same disagreement — the
same rule the evidence records follow.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class EstateRemediationWork(BaseModel, TenantScoped):
    """One piece of work the twin opened, with the proof it would take to close it."""

    __tablename__ = "estate_remediation_work"
    __table_args__ = (
        Index("ix_estate_remediation_tenant_claim", "tenant_id", "claim_key", unique=True),
        Index("ix_estate_remediation_status", "status"),
        Index("ix_estate_remediation_subject", "subject_id"),
    )

    #: content-derived: source + subject + claim
    claim_key: Mapped[str] = mapped_column(String(96), nullable=False)
    #: CONFLICT | COVERAGE_LOSS | SIMULATION_BLOCKER
    source: Mapped[str] = mapped_column(String(40), nullable=False)
    subject_id: Mapped[Optional[str]] = mapped_column(String(120))
    subject_kind: Mapped[Optional[str]] = mapped_column(String(40))
    title: Mapped[str] = mapped_column(String(400), nullable=False)
    claim: Mapped[str] = mapped_column(Text, nullable=False)
    #: what this work does not prove, carried from the claim that opened it
    not_proven: Mapped[Optional[list]] = mapped_column(JSON)
    severity: Mapped[Optional[str]] = mapped_column(String(20))

    #: OPEN | PROVEN | ABANDONED
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="OPEN")
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    opened_by: Mapped[Optional[str]] = mapped_column(String(120))
    opened_from: Mapped[Optional[str]] = mapped_column(String(96))

    #: COVERAGE_DISPUTE | COLLECTOR_STATUS | HUMAN
    proof_kind: Mapped[str] = mapped_column(String(30), nullable=False, default="HUMAN")
    proof_fact_type: Mapped[Optional[str]] = mapped_column(String(120))
    proof_expected: Mapped[Optional[str]] = mapped_column(String(200))
    proof_note: Mapped[Optional[str]] = mapped_column(Text)

    proven_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    proof_observation_id: Mapped[Optional[str]] = mapped_column(String(96))
    proof_evidence_id: Mapped[Optional[str]] = mapped_column(String(96))
    proof_observed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    proof_detail: Mapped[Optional[dict]] = mapped_column(JSON)
    reconcile_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_checked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
