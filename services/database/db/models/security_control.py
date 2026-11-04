"""What the security controls said, when, and how it is proved.

Guide 181 built the layer and kept its evidence in a directory: an append-only, hash-chained
file store per tenant. That is the right shape for evidence — but a bank does not audit a
directory, it audits a record: which control said what, on which snapshot, with which two
evidence ids behind the claim, and whether the row has been edited since.

So there are two tables, and the split is the point:

* :class:`SecurityControlSnapshot` — one row per *read*, carrying the digest of the body, the
  sequence within its tenant, and the previous row's entry hash. The body itself stays where a
  body belongs (the object store or the file store), because a snapshot can be megabytes of
  device configuration and a row is not a place to put one. What lives here is the part that
  has to be queryable and immutable: the chain.
* :class:`SecurityControlFinding` — the *statements* a snapshot makes, one row each:
  ``state``, the subject, the fact classes, and the evidence ids that back it. A finding is a
  claim, and a claim with no ``evidence_ids`` is refused by the writer rather than stored
  hopefully.

Neither table is written by a user. A snapshot row is created by the collector, through the
service identity (guide 182's ``POST /security-controls/snapshots``); a finding row is created
with it. There is no update path in the API for either, because a closed snapshot is evidence.

Why ``tenant_id`` is on both, explicitly
----------------------------------------

The tenant guard adds it automatically for a ``TenantScoped`` model, but the *index* has to
name it: every read this table serves is "for this tenant, the latest snapshot" or "for this
tenant, the findings in this control", and a query that cannot use an index becomes a scan of
every tenant's evidence — which is both slow and a tenancy smell in review.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import (JSON, Boolean, DateTime, ForeignKey, Index, Integer, String,
                        UniqueConstraint)
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped

#: the fact classes a finding may carry. A finding that names a class outside this set is a
#: model bug, and the writer refuses it instead of storing an aspiration as a fact.
FACT_CLASSES: tuple[str, ...] = ("CONFIGURED", "OBSERVED", "RUNTIME_OBSERVED", "INFERRED")

#: the states a finding may be in. ``NOT_CONFIGURED`` and ``UNKNOWN`` are *different*: the
#: first is a decision the bank has not made, the second is a reading the collector could not
#: take. Collapsing them is how a gap gets reported as a policy.
FINDING_STATES: tuple[str, ...] = (
    "CONFIGURED", "OBSERVED", "WITHIN_LIMIT", "OVER_LIMIT", "NOT_CONFIGURED",
    "POLICY_NOT_ATTACHED", "INCOMPARABLE_WINDOW", "UNKNOWN", "STALE_EVIDENCE", "REFUSED",
)


class SecurityControlSnapshot(BaseModel, TenantScoped):
    """One read of one or more controls, chained to the read before it."""

    __tablename__ = "security_control_snapshots"
    __table_args__ = (
        UniqueConstraint("tenant_id", "sequence", name="uq_security_control_snapshot_seq"),
        UniqueConstraint("tenant_id", "digest", name="uq_security_control_snapshot_digest"),
        Index("ix_security_control_snapshot_tenant_captured",
              "tenant_id", "captured_at"),
    )

    #: sha256 over the canonical body, minus the volatile fields. Two reads that say the same
    #: thing have one digest, which is what makes a retried collection idempotent.
    digest: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    #: monotonic within the tenant. A gap is a deleted row, and ``verify`` says so.
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    #: the entry hash of the row before this one, so the chain can be re-walked
    previous_hash: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    entry_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    #: which controls the read covered, and the counts that make a diff readable without
    #: loading the body
    controls: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    counts: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    #: where the body is kept. Not the body: a snapshot is evidence, and evidence is content
    #: addressed in a store built for it, not a JSON column that grows a table by megabytes.
    body_digest: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    body_location: Mapped[str] = mapped_column(String(400), nullable=False, default="")
    body_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    #: the collector identity that produced the read (a service identity, never a user token)
    collector: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    #: a snapshot that was re-read because a section failed says so here; the state is the
    #: worst section state, never ``OK``
    read_state: Mapped[str] = mapped_column(String(40), nullable=False, default="OK")
    partial: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    #: refusals are counted, and the rows are kept as findings — a refusal is a finding about
    #: the integration and it is never dropped
    refusals: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class SecurityControlFinding(BaseModel, TenantScoped):
    """One statement a snapshot makes, with the evidence that backs it."""

    __tablename__ = "security_control_findings"
    __table_args__ = (
        Index("ix_security_control_finding_tenant_control",
              "tenant_id", "control", "state"),
        Index("ix_security_control_finding_snapshot", "snapshot_id"),
    )

    snapshot_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("security_control_snapshots.id", ondelete="CASCADE"),
        nullable=False)
    control: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    vendor: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    #: the thing the statement is about: an asset name, an API, a policy, a certificate ref
    subject: Mapped[Optional[str]] = mapped_column(String(400), nullable=True, index=True)
    #: what kind of statement it is — a control state, a relationship, a rate-limit verdict
    kind: Mapped[str] = mapped_column(String(40), nullable=False, default="STATE")
    state: Mapped[str] = mapped_column(String(40), nullable=False, index=True)

    #: the fact classes this row rests on. ``CONFIGURED`` alone never becomes ``OBSERVED`` by
    #: being stored next to it; the list is kept and read as a list.
    facts: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    #: one or more ids. A finding with none cannot be constructed by the writer.
    evidence_ids: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    #: the configured expectation and the observed measurement, side by side and never merged
    expected: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    observed: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    detail: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    reason: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)

    def states(self) -> list[str]:
        """Helper for callers that want the row's own vocabulary, not a vocabulary."""
        return [self.state] if self.state else []
