"""Durable compliance records (§4.3, round 47).

The evidence engine collects live control checks on every call and the
attestation route used to sign an in-memory pack that evaporated with the
request — a reviewer sign-off had no durable record, and requirement
expiry/freshness had nothing to be measured against. Two tables fix that:

* ``ComplianceEvidencePack`` — ONE collected evidence pack, stored verbatim
  and content-addressed (SHA-256 over the exact serialized payload, the same
  serialization ``collect_evidence`` hashed). Requirement evaluation and
  attestations reference the pinned pack, never a moving live state.
* ``ComplianceAttestation`` — a reviewer's JWS signature over an exact
  pinned pack (scope, signer, snapshot, compact JWS). Re-verified on read,
  so a rotated or tampered signature surfaces as invalid instead of
  silently counting as sign-off.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class ComplianceEvidencePack(BaseModel, TenantScoped):
    __tablename__ = "compliance_evidence_packs"
    __table_args__ = (UniqueConstraint("pack_sha256", name="uq_compliance_pack_sha"),)

    #: SHA-256 over the exact serialized payload (sort_keys, default=str) —
    #: the same hash collect_evidence computed, so integrity is checkable
    pack_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    #: the pack WITHOUT its pack_sha256 field — served verbatim, never
    #: regenerated; the pinned hash lives in the column, not the payload
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    summary: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    collected_by: Mapped[str] = mapped_column(String(120), nullable=False)


class ComplianceAttestation(BaseModel, TenantScoped):
    __tablename__ = "compliance_attestations"

    pack_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("compliance_evidence_packs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    pack_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    #: what the signature covers, e.g. a register scope like "SOC2-CC6.1"
    scope: Mapped[str] = mapped_column(String(120), nullable=False)
    signed_by: Mapped[str] = mapped_column(String(120), nullable=False)
    #: compact JWS (HS256) over the snapshot — re-verified on every read
    jws: Mapped[str] = mapped_column(Text, nullable=False)
    snapshot: Mapped[dict] = mapped_column(JSON, nullable=False)
    signed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
