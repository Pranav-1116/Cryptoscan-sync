"""Provenance-preserving links between collection events and stored content.

The critical distinction of evidence deduplication (spec 2.1): two systems
can produce **identical evidence bytes** and still be different evidence —
different owners, collection times, source locations and authorization
contexts. The bytes deduplicate (one ``content_objects`` row); the
provenance never does — every collection event inserts its own row here,
even when ``content_sha256`` is identical to a thousand others.

Deleting or merging these rows to "save space" would destroy the audit
trail: the row IS the answer to "who collected this, when, from where,
under whose authorization?".
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantOwned


class EvidenceContentLink(BaseModel, TenantOwned):
    """One collection event's relationship to one piece of stored content."""

    __tablename__ = "evidence_content_links"
    __table_args__ = (
        Index("ix_evidence_content_links_tenant_sha", "tenant_id", "content_sha256"),
        Index("ix_evidence_content_links_record", "evidence_record_id"),
    )

    #: The evidence record this content belongs to (scan evidence). NULL for
    #: content recorded outside a scan chain (e.g. raw collector output).
    evidence_record_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("evidence_records.id", ondelete="CASCADE"), nullable=True
    )
    #: Free-form reference for non-record observations (estate observations,
    #: job outputs) so the link table covers every collection path.
    observation_ref: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    #: Content address of the bytes (points at content_objects.sha256).
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    #: When the collection happened — the provenance that must survive
    #: deduplication.
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    #: Which system/collector produced the bytes.
    collector: Mapped[str] = mapped_column(String(120), nullable=False)
    #: Where the bytes came from (host, path, endpoint, run id …).
    source_location: Mapped[str] = mapped_column(Text, nullable=False)
    #: Who owns the evidence (the principal, team or system of record).
    owner: Mapped[str] = mapped_column(String(120), nullable=False)
    #: The authorization context the collection ran under. Kept verbatim;
    #: two identical bytes under different authorization are different
    #: evidence.
    authorization_context: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
