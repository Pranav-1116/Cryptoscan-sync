"""Evidence disposition ORM model (§4.2 P0, round 40).

Historical evidence rows committed before the snippet-sanitization change
may still contain raw detector text at rest. The safe response projection
hides those fields, but a projection is not deletion and the stored
hashes commit to the original payload. This table records the operator's
controlled disposition decision per scan — append-only, audited, never a
silent rewrite of ``finding_data``, chain links, manifests or signatures.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped

#: Decisions an operator can record. QUARANTINE_EXPORTS and MARK_REDACTED
#: both refuse scan exports until a re-issued chain exists; RETAIN records
#: an explicit reviewed decision to keep the rows as they are.
DECISIONS = ("RETAIN", "QUARANTINE_EXPORTS", "MARK_REDACTED")


class EvidenceDisposition(BaseModel, TenantScoped):
    __tablename__ = "evidence_dispositions"

    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    decision: Mapped[str] = mapped_column(String(50), nullable=False)
    decided_by: Mapped[str] = mapped_column(String(120), nullable=False)
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Field NAMES the inventory found stripped by the safe projection —
    # metadata only, never the sensitive content itself.
    triggering_fields: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    affected_records: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
