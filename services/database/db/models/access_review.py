"""Records of completed quarterly access reviews (SOC 2 CC6.3 minutes).

The ``access-review`` export produces a signed snapshot of the access
estate (``report_hash``). This table is the system of record for the
*review itself*: who attested, for which period, against which estate
hash, with which findings. Rows are create-only from the API — minutes
are append-only, never edited.
"""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel


# platform-scope: platform security-review plane — auditor records about
# the deployment itself, written by the auditor role, not tenant inventory.
class AccessReviewRecord(BaseModel):
    __tablename__ = "access_reviews"

    period: Mapped[str] = mapped_column(String(16), nullable=False)
    report_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    estate_unchanged: Mapped[bool] = mapped_column(Boolean, nullable=False)
    reviewer: Mapped[str] = mapped_column(String(100), nullable=False)
    findings: Mapped[list | None] = mapped_column(JSON, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    def to_dict(self) -> dict:
        data = super().to_dict()
        data["findings"] = data.get("findings") or []
        return data
