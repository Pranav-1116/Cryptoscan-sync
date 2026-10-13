"""Persisted, content-addressed CBOM snapshots (§4.4, round 45).

`GET /cbom/scan/{id}` regenerates a BOM from whatever the evidence store
says RIGHT NOW — two calls can differ (soft-deletions, dispositions,
re-loads), and the pipeline's BOM died with its ephemeral workspace. A
snapshot freezes ONE deterministic rendering, tied to the exact scan:

* ``content_hash`` is SHA-256 over the exact serialized document, so the
  snapshot is content-addressed: identical renderings collapse to one row
  (idempotent creation), and a mutated payload is detectable (integrity
  self-check on read).
* ``scan_id`` keeps the traceability chain: snapshot → scan → evidence →
  hash chain. An exported BOM can always be traced to the exact admitted
  scan and its evidence version.
* ``signed`` records the signature form embedded in the payload ("none",
  "jws" legacy metadata-property, or "jsf" CycloneDX-spec enveloped). The
  hash covers the signed document, so signature and content are pinned
  together.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


def normalize_for_snapshot(bom: dict, *, scan_timestamp_iso: str | None) -> dict:
    """Anchor the document's wall-clock to the scan before hashing.

    ``CbomGenerator`` stamps ``metadata.timestamp`` with ``datetime.now()`` —
    two renderings of identical evidence would hash differently and content
    addressing would be meaningless. A pinned snapshot replaces that with a
    scan-derived value (scan end, falling back to scan creation), making the
    document a pure function of (scan, evidence, signature). The snapshot's
    own ``snapshotted_at`` column still records the real pin time.
    """
    out = dict(bom)
    meta = dict(out.get("metadata") or {})
    if scan_timestamp_iso:
        meta["timestamp"] = scan_timestamp_iso
    out["metadata"] = meta
    return out


class CbomSnapshot(BaseModel, TenantScoped):
    __tablename__ = "cbom_snapshots"
    __table_args__ = (
        UniqueConstraint("scan_id", "content_hash", name="uq_cbom_snapshot_scan_hash"),
    )

    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    #: SHA-256 hex over the exact serialized document at snapshot time
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    #: serialization format of the stored payload ("json")
    format: Mapped[str] = mapped_column(String(10), nullable=False, default="json")
    #: signature form embedded in the payload: none | jws | jsf
    signed: Mapped[str] = mapped_column(String(10), nullable=False, default="none")
    #: which surface produced the rendering: api | pipeline
    generator: Mapped[str] = mapped_column(String(30), nullable=False, default="api")
    #: the exact rendered document — served verbatim, never regenerated
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    component_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_by: Mapped[str] = mapped_column(String(120), nullable=False)
    snapshotted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    def to_dict(self, exclude: set[str] | None = None) -> dict:
        exclude = (exclude or set()) | {"payload"}
        data = super().to_dict(exclude=exclude)
        for key in ("snapshotted_at", "created_at", "updated_at"):
            value = data.get(key)
            if hasattr(value, "isoformat"):
                data[key] = value.isoformat()
        return data
