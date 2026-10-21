"""Exact-estate assurance history. Revisions/blobs are append-only at the API.

These are evidence assertions, not a replacement asset identity or inventory.
Production DB administrators must also restrict UPDATE/DELETE on history tables.
"""
from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Integer, JSON, LargeBinary, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from db.models.base import BaseModel
from db.tenancy import TenantScoped

_SCOPE = "scope_key = CASE WHEN tenant_id IS NULL THEN 'platform' ELSE 'tenant:' || tenant_id END"


class AssuranceRevision(BaseModel, TenantScoped):
    __tablename__ = "assurance_revisions"
    __table_args__ = (
        CheckConstraint(_SCOPE, name="ck_assurance_scope"),
        UniqueConstraint("scope_key", "kind", "subject_id", "revision", name="uq_assurance_revision"),
    )
    scope_key: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    subject_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    previous_sha256: Mapped[str | None] = mapped_column(String(64))
    created_by: Mapped[str] = mapped_column(String(36), nullable=False)


class AssuranceBlob(BaseModel, TenantScoped):
    __tablename__ = "assurance_blobs"
    __table_args__ = (CheckConstraint(_SCOPE, name="ck_assurance_blob_scope"),)
    scope_key: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    byte_count: Mapped[int] = mapped_column(Integer, nullable=False)
    data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_by: Mapped[str] = mapped_column(String(36), nullable=False)


class CollectionPhaseReceipt(BaseModel, TenantScoped):
    __tablename__ = "collection_phase_receipts"
    __table_args__ = (UniqueConstraint("job_id", "ordinal", name="uq_collection_phase_ordinal"),)
    job_id: Mapped[str] = mapped_column(String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    endpoint: Mapped[str] = mapped_column(Text, nullable=False)
    phase: Mapped[str] = mapped_column(String(40), nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="NOT_ATTEMPTED")
    started_at: Mapped[object | None] = mapped_column(DateTime(timezone=True), nullable=True)
    observation_succeeded: Mapped[bool | None] = mapped_column(nullable=True)
    observation: Mapped[dict | None] = mapped_column(JSON)
    observation_sha256: Mapped[str | None] = mapped_column(String(64))
    reason: Mapped[str | None] = mapped_column(String(80))

# Protect ordinary ORM code paths too. Bulk SQL/DB administrator operations are
# outside this guard and require restricted grants, audited retention and backup
# controls; a hash chain alone is not storage immutability certification.
from sqlalchemy import event  # noqa: E402


def _immutable(_mapper, _connection, _target):
    raise ValueError("Assurance history and raw evidence are append-only")


for _model in (AssuranceRevision, AssuranceBlob):
    event.listen(_model, "before_update", _immutable)
    event.listen(_model, "before_delete", _immutable)
