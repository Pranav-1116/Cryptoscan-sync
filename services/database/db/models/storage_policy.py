"""Storage policies, quotas and restore-test records (spec §7 controls 5, 8, 10).

* ``StoragePolicy`` — how long each evidence category is retained and when
  it migrates hot → warm → cold. NULL ``tenant_id`` rows are the platform
  defaults; a tenant row overrides for that tenant. Retention deletes or
  archives expired data **according to policy** — never by guesswork.
* ``StorageQuota`` — per-tenant and per-job limits. A collection run that
  would push the estate past its quota is refused loudly at write time;
  silent growth until the disk fills is the failure mode these prevent.
* ``RestoreTestRecord`` — evidence that archived evidence was actually
  recovered and verified (control 10). A backup nobody restored is a
  hope, not a control.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, Boolean, DateTime, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantOwned, TenantScoped


class StoragePolicy(BaseModel, TenantScoped):
    """Retention + lifecycle policy for one evidence category."""

    __tablename__ = "storage_policies"
    __table_args__ = (
        Index("uq_storage_policies_tenant_category", "tenant_id", "category", unique=True),
    )

    #: One of EVIDENCE_CATEGORIES.
    category: Mapped[str] = mapped_column(String(40), nullable=False)
    #: Days to retain. Past this, the retention sweep archives or deletes
    #: per ``expired_action``.
    retention_days: Mapped[int] = mapped_column(Integer, nullable=False)
    #: Days an object stays hot before migrating to warm storage.
    hot_days: Mapped[int] = mapped_column(Integer, nullable=False, default=7)
    #: Days in warm before migrating to cold storage.
    warm_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    #: Whether content in this category is zstd-compressed where it helps.
    compress: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    #: 'archive' = move to cold and verify before drop; 'delete' = drop.
    expired_action: Mapped[str] = mapped_column(String(12), nullable=False, default="archive")


class StorageQuota(BaseModel, TenantOwned):
    """Per-tenant or per-job storage limit."""

    __tablename__ = "storage_quotas"
    __table_args__ = (
        Index("uq_storage_quotas_tenant_scope_job", "tenant_id", "scope", "job_id", unique=True),
    )

    #: 'tenant' = whole estate limit; 'job' = one collection job's budget.
    scope: Mapped[str] = mapped_column(String(12), nullable=False, default="tenant")
    #: NULL for tenant-scope rows; the job id for job-scope rows.
    job_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    #: Maximum stored bytes.
    max_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    #: Maximum number of content objects (0 = unlimited object count).
    max_objects: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)


class RestoreTestRecord(BaseModel, TenantOwned):
    """One restore verification of one content object."""

    __tablename__ = "restore_test_records"
    __table_args__ = (
        Index("ix_restore_test_records_tenant_sha", "tenant_id", "object_sha256"),
    )

    object_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    #: The tier the object was restored from (cold restores are the point).
    restored_from_tier: Mapped[str] = mapped_column(String(12), nullable=False)
    ok: Mapped[bool] = mapped_column(Boolean, nullable=False)
    bytes_verified: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    tested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    #: Failure detail (empty on success).
    detail: Mapped[str] = mapped_column(String(500), nullable=False, default="")
