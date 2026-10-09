"""Remediation task tracking + evidence-based verification (audit 62 / GAP-006).

``remediation_tasks`` — one tracked remediation of a non-compliant finding,
snapshotted at creation so later evidence pruning cannot rewrite history.
``remediation_verifications`` — the outcome of comparing a completed task
against rescan evidence: VERIFIED | PARTIAL | FAILED | REGRESSION |
INCONCLUSIVE, with the full comparison retained for the audit trail.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Index, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class RemediationTask(BaseModel, TenantScoped):
    __tablename__ = "remediation_tasks"

    __table_args__ = (
        Index("ix_remediation_tasks_status", "status"),
        Index("ix_remediation_tasks_scan", "scan_id"),
    )

    # the non-compliant EvidenceRecord this task exists to fix (snapshotted
    # below; the id is a provenance pointer, never dereferenced for verdicts)
    evidence_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    scan_id: Mapped[str] = mapped_column(String(36), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(80), nullable=False)
    category: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    priority: Mapped[Optional[str]] = mapped_column(String(4), nullable=True)
    replace_with: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    # full finding snapshot (algorithm, key_size, file_path, …) at creation
    original_finding: Mapped[dict] = mapped_column(JSON, nullable=False)
    # snapshot of the owning scan's target — verification must not depend on
    # the original scan row surviving
    target_location: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # PROPOSED | ACCEPTED | COMPLETED | VERIFIED | PARTIAL | FAILED | REGRESSION
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="PROPOSED")
    owner: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_by: Mapped[str] = mapped_column(String(100), nullable=False, default="system")
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)


class RemediationVerification(BaseModel, TenantScoped):
    __tablename__ = "remediation_verifications"

    __table_args__ = (
        Index("ix_remediation_ver_task", "task_id"),
        Index("ix_remediation_ver_result", "result"),
    )

    task_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    rescan_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    # VERIFIED | PARTIAL | FAILED | REGRESSION | INCONCLUSIVE
    result: Mapped[str] = mapped_column(String(20), nullable=False)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # machine-readable comparison: original snapshot, remaining sites,
    # replacement evidence, new violations — everything the verdict rests on
    comparison: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    verified_by: Mapped[str] = mapped_column(String(100), nullable=False, default="system")
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
