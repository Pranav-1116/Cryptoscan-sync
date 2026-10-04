"""ZELNX P2 enterprise models (deterministic — no AI/ML).

Covers the deferred P2 capabilities that are built on policy and statistics
rather than model inference:

* ``PluginPackage``        — marketplace plugins (hash-pinned, Ed25519-signed,
                             lifecycle state incl. QUARANTINED).
* ``LakeExportBatch``      — append-only hash-chained data-lake export manifests.
* ``AnomalyFlag``          — statistical anomaly detections (z-score/EWMA/ROC/
                             frequency) over telemetry.
* ``MigrationValidation``  — pre/post migration quantum-readiness validation runs.
* ``GovernanceApproval``   — deterministic policy gate approvals for change
                             requests (rules-based, no AI decisioning).
* ``ApiKeyScope`` / quota  — (stored on ApiKey via roles; quotas in api_keys).

All payload columns are JSON metadata only; no secret material is stored.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


# platform-scope: global plugin catalog (versions, signatures); a shared
# resource marketplace, not tenant inventory.
class PluginPackage(BaseModel):
    __tablename__ = "plugin_packages"

    plugin_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    plugin_type: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    content: Mapped[str | None] = mapped_column(Text, nullable=True)  # text payload (rules/code)
    signature: Mapped[str | None] = mapped_column(Text, nullable=True)  # base64 Ed25519
    signer_key_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    min_platform: Mapped[str] = mapped_column(String(32), nullable=False, default="0.0.0")
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="UPLOADED", index=True)
    trusted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    author: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    tags: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    verify_errors: Mapped[list | None] = mapped_column(JSON, nullable=True)
    enabled_by: Mapped[str | None] = mapped_column(String(100), nullable=True)


class LakeExportBatch(BaseModel, TenantScoped):
    __tablename__ = "lake_export_batches"

    lake_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    batch_id: Mapped[int] = mapped_column(Integer, nullable=False)
    record_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    record_hashes: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    batch_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    previous_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    chain_digest: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    signer_key_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    export_kind: Mapped[str] = mapped_column(String(40), nullable=False, default="findings")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="SEALED")
    created_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    records: Mapped[list | None] = mapped_column(JSON, nullable=True)  # payload (small batches)


class AnomalyFlag(BaseModel, TenantScoped):
    __tablename__ = "anomaly_flags"

    rule: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    metric: Mapped[str] = mapped_column(String(128), nullable=False, default="", index=True)
    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    value: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    explanation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    context: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="OPEN", index=True)
    acknowledged_by: Mapped[str | None] = mapped_column(String(100), nullable=True)


class MigrationValidation(BaseModel, TenantScoped):
    __tablename__ = "migration_validations"

    migration_project_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    system_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    stage: Mapped[str] = mapped_column(String(20), nullable=False, default="PRE")  # PRE/POST
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="PENDING", index=True)
    findings_before: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_after: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    regressions: Mapped[list | None] = mapped_column(JSON, nullable=True)
    coverage_delta: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    report: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    validated_by: Mapped[str | None] = mapped_column(String(100), nullable=True)


class GovernanceApproval(BaseModel, TenantScoped):
    __tablename__ = "governance_approvals"

    request_type: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    request_ref: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    requested_by: Mapped[str] = mapped_column(String(100), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="PENDING", index=True)
    decision: Mapped[str | None] = mapped_column(String(20), nullable=True)  # APPROVED/DENIED
    decided_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    rationale: Mapped[str] = mapped_column(Text, nullable=False, default="")
    policy_rules: Mapped[list | None] = mapped_column(JSON, nullable=True)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False, default="LOW")
    payload: Mapped[dict | None] = mapped_column(JSON, nullable=True)
