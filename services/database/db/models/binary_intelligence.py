"""Binary Intelligence persistence (docs/binary-intelligence/
01_PRODUCT_SPEC.md §11).

The original artifact identity, the scan run, individual findings and
their evidence are preserved SEPARATELY. The artifact's SHA-256 is
linked to every scan run; a changed artifact is a new immutable
artifact version, never an overwrite.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import JSON, Boolean, DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class BinaryArtifact(BaseModel, TenantScoped):
    """Artifact identity: digest-based and immutable (§1/§11)."""

    __tablename__ = "binary_artifacts"

    artifact_id: Mapped[str] = mapped_column(String(80), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    file_size: Mapped[int] = mapped_column(Integer, nullable=False)
    detected_format: Mapped[str] = mapped_column(String(40), nullable=False)
    format_reason: Mapped[str] = mapped_column(Text, nullable=False)
    original_filename: Mapped[str] = mapped_column(String(200), nullable=False)
    source_type: Mapped[str] = mapped_column(String(40), nullable=False)
    source_location: Mapped[Optional[str]] = mapped_column(String(400))
    uploaded_by: Mapped[str] = mapped_column(String(120), nullable=False)

    __table_args__ = (
        Index("ix_binary_artifacts_tenant_artifact",
              "tenant_id", "artifact_id", unique=True),
        Index("ix_binary_artifacts_tenant_sha",
              "tenant_id", "sha256", unique=True),
    )


class BinaryScanRun(BaseModel, TenantScoped):
    """One analysis run: configuration, versions, status and the
    normalized structural report (sections, symbols, dependencies)."""

    __tablename__ = "binary_scan_runs"

    scan_id: Mapped[str] = mapped_column(String(80), nullable=False)
    artifact_id: Mapped[str] = mapped_column(String(80), nullable=False)
    artifact_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    scan_profile: Mapped[str] = mapped_column(String(20), nullable=False)
    scanner_version: Mapped[str] = mapped_column(String(80), nullable=False)
    signature_database_version: Mapped[str] = mapped_column(
        String(120), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    structural_report: Mapped[Optional[Any]] = mapped_column(JSON)
    pqc_assessment: Mapped[Optional[Any]] = mapped_column(JSON)
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False)

    __table_args__ = (
        Index("ix_binary_scan_runs_tenant_scan",
              "tenant_id", "scan_id", unique=True),
        Index("ix_binary_scan_runs_tenant_artifact",
              "tenant_id", "artifact_id"),
    )


class BinaryCryptoFinding(BaseModel, TenantScoped):
    """A normalized cryptographic finding — evidence class and usage
    status carry the claim (§5/§7)."""

    __tablename__ = "binary_crypto_findings"

    run_id: Mapped[str] = mapped_column(String(80), nullable=False)
    finding_id: Mapped[str] = mapped_column(String(80), nullable=False)
    subject: Mapped[str] = mapped_column(String(200), nullable=False)
    finding_type: Mapped[str] = mapped_column(String(60), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(60), nullable=False,
                                           default="")
    variant: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    operation: Mapped[str] = mapped_column(String(60), nullable=False,
                                           default="")
    mode_or_padding: Mapped[str] = mapped_column(String(40), nullable=False,
                                                 default="")
    key_size_bits: Mapped[Optional[int]] = mapped_column(Integer)  # None = unknown
    library: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    detection_method: Mapped[str] = mapped_column(String(80), nullable=False,
                                                  default="")
    evidence_class: Mapped[str] = mapped_column(String(40), nullable=False)
    usage_status: Mapped[str] = mapped_column(String(40), nullable=False)
    runtime_confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False,
                                                    default=False)
    quantum_vulnerable: Mapped[bool] = mapped_column(Boolean, nullable=False,
                                                     default=False)
    pqc_family: Mapped[bool] = mapped_column(Boolean, nullable=False,
                                             default=False)
    limitations: Mapped[Optional[Any]] = mapped_column(JSON)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False)

    __table_args__ = (
        Index("ix_binary_crypto_findings_run", "run_id"),
        Index("ix_binary_crypto_findings_tenant_run",
              "tenant_id", "run_id"),
    )


class BinaryEvidence(BaseModel, TenantScoped):
    """Evidence items, preserved separately from their finding (§11)."""

    __tablename__ = "binary_evidence"

    finding_id: Mapped[str] = mapped_column(String(80), nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(40), nullable=False)
    location: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    excerpt: Mapped[str] = mapped_column(Text, nullable=False, default="")

    __table_args__ = (
        Index("ix_binary_evidence_finding", "finding_id"),
        Index("ix_binary_evidence_tenant_finding",
              "tenant_id", "finding_id"),
    )


class BinaryAnalysisCoverage(BaseModel, TenantScoped):
    """Analysis coverage — separate from finding confidence (§7)."""

    __tablename__ = "binary_analysis_coverage"

    run_id: Mapped[str] = mapped_column(String(80), nullable=False)
    total_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    bytes_inspected: Mapped[int] = mapped_column(Integer, nullable=False)
    sections_total: Mapped[int] = mapped_column(Integer, nullable=False)
    sections_inspected: Mapped[int] = mapped_column(Integer, nullable=False)
    executable_sections: Mapped[int] = mapped_column(Integer, nullable=False)
    symbols_found: Mapped[int] = mapped_column(Integer, nullable=False)
    symbols_stripped: Mapped[bool] = mapped_column(Boolean, nullable=False)
    unresolved_dependencies: Mapped[Optional[Any]] = mapped_column(JSON)
    unsupported_regions: Mapped[Optional[Any]] = mapped_column(JSON)
    extraction_failures: Mapped[Optional[Any]] = mapped_column(JSON)
    deep_analysis_completed: Mapped[bool] = mapped_column(Boolean,
                                                          nullable=False,
                                                          default=False)
    packed_or_encrypted_suspected: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False)
    analysis_timeouts: Mapped[int] = mapped_column(Integer, nullable=False,
                                                   default=0)

    __table_args__ = (
        Index("ix_binary_analysis_coverage_run", "run_id"),
        Index("ix_binary_analysis_coverage_tenant_run",
              "tenant_id", "run_id", unique=True),
    )
