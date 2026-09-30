"""Durable binary-analysis index and bounded per-artifact observations.

The content-addressed SBOM/CBOM documents remain in the artifact store. These
rows make the binary surface queryable without reading every manifest or large
JSON document, and preserve the evidence boundary: observations contain
selected parser metadata, hashes, confidence/state fields, and redacted crypto
metadata, never executable bytes or private key material.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import Boolean, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class BinaryScanRecord(BaseModel, TenantScoped):
    __tablename__ = "binary_scan_records"
    __table_args__ = (UniqueConstraint("tenant_id", "artifact_id", name="uq_binary_scan_records_tenant_artifact"),)

    artifact_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    job_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    target: Mapped[str] = mapped_column(Text, nullable=False)
    format: Mapped[str] = mapped_column(String(32), nullable=False, default="cyclonedx")
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="COMPLETED")
    created_by: Mapped[str] = mapped_column(String(200), nullable=False, default="system")

    files_walked: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    binaries_scanned: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    observations_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    observations_truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Summary and limits are deliberately denormalized read models. The signed
    # manifest remains the authoritative export; these fields power filtering and
    # the UI without loading the whole artifact.
    summary: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    coverage: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    limits: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)


class BinaryScanObservation(BaseModel, TenantScoped):
    __tablename__ = "binary_scan_observations"

    scan_record_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    artifact_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    format: Mapped[str] = mapped_column(String(32), nullable=False, default="raw")
    arch: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    parsed: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    evidence_state: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    derived_from: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    depth: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Selected, bounded JSON projections. No raw bytes and no key material.
    crypto: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    hardening: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    signature: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    coverage: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    findings: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    # `metadata` is reserved by SQLAlchemy's Declarative base; expose it as
    # `metadata` in the API serializer, but keep a safe ORM attribute name.
    parser_metadata: Mapped[Optional[dict]] = mapped_column("parser_metadata", JSON, nullable=True)
