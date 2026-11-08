"""OS & Kernel Intelligence persistence
(docs/os-kernel-intelligence/01_PRODUCT_SPEC.md §10).

Entities os_assets … os_coverage (Phase 1). One OSAsset row is one
observed host; every child row belongs to exactly one collection and
carries its evidence class. runtime_usage_confirmed is stored per
capability and is never true from read-only OS collection (§2.2) —
the field exists so future Tier-2 runtime evidence can raise it
without overwriting the static observation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (JSON, Boolean, DateTime, Index, Integer, String,
                        Text)
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class OSAsset(BaseModel, TenantScoped):
    """One observed host: OS identity, kernel identity, collection
    identity. environment_development_only records that a single-host
    development collection is never enterprise qualification (§12)."""

    __tablename__ = "os_assets"

    asset_id: Mapped[str] = mapped_column(String(80), nullable=False)
    collection_id: Mapped[str] = mapped_column(String(80), nullable=False)
    kernel_name: Mapped[str] = mapped_column(String(40), nullable=False)
    kernel_release: Mapped[str] = mapped_column(String(80), nullable=False)
    kernel_version: Mapped[Optional[str]] = mapped_column(String(300))
    machine: Mapped[Optional[str]] = mapped_column(String(40))
    os_pretty_name: Mapped[Optional[str]] = mapped_column(String(200))
    os_id: Mapped[Optional[str]] = mapped_column(String(80))
    os_version_id: Mapped[Optional[str]] = mapped_column(String(80))
    arch: Mapped[Optional[str]] = mapped_column(String(40))
    cmdline: Mapped[Optional[str]] = mapped_column(Text)
    tainted_flags: Mapped[Optional[str]] = mapped_column(String(24))
    tainted_meanings: Mapped[Optional[Any]] = mapped_column(JSON)
    environment_development_only: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True)
    qualification_note: Mapped[Optional[str]] = mapped_column(Text)
    collector_version: Mapped[str] = mapped_column(String(80),
                                                   nullable=False)
    notes: Mapped[Optional[Any]] = mapped_column(JSON)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                   nullable=False)

    __table_args__ = (
        Index("ix_os_assets_tenant_asset", "tenant_id", "asset_id",
              unique=True),
    )


class OSCryptoCapability(BaseModel, TenantScoped):
    """One Kernel Crypto API registration (§2.2): the generic algorithm
    name and the implementation driver are stored separately. This is
    an inventory of REGISTERED implementations — runtime usage is not
    proven; runtime_usage_confirmed stays false for Tier-1 collection."""

    __tablename__ = "os_crypto_capabilities"

    collection_id: Mapped[str] = mapped_column(String(80), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(80), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(120), nullable=False)
    driver: Mapped[Optional[str]] = mapped_column(String(120))
    implementation_type: Mapped[Optional[str]] = mapped_column(String(40))
    module: Mapped[Optional[str]] = mapped_column(String(80))
    priority: Mapped[Optional[int]] = mapped_column(Integer)
    blocksize: Mapped[Optional[int]] = mapped_column(Integer)
    digestsize: Mapped[Optional[int]] = mapped_column(Integer)
    min_keysize: Mapped[Optional[int]] = mapped_column(Integer)
    max_keysize: Mapped[Optional[int]] = mapped_column(Integer)
    selftest: Mapped[Optional[str]] = mapped_column(String(24))
    hardware_accelerated: Mapped[Optional[bool]] = mapped_column(Boolean)
    runtime_usage_confirmed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False)
    parse_notes: Mapped[Optional[Any]] = mapped_column(JSON)

    __table_args__ = (
        Index("ix_os_crypto_cap_tenant_collection", "tenant_id",
              "collection_id"),
        Index("ix_os_crypto_cap_tenant_algorithm", "tenant_id", "algorithm"),
    )


class OSModuleRecord(BaseModel, TenantScoped):
    """One loaded kernel module (LKM) row (§5). A missing row is never
    'the feature is unavailable' — modules may be built in."""

    __tablename__ = "os_modules"

    collection_id: Mapped[str] = mapped_column(String(80), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(80), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    size: Mapped[Optional[int]] = mapped_column(Integer)
    refcount: Mapped[Optional[int]] = mapped_column(Integer)
    used_by: Mapped[Optional[Any]] = mapped_column(JSON)
    state: Mapped[Optional[str]] = mapped_column(String(40))

    __table_args__ = (
        Index("ix_os_modules_tenant_collection", "tenant_id", "collection_id"),
    )


class OSConfigFlag(BaseModel, TenantScoped):
    """One kernel configuration flag of interest (§5). Only flags with a
    recorded state exist as rows: 'not_set' is an explicit disabled
    state; a flag missing from the config source is never recorded as
    disabled (§2.1) — that absence lives in os_coverage."""

    __tablename__ = "os_config_flags"

    collection_id: Mapped[str] = mapped_column(String(80), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(80), nullable=False)
    flag: Mapped[str] = mapped_column(String(120), nullable=False)
    value: Mapped[str] = mapped_column(String(200), nullable=False)
    explicitly_disabled: Mapped[bool] = mapped_column(Boolean,
                                                      nullable=False)

    __table_args__ = (
        Index("ix_os_config_flags_tenant_collection", "tenant_id",
              "collection_id"),
    )


class OSStorageFact(BaseModel, TenantScoped):
    """Disk-encryption METADATA (§7): device, fstype, observed metadata.
    No recovery keys, key files or secrets are ever stored."""

    __tablename__ = "os_storage_facts"

    collection_id: Mapped[str] = mapped_column(String(80), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(80), nullable=False)
    device: Mapped[str] = mapped_column(String(120), nullable=False)
    fstype: Mapped[Optional[str]] = mapped_column(String(60))
    metadata_: Mapped[Optional[Any]] = mapped_column("metadata", JSON)
    notes: Mapped[Optional[Any]] = mapped_column(JSON)

    __table_args__ = (
        Index("ix_os_storage_facts_tenant_collection", "tenant_id",
              "collection_id"),
    )


class OSTrustFact(BaseModel, TenantScoped):
    """Hardware trust metadata (§5): TPM/RNG device presence. Presence
    is metadata, never a trust verdict (§12)."""

    __tablename__ = "os_trust_facts"

    collection_id: Mapped[str] = mapped_column(String(80), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(80), nullable=False)
    subject: Mapped[str] = mapped_column(String(80), nullable=False)
    state: Mapped[str] = mapped_column(String(40), nullable=False)
    evidence_class: Mapped[str] = mapped_column(String(30), nullable=False)
    metadata_: Mapped[Optional[Any]] = mapped_column("metadata", JSON)
    notes: Mapped[Optional[Any]] = mapped_column(JSON)

    __table_args__ = (
        Index("ix_os_trust_facts_tenant_collection", "tenant_id",
              "collection_id"),
    )


class OSFindingRecord(BaseModel, TenantScoped):
    """One normalized finding (§10): observation source, type, evidence
    class, runtime_usage_confirmed and limitations travel together.
    Severity fields are COMPUTED (never named by hand) and nullable
    until the risk model (R=f(S,E,X,B,C), model_version preserved)
    evaluates them."""

    __tablename__ = "os_findings"

    collection_id: Mapped[str] = mapped_column(String(80), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(80), nullable=False)
    finding_type: Mapped[str] = mapped_column(String(120), nullable=False)
    subject: Mapped[Optional[str]] = mapped_column(String(200))
    algorithm: Mapped[Optional[str]] = mapped_column(String(120))
    implementation: Mapped[Optional[str]] = mapped_column(String(120))
    evidence_source: Mapped[Optional[str]] = mapped_column(String(200))
    observation_type: Mapped[str] = mapped_column(String(60),
                                                  nullable=False)
    runtime_usage_confirmed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False)
    evidence_class: Mapped[str] = mapped_column(String(30), nullable=False)
    severity_label: Mapped[Optional[str]] = mapped_column(String(24))
    severity_factors: Mapped[Optional[Any]] = mapped_column(JSON)
    risk_model_version: Mapped[Optional[str]] = mapped_column(String(40))
    details: Mapped[Optional[Any]] = mapped_column(JSON)
    limitations: Mapped[Optional[Any]] = mapped_column(JSON)

    __table_args__ = (
        Index("ix_os_findings_tenant_collection", "tenant_id",
              "collection_id"),
        Index("ix_os_findings_tenant_asset", "tenant_id", "asset_id"),
    )


class OSCoverageRecord(BaseModel, TenantScoped):
    """Collection completeness (§2.1): sources attempted, collected and
    unavailable with reasons + evidence digests. An unavailable source
    is NEVER treated as 'disabled' — and coverage is never finding
    confidence."""

    __tablename__ = "os_coverage"

    collection_id: Mapped[str] = mapped_column(String(80), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(80), nullable=False)
    sources_attempted: Mapped[Optional[Any]] = mapped_column(JSON)
    sources_collected: Mapped[Optional[Any]] = mapped_column(JSON)
    sources_unavailable: Mapped[Optional[Any]] = mapped_column(JSON)
    source_digests: Mapped[Optional[Any]] = mapped_column(JSON)
    note: Mapped[Optional[str]] = mapped_column(Text)

    __table_args__ = (
        Index("ix_os_coverage_tenant_collection", "tenant_id",
              "collection_id", unique=True),
        Index("ix_os_coverage_tenant_asset", "tenant_id", "asset_id"),
    )

class OSTwinEdge(BaseModel, TenantScoped):
    """Digital Twin relationship edge derived from OS collection
    evidence (docs/os-kernel-intelligence/01_PRODUCT_SPEC.md §8).

    Every edge carries its provenance class and the evidence class that
    supports it. The engine emits ONLY provides/contains/anchors
    predicates — never 'uses', and never a predicate for an indicator:
    the twin vocabulary has no 'indicates', and inventing one would
    promote an indicator into a relationship claim. Same-host
    co-location never creates an edge.
    """

    __tablename__ = "os_twin_edges"
    __table_args__ = (
        Index("uq_os_twin_edges_tenant_edge", "tenant_id", "edge_id",
              unique=True),
        Index("ix_os_twin_edges_tenant_asset", "tenant_id", "asset_id"),
    )

    edge_id: Mapped[str] = mapped_column(String(80), nullable=False)
    run_id: Mapped[str] = mapped_column(String(80), nullable=False,
                                        index=True)
    asset_id: Mapped[str] = mapped_column(String(80), nullable=False)
    source: Mapped[str] = mapped_column(String(160), nullable=False)
    predicate: Mapped[str] = mapped_column(String(40), nullable=False)
    target: Mapped[str] = mapped_column(String(160), nullable=False)
    provenance: Mapped[str] = mapped_column(String(40), nullable=False)
    evidence_class: Mapped[str] = mapped_column(String(30),
                                                nullable=False)
    evidence_source: Mapped[Optional[str]] = mapped_column(String(200))
    limitations: Mapped[Optional[Any]] = mapped_column(JSON)


class OSAssetCertificate(BaseModel, TenantScoped):
    """Collected certificate METADATA (OS-CRYPTO-008's source, §7).

    PUBLIC certificate attributes only — private keys are NEVER
    collected, exported, displayed or stored. Unparseable validity
    dates are stored as UNKNOWN — never 'not expired' (§2.1).
    """

    __tablename__ = "os_certificates"
    __table_args__ = (
        Index("ix_os_certificates_tenant_collected",
              "tenant_id", "collected_at"),
    )

    certificate_id: Mapped[str] = mapped_column(String(80),
                                                nullable=False,
                                                unique=True)
    collection_id: Mapped[str] = mapped_column(String(80),
                                               nullable=False)
    asset_id: Mapped[str] = mapped_column(String(80), nullable=False)
    subject: Mapped[str] = mapped_column(String(512), nullable=False,
                                         default="unknown")
    issuer: Mapped[str] = mapped_column(String(512), nullable=False,
                                        default="unknown")
    not_before: Mapped[Optional[str]] = mapped_column(String(64))
    not_after: Mapped[Optional[str]] = mapped_column(String(64))
    thumbprint_sha256: Mapped[Optional[str]] = mapped_column(
        String(128))
    public_key_algorithm: Mapped[Optional[str]] = mapped_column(
        String(64))
    public_key_bits: Mapped[Optional[int]] = mapped_column(Integer)
    evidence_class: Mapped[str] = mapped_column(String(30),
                                                nullable=False)
    evidence_source: Mapped[Optional[str]] = mapped_column(
        String(200))
    limitations: Mapped[Optional[Any]] = mapped_column(JSON)
    collected_at: Mapped[datetime] = mapped_column(DateTime,
                                                   nullable=False)
