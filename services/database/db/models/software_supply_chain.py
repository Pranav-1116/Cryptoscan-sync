"""Explicit, write-once release identity and deployment assertions.

An SBOM document digest is never an executable/image digest. Both are retained.
Scope keys make platform (NULL tenant) uniqueness and exact-estate reads explicit.
"""
from __future__ import annotations

from sqlalchemy import CheckConstraint, ForeignKey, ForeignKeyConstraint, Integer, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped
from db.models.relationship_lifecycle import RelationshipLifecycle


class SoftwareArtifact(BaseModel, TenantScoped):
    __tablename__ = "software_artifacts"
    __table_args__ = (
        CheckConstraint("scope_key = CASE WHEN tenant_id IS NULL THEN 'platform' ELSE 'tenant:' || tenant_id END",
                        name="ck_software_artifacts_scope_owner"),
        UniqueConstraint("scope_key", "digest", name="uq_software_artifact_scope_digest"),
        UniqueConstraint("scope_key", "id", name="uq_software_artifact_scope_id"),
    )
    scope_key: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    digest: Mapped[str] = mapped_column(String(71), nullable=False, index=True)
    media_type: Mapped[str] = mapped_column(String(120), nullable=False)
    identity_source: Mapped[str] = mapped_column(String(30), nullable=False)
    byte_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    evidence_ref: Mapped[str] = mapped_column(String(500), nullable=False)
    created_by: Mapped[str] = mapped_column(String(100), nullable=False)


class ReleaseSbomBinding(BaseModel, TenantScoped, RelationshipLifecycle):
    __tablename__ = "release_sbom_bindings"
    __table_args__ = (
        CheckConstraint("scope_key = CASE WHEN tenant_id IS NULL THEN 'platform' ELSE 'tenant:' || tenant_id END",
                        name="ck_release_sbom_bindings_scope_owner"),
        ForeignKeyConstraint(["scope_key", "artifact_id"],
                             ["software_artifacts.scope_key", "software_artifacts.id"]),
        UniqueConstraint("scope_key", "artifact_id", "sbom_artifact_id", name="uq_release_sbom_binding"),
    )
    scope_key: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    artifact_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    sbom_artifact_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    sbom_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    components: Mapped[list] = mapped_column(JSON, nullable=False)
    component_count: Mapped[int] = mapped_column(Integer, nullable=False)
    unresolved_component_count: Mapped[int] = mapped_column(Integer, nullable=False)
    assertion_source: Mapped[str] = mapped_column(String(30), nullable=False)
    evidence_ref: Mapped[str] = mapped_column(String(500), nullable=False)
    created_by: Mapped[str] = mapped_column(String(100), nullable=False)


class SoftwareDeployment(BaseModel, TenantScoped, RelationshipLifecycle):
    __tablename__ = "software_deployments"
    __table_args__ = (
        CheckConstraint("scope_key = CASE WHEN tenant_id IS NULL THEN 'platform' ELSE 'tenant:' || tenant_id END",
                        name="ck_software_deployments_scope_owner"),
        ForeignKeyConstraint(["scope_key", "artifact_id"],
                             ["software_artifacts.scope_key", "software_artifacts.id"]),
        UniqueConstraint("scope_key", "deployment_key", name="uq_software_deployment_key"),
    )
    scope_key: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    artifact_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    system_id: Mapped[str] = mapped_column(String(36), ForeignKey("systems.id"), nullable=False, index=True)
    deployment_key: Mapped[str] = mapped_column(String(300), nullable=False)
    environment: Mapped[str] = mapped_column(String(60), nullable=False)
    assertion_source: Mapped[str] = mapped_column(String(30), nullable=False)
    evidence_ref: Mapped[str] = mapped_column(String(500), nullable=False)
    created_by: Mapped[str] = mapped_column(String(100), nullable=False)
