"""P1 enterprise layer: policy-as-code, compliance, ITSM tickets, CMDB/SIEM
integrations, regions/DR, and the crypto knowledge registry.

All deterministic/metadata-only. Integration rows hold provider config and
non-secret references; signed air-gapped packages carry content hashes.
"""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel

# --------------------------------------------------------------------------- #
# Policy-as-code (versioned, auditable)
# --------------------------------------------------------------------------- #

POLICY_LAYERS = ("sector", "region", "organization", "control", "risk")
POLICY_VERDICTS = ("PASS", "FAIL", "WARN", "NOT_APPLICABLE")


class PolicyDocument(BaseModel):
    """A versioned policy-as-code document (one layer of the policy stack)."""

    __tablename__ = "ent_policies"

    name: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    layer: Mapped[str] = mapped_column(String(20), nullable=False, default="organization", index=True)
    sector: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    region: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    version: Mapped[str] = mapped_column(String(32), nullable=False, default="v0")
    rules: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by: Mapped[str | None] = mapped_column(String(120), nullable=True)


class PolicyEvaluation(BaseModel):
    """An immutable evaluation record (target -> verdict) for audit."""

    __tablename__ = "ent_policy_evaluations"

    policy_version: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(40), nullable=False)  # finding/asset
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    verdict: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    results: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


# --------------------------------------------------------------------------- #
# Compliance intelligence
# --------------------------------------------------------------------------- #

COMPLIANCE_STATES = ("COMPLIANT", "GAP", "NOT_EVIDENCED", "NOT_APPLICABLE")


class ComplianceControl(BaseModel):
    """A requirement/control mapped to a framework and in-scope assets."""

    __tablename__ = "ent_compliance_controls"

    framework: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    control_id: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    title: Mapped[str | None] = mapped_column(Text, nullable=True)
    sector: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    assets: Mapped[list] = mapped_column(JSON, nullable=False, default=list)


class ComplianceStatus(BaseModel):
    """A point-in-time control evaluation snapshot for audit/history."""

    __tablename__ = "ent_compliance_status"

    framework: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    control_id: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    open_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    evidence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    compliance_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    coverage_pct: Mapped[float | None] = mapped_column(Float, nullable=True)


# --------------------------------------------------------------------------- #
# ITSM tickets
# --------------------------------------------------------------------------- #

TICKET_STATES = ("open", "triaged", "assigned", "in_progress", "in_migration",
                 "validation", "resolved", "closed", "reopened")


class Ticket(BaseModel):
    """A finding converted into a tracked ITSM work item."""

    __tablename__ = "ent_tickets"

    provider: Mapped[str] = mapped_column(String(30), nullable=False, default="manual")
    external_ref: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    finding_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    asset_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    assignee: Mapped[str | None] = mapped_column(String(120), nullable=True)
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="open", index=True)
    history: Mapped[list] = mapped_column(JSON, nullable=False, default=list)


# --------------------------------------------------------------------------- #
# Integrations (CMDB / ITSM / SIEM) — provider config (no secrets)
# --------------------------------------------------------------------------- #

INTEGRATION_KINDS = ("cmdb", "itsm", "siem", "soar")


class Integration(BaseModel):
    """A registered external integration. Config is non-secret (endpoint URL,
    provider, project); credentials live in the vault and are referenced."""

    __tablename__ = "ent_integrations"

    kind: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(40), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    endpoint: Mapped[str | None] = mapped_column(Text, nullable=True)
    config: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    credential_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    last_sync_at: Mapped[str | None] = mapped_column(String(40), nullable=True)
    last_sync_status: Mapped[str | None] = mapped_column(String(20), nullable=True)


# --------------------------------------------------------------------------- #
# Regions / DR
# --------------------------------------------------------------------------- #


class Region(BaseModel):
    """A deployment/processing region with residency and DR posture."""

    __tablename__ = "ent_regions"

    code: Mapped[str] = mapped_column(String(20), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    is_primary: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    healthy: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    rpo_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    rto_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    last_backup_at: Mapped[str | None] = mapped_column(String(40), nullable=True)


# --------------------------------------------------------------------------- #
# Crypto knowledge registry (overridable, updatable like a signature pack)
# --------------------------------------------------------------------------- #


class CryptoKnowledgeEntry(BaseModel):
    """An organization override/addition to the built-in crypto KB."""

    __tablename__ = "ent_crypto_kb"

    algorithm: Mapped[str] = mapped_column(String(120), nullable=False, unique=True, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    category: Mapped[str | None] = mapped_column(String(40), nullable=True)
    pqc: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    migration_candidate: Mapped[str | None] = mapped_column(Text, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
