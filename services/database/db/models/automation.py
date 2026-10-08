"""Automation engine persistence: configured rules and executed run records.

Deterministic automation (no AI/ML). Rules are declarative WHEN/IF/THEN config;
runs record the plan the engine produced for an event, including which actions
ran automatically and which required human approval. No secret material.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel, utcnow
from db.tenancy import TenantScoped


class AutomationRuleRow(BaseModel, TenantScoped):
    __tablename__ = "automation_rules"

    rule_id: Mapped[str] = mapped_column(String(80), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    when: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    #: JSON list of {field, operator, value}
    conditions: Mapped[list | None] = mapped_column(JSON, nullable=True)
    #: JSON list of action names
    actions: Mapped[list | None] = mapped_column(JSON, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="MEDIUM")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by: Mapped[str] = mapped_column(String(100), nullable=False, default="")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "name": self.name,
            "when": self.when,
            "if": self.conditions or [],
            "then": self.actions or [],
            "severity": self.severity,
            "enabled": self.enabled,
            "created_by": self.created_by,
        }


class AutomationRun(BaseModel, TenantScoped):
    __tablename__ = "automation_runs"

    event_kind: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    asset_id: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    scanners: Mapped[list | None] = mapped_column(JSON, nullable=True)
    auto_actions: Mapped[list | None] = mapped_column(JSON, nullable=True)
    gated_actions: Mapped[list | None] = mapped_column(JSON, nullable=True)
    matched_rules: Mapped[list | None] = mapped_column(JSON, nullable=True)
    playbook: Mapped[str | None] = mapped_column(String(80), nullable=True)
    needs_human: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    recommended_tier: Mapped[str] = mapped_column(String(16), nullable=False, default="LOW")
    triggered_by: Mapped[str] = mapped_column(String(100), nullable=False, default="system")
    governance_ref: Mapped[str | None] = mapped_column(String(120), nullable=True)
    executed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "event_kind": self.event_kind,
            "asset_id": self.asset_id,
            "scanners": self.scanners or [],
            "auto_actions": self.auto_actions or [],
            "gated_actions": self.gated_actions or [],
            "matched_rules": self.matched_rules or [],
            "playbook": self.playbook,
            "needs_human": self.needs_human,
            "recommended_tier": self.recommended_tier,
            "triggered_by": self.triggered_by,
            "governance_ref": self.governance_ref,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
        }


class CbomVersionRow(BaseModel, TenantScoped):
    """Immutable, content-addressed live CBOM version (deterministic)."""

    __tablename__ = "cbom_versions"
    __table_args__ = (UniqueConstraint("tenant_id", "version",
                                       name="uq_cbom_versions_tenant_version"),)

    version: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    # per-tenant numbering: two tenants each capture a version 1 — a global
    # UNIQUE here made the second one a database error (see migration 0071)

    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    parent_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    component_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    components: Mapped[list | None] = mapped_column(JSON, nullable=True)
    added: Mapped[list | None] = mapped_column(JSON, nullable=True)
    removed: Mapped[list | None] = mapped_column(JSON, nullable=True)
    created_by: Mapped[str] = mapped_column(String(100), nullable=False, default="system")

    def to_dict(self) -> dict:
        return {
            "id": self.id, "version": self.version, "fingerprint": self.fingerprint,
            "parent_fingerprint": self.parent_fingerprint,
            "component_count": self.component_count,
            "added": self.added or [], "removed": self.removed or [],
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
