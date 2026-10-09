"""Tenant-scoped runtime overrides for policy-pack rules (audit 05).

The YAML rule pack under ``policy/rule_definitions`` is the reviewed baseline,
but an estate needs a controlled way to say "this rule is accepted-risk here"
or "this rule must be CRITICAL here" without forking the pack. Overrides live
in the database (auditable, tenant-scoped, revertible) and are applied on top
of the pack at evaluation time — the pack itself is never edited.

Design constraints:

* one override per (tenant, rule_id) — the unique constraint plus the ORM
  tenant guard make the upsert unambiguous;
* ``enabled=False`` disables a rule for this tenant; ``severity`` overrides
  the rule's severity when set (NULL = keep pack severity);
* the API surface is admin-only (``PUT/DELETE /policy/rules/{id}/override``)
  because flipping a compliance rule is a compliance decision, and
  ``GET /policy/rules`` reports pack + override + effective state side by
  side so a reviewer can always see what was changed;
* the worker's policy stage applies the same overrides through
  ``policy.core.overrides.apply_overrides`` — one helper, used by both the
  API listing and the evaluation path, so what you see is what runs.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class PolicyRuleOverride(BaseModel, TenantScoped):
    __tablename__ = "policy_rule_overrides"
    __table_args__ = (UniqueConstraint("tenant_id", "rule_id", name="uq_policy_rule_override"),)

    rule_id: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    # None (SQL NULL) = keep the pack's severity; otherwise a pack severity
    # value (INFO/WARN/CRITICAL — validated by the API, not the column).
    severity: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    # tri-state is unnecessary: an override row exists to *change* the pack.
    # Disabling is `enabled=False`; deleting the row restores pack behavior.
    enabled: Mapped[bool] = mapped_column(nullable=False, default=True)
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    updated_by: Mapped[str] = mapped_column(String(100), nullable=False, default="system")
