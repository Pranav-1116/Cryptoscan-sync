"""Policy rule catalogue + tenant runtime overrides (audit 05).

The YAML pack under ``policy/rule_definitions`` stays the reviewed baseline.
What this router adds on top (previously the whole surface was read-only):

* ``GET /policy/rules`` — pack state, any override, and the *effective*
  state side by side, so a reviewer can always see what a tenant changed;
* ``PUT /policy/rules/{rule_id}/override`` — disable a rule for this tenant
  or change its severity (admin-only: flipping a compliance rule is a
  compliance decision, with an audit-log entry);
* ``DELETE /policy/rules/{rule_id}/override`` — revert to pack behavior.

The worker's evaluation stage applies the same rows through
``policy.core.overrides`` — one helper for both surfaces — so what the
listing shows is what the engine enforces.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, require_admin
from db.models.policy_rule_override import PolicyRuleOverride
from policy.core.engine import PolicyEngine
from policy.core.overrides import apply_overrides, load_override_rows

router = APIRouter(prefix="/policy", tags=["policy"])


class RuleOverrideRequest(BaseModel):
    enabled: bool = Field(..., description="False disables the rule for this tenant")
    severity: str | None = Field(
        None, description="Override severity (INFO/WARN/CRITICAL); omit to keep the pack's"
    )
    note: str | None = Field(None, description="Why this override exists (audit trail)")


def _rules_dir() -> Path:
    return Path(__file__).resolve().parents[3] / "policy" / "rule_definitions"


def _audit(db: Session, actor: str, action: str, rule_id: str, detail: dict | None) -> None:
    """Same audited-write pattern as the drift surface."""
    from db.repositories.user_repository import UserRepository

    UserRepository(db).audit(actor, action, target_type="policy_rule", target_id=rule_id, detail=detail)
    db.commit()


def _pack_state(engine: PolicyEngine) -> dict[str, dict]:
    """The pack's own enabled/severity per rule — read BEFORE overrides are
    applied, so the listing can always show pack vs effective side by side."""
    return {
        rule.rule_id: {"enabled": bool(rule.enabled), "severity": rule.severity}
        for rule in engine.rule_set.rules
    }


def _rule_out(rule, override: PolicyRuleOverride | None, pack: dict[str, dict]) -> dict:
    pack_row = pack.get(rule.rule_id, {})
    out = {
        "rule_id": rule.rule_id,
        "rule_name": rule.rule_name,
        "severity": rule.severity,
        "pack_enabled": pack_row.get("enabled", bool(rule.enabled)),
        "pack_severity": pack_row.get("severity"),
        "standard_reference": rule.standard_reference,
        "enabled": bool(rule.enabled),  # effective (post-override)
        "condition_type": rule.condition.type,
        "override": None,
    }
    if override is not None:
        out["override"] = {
            "enabled": bool(override.enabled),
            "severity": override.severity,
            "note": override.note,
            "updated_by": override.updated_by,
            "updated_at": override.updated_at.isoformat() if override.updated_at else None,
        }
    return out


@router.get("/rules")
def list_rules(user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    engine = PolicyEngine(str(_rules_dir()))
    pack = _pack_state(engine)
    overrides = {row.rule_id: row for row in load_override_rows(db)}
    if overrides:
        apply_overrides(engine, overrides.values())
    rules = [_rule_out(rule, overrides.get(rule.rule_id), pack) for rule in engine.rule_set.rules]
    return {
        "rules": sorted(rules, key=lambda item: item["rule_id"]),
        "counts": engine.get_rule_count(),
        "pack_hash": engine.pack_hash(),
        "pack": engine.pack_descriptor(),
        "override_count": len(overrides),
    }


@router.get("/rules/coverage")
def rule_test_coverage_surface(user: str = Depends(get_current_user)):
    """Per-rule test coverage matrix (audit 65 P0#4, round 28).

    Static analysis: which rules in the shipped packs are referenced by
    at least one policy test file. Uncovered is a review lead, not a
    proof of absence (whole-pack engine tests exercise rules indirectly).
    """
    from policy.rules.rule_coverage import rule_test_coverage

    return rule_test_coverage(_rules_dir(), _rules_dir().parent / "tests")


@router.get("/rules/conflicts")
def rule_conflicts(user: str = Depends(get_current_user),
                   db: Session = Depends(get_db_session)):
    """Cross-rule conflict analysis over the *effective* rule set (audit 65).

    Detects duplicate rule ids, exact duplicates, shadowed rules (a rule
    whose every fire is subsumed by a louder one), contradictory verdicts,
    and partial overlaps. Rules disabled by override are excluded before
    analysis, so an override can silence a conflict.
    """
    engine = PolicyEngine(str(_rules_dir()))
    overrides = {row.rule_id: row for row in load_override_rows(db)}
    if overrides:
        apply_overrides(engine, overrides.values())
    from policy.rules.rule_conflicts import detect_rule_conflicts

    conflicts = detect_rule_conflicts(engine.rule_set.rules)
    counts: dict[str, int] = {}
    for item in conflicts:
        counts[item["type"]] = counts.get(item["type"], 0) + 1
    return {
        "conflicts": conflicts,
        "counts": counts,
        "rule_count": len(engine.rule_set.rules),
        "pack_hash": engine.pack_hash(),
        "override_count": len(overrides),
    }


@router.put("/rules/{rule_id}/override")
def set_rule_override(
    rule_id: str,
    body: RuleOverrideRequest,
    user: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Create or update this tenant's override for one pack rule."""
    engine = PolicyEngine(str(_rules_dir()))
    if engine.get_rule(rule_id) is None:
        raise HTTPException(status_code=404, detail=f"Unknown rule_id {rule_id!r} — not in the pack")
    if body.severity is not None:
        allowed = {"INFO", "WARN", "CRITICAL", "HIGH", "MEDIUM", "LOW"}
        if str(body.severity).upper() not in allowed:
            raise HTTPException(
                status_code=422,
                detail=f"severity must be one of {sorted(allowed)} (got {body.severity!r})",
            )

    row = (
        db.query(PolicyRuleOverride)
        .filter(PolicyRuleOverride.rule_id == rule_id)
        .first()
    )
    if row is None:
        row = PolicyRuleOverride(rule_id=rule_id)
        db.add(row)
    row.enabled = bool(body.enabled)
    row.severity = str(body.severity).upper() if body.severity else None
    row.note = body.note
    row.updated_by = user
    row.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(row)

    _audit(
        db,
        user,
        "policy.rule_override_set",
        rule_id,
        {"enabled": row.enabled, "severity": row.severity, "note": body.note},
    )

    engine = PolicyEngine(str(_rules_dir()))
    pack = _pack_state(engine)
    overrides = {row.rule_id: row for row in load_override_rows(db)}
    apply_overrides(engine, overrides.values())
    rule = engine.get_rule(rule_id)
    return {
        "rule_id": rule_id,
        "rule": _rule_out(rule, overrides.get(rule_id), pack),
        "override": _rule_out(rule, overrides.get(rule_id), pack)["override"],
    }


@router.delete("/rules/{rule_id}/override")
def clear_rule_override(
    rule_id: str,
    user: str = Depends(require_admin),
    db: Session = Depends(get_db_session),
):
    """Revert one rule to pack behavior for this tenant."""
    row = (
        db.query(PolicyRuleOverride)
        .filter(PolicyRuleOverride.rule_id == rule_id)
        .first()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="No override exists for this rule")
    db.delete(row)
    db.commit()

    _audit(db, user, "policy.rule_override_cleared", rule_id, None)
    return {"rule_id": rule_id, "override": None, "pack_behavior_restored": True}
