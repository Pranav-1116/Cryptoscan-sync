"""Policy rule catalogue (read-only)."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends

from api.dependencies import get_current_user
from policy.core.engine import PolicyEngine

router = APIRouter(prefix="/policy", tags=["policy"])


@router.get("/rules")
def list_rules(user: str = Depends(get_current_user)):
    rules_dir = Path(__file__).resolve().parents[3] / "policy" / "rule_definitions"
    engine = PolicyEngine(str(rules_dir))
    rules = []
    for rule in engine.rule_set.rules:
        rules.append(
            {
                "rule_id": rule.rule_id,
                "rule_name": rule.rule_name,
                "severity": rule.severity,
                "standard_reference": rule.standard_reference,
                "enabled": rule.enabled,
                "condition_type": rule.condition.type,
            }
        )
    return {
        "rules": sorted(rules, key=lambda item: item["rule_id"]),
        "counts": engine.get_rule_count(),
        "pack_hash": engine.pack_hash(),
        "pack": engine.pack_descriptor(),
    }
