"""Deterministic automation safety layer (no AI/ML).

Every automated action is classified on the observe->analyze->recommend->approve
->execute->verify ladder and assigned a risk level. The engine never performs a
write/change action automatically: actions above the ``recommend`` tier require an
explicit, recorded human approval before an executor may run them. This makes the
automation incapable of making destructive changes to production by itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class ActionTier(str, Enum):
    OBSERVE = "OBSERVE"        # read-only, always auto
    ANALYZE = "ANALYZE"        # derived computation, always auto
    RECOMMEND = "RECOMMEND"    # produce a suggestion/ticket/alert, auto
    APPROVE = "APPROVE"        # needs human sign-off (produces a gate)
    EXECUTE = "EXECUTE"        # performs a change — only after approval
    VERIFY = "VERIFY"          # post-change verification read


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


#: action -> (tier, risk). Anything that changes production requires approval.
ACTION_POLICY: dict[str, tuple[ActionTier, RiskLevel]] = {
    # read / derive / notify — safe to run automatically
    "targeted_rescan": (ActionTier.OBSERVE, RiskLevel.LOW),
    "update_cbom": (ActionTier.ANALYZE, RiskLevel.LOW),
    "create_alert": (ActionTier.RECOMMEND, RiskLevel.LOW),
    "notify_webhook": (ActionTier.RECOMMEND, RiskLevel.LOW),
    "notify_crypto_team": (ActionTier.RECOMMEND, RiskLevel.LOW),
    "add_pqc_queue": (ActionTier.RECOMMEND, RiskLevel.MEDIUM),
    "add_to_pqc_queue": (ActionTier.RECOMMEND, RiskLevel.MEDIUM),
    "create_migration_task": (ActionTier.RECOMMEND, RiskLevel.MEDIUM),
    "create_ticket": (ActionTier.RECOMMEND, RiskLevel.MEDIUM),
    # changes — gated behind human approval
    "request_approval": (ActionTier.APPROVE, RiskLevel.MEDIUM),
    "apply_remediation": (ActionTier.EXECUTE, RiskLevel.HIGH),
    "config_change": (ActionTier.EXECUTE, RiskLevel.HIGH),
    "firmware_update": (ActionTier.EXECUTE, RiskLevel.CRITICAL),
    "disable_asset": (ActionTier.EXECUTE, RiskLevel.CRITICAL),
}


@dataclass
class ActionDecision:
    action: str
    tier: str
    risk: str
    auto_permitted: bool
    requires_approval: bool
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action, "tier": self.tier, "risk": self.risk,
            "auto_permitted": self.auto_permitted,
            "requires_approval": self.requires_approval, "reason": self.reason,
        }


def classify_action(action: str) -> ActionDecision:
    if action not in ACTION_POLICY:
        # unknown actions fail closed: treat as needing approval, never auto-run
        return ActionDecision(action, ActionTier.APPROVE.value, RiskLevel.HIGH,
                              auto_permitted=False, requires_approval=True,
                              reason="unknown action: fail-closed, human review required")
    tier, risk = ACTION_POLICY[action]
    auto = tier in (ActionTier.OBSERVE, ActionTier.ANALYZE, ActionTier.RECOMMEND)
    return ActionDecision(
        action=action, tier=tier.value, risk=risk.value,
        auto_permitted=auto, requires_approval=not auto,
        reason=("read/derive/notify — automatic" if auto
                else "production change — human approval required before execution"),
    )


def partition_actions(actions: list[str]) -> dict[str, Any]:
    """Split emitted actions into auto-run vs approval-gated (fail-closed)."""
    auto: list[ActionDecision] = []
    gated: list[ActionDecision] = []
    for a in actions:
        decision = classify_action(a)
        (auto if decision.auto_permitted else gated).append(decision)
    return {
        "auto": [d.as_dict() for d in auto],
        "requires_approval": [d.as_dict() for d in gated],
        "all_safe_without_approval": len(gated) == 0,
    }
