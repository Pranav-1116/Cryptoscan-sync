"""Deterministic automation orchestrator (no AI/ML).

Binds the pieces into one decision: given an event, produce an automation plan
that names the scanners to run, the rules that matched, the playbook to follow,
the actions that may run automatically, and the actions that require human
approval. The orchestrator never changes production itself — it emits a plan;
executors run only the auto-permitted steps, and approval-gated steps wait.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from automation.playbooks import all_playbooks, playbook_for_event
from automation.rules_engine import AutomationRule, match_event
from automation.safety import partition_actions
from automation.scanner_selection import select_scanners


@dataclass
class AutomationPlan:
    event_kind: str
    asset_id: str | None
    scanners: list[str]
    scanner_reasons: dict[str, str]
    matched_rules: list[dict[str, Any]]
    playbook: dict[str, Any] | None
    auto_actions: list[dict[str, Any]]
    requires_approval: list[dict[str, Any]]
    needs_human: bool
    recommended_tier: str
    produced_at: str = field(default="")

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_kind": self.event_kind,
            "asset_id": self.asset_id,
            "scanners": self.scanners,
            "scanner_reasons": self.scanner_reasons,
            "matched_rules": self.matched_rules,
            "playbook": self.playbook,
            "auto_actions": self.auto_actions,
            "requires_approval": self.requires_approval,
            "needs_human": self.needs_human,
            "recommended_tier": self.recommended_tier,
            "produced_at": self.produced_at,
        }


def _highest_tier(actions: list[dict[str, Any]]) -> str:
    order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    best = "LOW"
    for a in actions:
        if order.get(a.get("risk", "LOW"), 0) > order[best]:
            best = a["risk"]
    return best


def build_plan(event_kind: str, event: dict[str, Any],
               rules: list[AutomationRule] | None = None,
               *, select_scanners_for: dict[str, Any] | None = None) -> AutomationPlan:
    """Produce a deterministic automation plan for an event.

    ``event`` is the event payload; ``select_scanners_for`` optionally provides
    the full asset record for scanner auto-selection (otherwise the event's data
    is used).
    """
    rules = rules or []
    matched = match_event(rules, event_kind, event)

    # gather actions: from matched rules + the mapped playbook
    actions: list[str] = []
    for m in matched:
        actions.extend(m.actions)
    playbook = playbook_for_event(event_kind)
    playbook_dict = None
    if playbook is not None:
        playbook_dict = playbook.as_dict()
        actions.extend(s.action for s in playbook.steps)
    # de-duplicate while preserving order
    seen: set[str] = set()
    unique_actions = [a for a in actions if not (a in seen or seen.add(a))]

    partitioned = partition_actions(unique_actions)

    # scanner auto-selection (for discovery/scan events, run only relevant scanners)
    scanners: list[str] = []
    scanner_reasons: dict[str, str] = {}
    asset = select_scanners_for if select_scanners_for is not None else event.get("asset") or event.get("data") or {}
    if isinstance(asset, dict) and asset:
        sel = select_scanners(asset)
        scanners = sel.scanners
        scanner_reasons = sel.reasons

    # default safe behavior: a crypto/asset event should at least rescan + update CBOM
    if not scanners and isinstance(asset, dict):
        sel = select_scanners(asset or {"id": event.get("asset_id"), "asset_kind": "host"})
        scanners = sel.scanners
        scanner_reasons = sel.reasons

    return AutomationPlan(
        event_kind=event_kind,
        asset_id=str(event.get("asset_id") or event.get("id") or (asset or {}).get("id")),
        scanners=scanners,
        scanner_reasons=scanner_reasons,
        matched_rules=[m.as_dict() for m in matched],
        playbook=playbook_dict,
        auto_actions=partitioned["auto"],
        requires_approval=partitioned["requires_approval"],
        needs_human=not partitioned["all_safe_without_approval"],
        recommended_tier=_highest_tier(partitioned["auto"] + partitioned["requires_approval"]),
        produced_at=datetime.now(timezone.utc).isoformat(),
    )


def known_rules_from_dicts(rule_dicts: list[dict[str, Any]]) -> list[AutomationRule]:
    return [AutomationRule.from_dict(d) for d in rule_dicts]


def known_playbooks() -> list[dict[str, Any]]:
    return [p.as_dict() for p in all_playbooks()]
