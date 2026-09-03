"""ZELNX deterministic automation engine (no AI/ML).

Coordinates discovery-driven scanner auto-selection, risk-based adaptive
scheduling, event-driven rules (WHEN/IF/THEN), reusable playbooks, and a
fail-closed action safety/approval layer. Every decision is rule-based and
auditable; the engine recommends and orchestrates but never changes production
without human approval for EXECUTE-tier actions.
"""

from automation.engine import (
    AutomationPlan,
    build_plan,
    known_playbooks,
    known_rules_from_dicts,
)
from automation.playbooks import all_playbooks, playbook_for_event
from automation.rules_engine import (
    ACTIONS,
    EVENT_KINDS,
    AutomationRule,
    RulesError,
    evaluate_conditions,
    match_event,
)
from automation.safety import (
    ActionTier,
    classify_action,
    partition_actions,
)
from automation.scanner_selection import select_for_many, select_scanners
from automation.scheduling import due_assets, schedule_for_asset
from automation.sector_activation import activate_sector, available_sectors, normalize_sector
from automation.blast_radius import analyze_blast_radius
from automation.watchers.cert_expiry import assess_certificate, watch_certificates

__all__ = [
    "AutomationPlan", "build_plan", "known_playbooks", "known_rules_from_dicts",
    "all_playbooks", "playbook_for_event",
    "ACTIONS", "EVENT_KINDS", "AutomationRule", "RulesError",
    "evaluate_conditions", "match_event",
    "ActionTier", "classify_action", "partition_actions",
    "select_scanners", "select_for_many",
    "schedule_for_asset", "due_assets",
    "activate_sector", "available_sectors", "normalize_sector",
    "analyze_blast_radius",
    "assess_certificate", "watch_certificates",
]
