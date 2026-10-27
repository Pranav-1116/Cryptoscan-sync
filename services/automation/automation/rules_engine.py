"""Deterministic automation rules engine (WHEN / IF / THEN), no AI/ML.

Administrators author declarative rules:

    WHEN   <event kind>            (e.g. crypto_asset_detected)
    IF     <all conditions hold>   (field/operator/value comparisons)
    THEN   <actions>               (alert, ticket, pqc_queue, migration_task, rescan, webhook)

The engine matches an incoming event against rule triggers, evaluates every
condition with a small fixed operator set (no expression language to misuse and
no model), and emits deterministic actions. Condition evaluation is pure and
side-effect free; the orchestrator decides how to execute each emitted action.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

#: event kinds a rule can trigger on.
EVENT_KINDS = frozenset({
    "crypto_asset_detected", "certificate_changed", "certificate_expiring",
    "new_asset", "asset_removed", "algorithm_changed", "library_upgraded",
    "firmware_changed", "cloud_config_changed", "vulnerable_library_detected",
    "drift_detected", "quantum_vulnerable_detected", "scan_completed",
    "anomaly_detected", "sla_breached", "connector_failed", "agent_offline",
    "any",
})

#: actions the engine may emit (orchestrator executes them).
ACTIONS = frozenset({
    "create_alert", "create_ticket", "add_pqc_queue", "create_migration_task",
    "targeted_rescan", "notify_webhook", "update_cbom", "notify_crypto_team",
    "add_to_pqc_queue", "request_approval",
})

VALID_OPERATORS = frozenset({
    "equals", "not_equals", "in", "not_in", "contains", "not_contains",
    "gt", "gte", "lt", "lte", "matches", "exists",
})

_SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


class RulesError(ValueError):
    pass


@dataclass(frozen=True)
class Condition:
    field: str
    operator: str
    value: Any = None

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Condition":
        field_ = str(d.get("field") or "").strip()
        op = str(d.get("operator") or "").strip()
        if not field_:
            raise RulesError("condition.field is required")
        if op not in VALID_OPERATORS:
            raise RulesError(f"unsupported operator {op!r}; valid: {sorted(VALID_OPERATORS)}")
        if op != "exists" and "value" not in d:
            raise RulesError(f"operator {op!r} requires a value")
        return Condition(field=field_, operator=op, value=d.get("value"))


@dataclass
class AutomationRule:
    id: str
    name: str
    when: str
    conditions: list[Condition] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    severity: str = "MEDIUM"
    enabled: bool = True

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "AutomationRule":
        rid = str(d.get("id") or d.get("rule_id") or "").strip()
        if not rid:
            raise RulesError("rule id is required")
        when = str(d.get("when") or "").strip()
        if when not in EVENT_KINDS:
            raise RulesError(f"unknown WHEN event {when!r}; valid: {sorted(EVENT_KINDS)}")
        raw_conditions = d.get("if") or d.get("conditions") or []
        if not isinstance(raw_conditions, list):
            raise RulesError("if/conditions must be a list")
        conditions = [Condition.from_dict(c) for c in raw_conditions]
        raw_actions = d.get("then") or d.get("actions") or []
        if isinstance(raw_actions, str):
            raw_actions = [raw_actions]
        if not isinstance(raw_actions, list) or not raw_actions:
            raise RulesError("then/actions must be a non-empty list")
        bad = [a for a in raw_actions if str(a) not in ACTIONS]
        if bad:
            raise RulesError(f"unknown actions {bad}; valid: {sorted(ACTIONS)}")
        severity = str(d.get("severity") or "MEDIUM").upper()
        return AutomationRule(
            id=rid, name=str(d.get("name") or rid), when=when,
            conditions=conditions, actions=[str(a) for a in raw_actions],
            severity=severity, enabled=bool(d.get("enabled", True)),
        )


def _get_field(event: dict[str, Any], path: str) -> Any:
    """Resolve a dotted field path from the event payload (and its 'data')."""
    sources = [event]
    if isinstance(event.get("data"), dict):
        sources.append(event["data"])
    for source in sources:
        cur: Any = source
        ok = True
        for part in path.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                ok = False
                break
        if ok:
            return cur
    return None


def _compare(actual: Any, op: str, expected: Any) -> bool:
    if op == "exists":
        return actual is not None
    if op == "equals":
        return str(actual).lower() == str(expected).lower()
    if op == "not_equals":
        return str(actual).lower() != str(expected).lower()
    if op == "in":
        return str(actual).lower() in {str(x).lower() for x in (expected or [])}
    if op == "not_in":
        return str(actual).lower() not in {str(x).lower() for x in (expected or [])}
    if op == "contains":
        try:
            return str(expected).lower() in str(actual).lower()
        except (TypeError, AttributeError):
            return False
    if op == "not_contains":
        try:
            return str(expected).lower() not in str(actual).lower()
        except (TypeError, AttributeError):
            return True
    if op in ("gt", "gte", "lt", "lte"):
        try:
            a = float(actual)
            b = float(expected)
        except (TypeError, ValueError):
            return False
        return {"gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b}[op]
    if op == "matches":
        try:
            return re.search(str(expected), str(actual)) is not None
        except re.error:
            return False
    return False


def evaluate_conditions(rule: AutomationRule, event: dict[str, Any]) -> bool:
    """All conditions must hold (AND semantics)."""
    for cond in rule.conditions:
        actual = _get_field(event, cond.field)
        if not _compare(actual, cond.operator, cond.value):
            return False
    return True


@dataclass
class MatchedRule:
    rule_id: str
    name: str
    actions: list[str]
    severity: str

    def as_dict(self) -> dict[str, Any]:
        return {"rule_id": self.rule_id, "name": self.name,
                "actions": self.actions, "severity": self.severity}


def match_event(rules: list[AutomationRule], event_kind: str,
                event: dict[str, Any]) -> list[MatchedRule]:
    """Return deterministic list of rules whose WHEN+IF match the event."""
    matched: list[MatchedRule] = []
    for rule in sorted((r for r in rules if r.enabled),
                       key=lambda r: (-_SEVERITY_ORDER.get(r.severity, 1), r.id)):
        if rule.when not in ("any", event_kind):
            continue
        if evaluate_conditions(rule, event):
            matched.append(MatchedRule(rule.id, rule.name, list(rule.actions), rule.severity))
    return matched
