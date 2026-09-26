"""KEY_INVENTORY_ATTRIBUTE condition — policy over HSM / KMS / keystore / certificate export metadata.

Applies only to findings whose ``source.type`` is ``KEY_INVENTORY`` (everything else is NOT_APPLICABLE, so
the rules never fire on code findings). Reads ``finding_data.inventory.<attribute>`` and applies one operator:

    equals / in            — case-insensitive string match (``value`` / ``values``)
    contains               — substring, case-insensitive (``value``)
    is_true                — boolean attribute is truthy
    date_before_today      — ISO date attribute is in the past (expired)
    date_within_days       — ISO date attribute falls within the next ``days`` (expiring)
    older_than_days        — ISO date attribute is more than ``days`` ago (stale / no rotation)
    missing                — attribute absent

``result`` chooses the outcome when the operator matches (FAIL by default, WARN for advisories).
``require_attributes`` (optional list) makes the rule NOT_APPLICABLE unless all of them are present, e.g.
``[last_used]`` so a stale-key rule stays silent for exports that carry no usage dates.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Any

from policy.conditions.base_condition import BaseCondition, EvaluationOutcome

_OPERATORS = {"equals", "in", "contains", "is_true", "date_before_today", "date_within_days", "older_than_days", "missing"}


def _as_date(value: Any) -> date | None:
    if value in (None, ""):
        return None
    try:
        return datetime.fromisoformat(str(value)[:10]).date()
    except ValueError:
        return None


class KeyInventoryAttributeCondition(BaseCondition):
    CONDITION_TYPE = "KEY_INVENTORY_ATTRIBUTE"

    def evaluate(self, evidence_data: dict[str, Any], params: dict[str, Any]) -> EvaluationOutcome:
        finding = evidence_data.get("finding_data") or evidence_data.get("finding") or {}
        if not isinstance(finding, dict) or ((finding.get("source") or {}).get("type")) != "KEY_INVENTORY":
            return EvaluationOutcome("NOT_APPLICABLE", "Not a key-inventory record")
        inventory = finding.get("inventory") or {}
        attribute = str(params.get("attribute") or "")
        operator = str(params.get("operator") or "equals")
        outcome = str(params.get("result") or "FAIL")
        if not attribute or operator not in _OPERATORS or outcome not in {"FAIL", "WARN"}:
            return EvaluationOutcome("WARN", f"Rule misconfigured: attribute={attribute!r} operator={operator!r} result={outcome!r}")
        for req in params.get("require_attributes") or []:
            if inventory.get(req) in (None, ""):
                return EvaluationOutcome("NOT_APPLICABLE", f"Export carries no '{req}'")
        if inventory.get("role"):  # side rows (certificate signature digest) are not the key itself
            return EvaluationOutcome("NOT_APPLICABLE", "Derived attribute row")

        label = inventory.get("key_label") or inventory.get("subject") or inventory.get("key_id") or "key"
        value = inventory.get(attribute)
        today = datetime.now(timezone.utc).date()
        matched = False
        detail = f"{attribute}={value!r}"
        if operator == "missing":
            matched = value in (None, "", [])
        elif value in (None, "", []):
            return EvaluationOutcome("NOT_APPLICABLE", f"Export carries no '{attribute}'")
        elif operator == "equals":
            matched = str(value).strip().lower() == str(params.get("value", "")).strip().lower()
        elif operator == "in":
            matched = str(value).strip().lower() in {str(v).strip().lower() for v in params.get("values") or []}
        elif operator == "contains":
            matched = str(params.get("value", "")).lower() in str(value).lower()
        elif operator == "is_true":
            matched = value is True or str(value).strip().lower() in {"true", "yes", "1", "y"}
        else:
            d = _as_date(value)
            if d is None:
                return EvaluationOutcome("NOT_APPLICABLE", f"'{attribute}' is not a date: {value!r}")
            days = int(params.get("days") or 0)
            if operator == "date_before_today":
                matched = d < today
                detail = f"{attribute}={d.isoformat()} ({(today - d).days} days ago)" if matched else detail
            elif operator == "date_within_days":
                matched = today <= d <= today + timedelta(days=days)
                detail = f"{attribute}={d.isoformat()} (in {(d - today).days} days)"
            elif operator == "older_than_days":
                matched = d < today - timedelta(days=days)
                detail = f"{attribute}={d.isoformat()} ({(today - d).days} days ago)"
        if matched:
            return EvaluationOutcome(outcome, f"{label}: {detail}")  # type: ignore[arg-type]
        return EvaluationOutcome("PASS", f"{label}: {detail} acceptable")
