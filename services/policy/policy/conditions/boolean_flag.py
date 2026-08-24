"""BOOLEAN_FLAG condition."""

from __future__ import annotations

from typing import Any

from policy.conditions.base_condition import BaseCondition, EvaluationOutcome
from policy.models.policy_rule import BooleanFlagParameters


class BooleanFlagCondition(BaseCondition):
    CONDITION_TYPE = "BOOLEAN_FLAG"

    def evaluate(self, evidence_data: dict[str, Any], params: dict[str, Any]) -> EvaluationOutcome:
        typed = BooleanFlagParameters.model_validate(params)
        value = evidence_data.get(typed.field)
        if value is None:
            finding = evidence_data.get("finding_data") or evidence_data.get("finding") or {}
            metadata = finding.get("metadata") if isinstance(finding, dict) else {}
            if isinstance(metadata, dict):
                value = metadata.get(typed.field)
        if value is None:
            return EvaluationOutcome("PASS", f"Field '{typed.field}' not present")
        if bool(value) == typed.forbidden_value:
            return EvaluationOutcome(
                "FAIL",
                f"Field '{typed.field}' equals forbidden value {typed.forbidden_value}",
            )
        return EvaluationOutcome("PASS", f"Field '{typed.field}' is acceptable")
