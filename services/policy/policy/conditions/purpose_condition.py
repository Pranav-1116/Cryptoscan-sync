"""PURPOSE_IN_LIST — apply a rule only when the finding purpose matches."""

from __future__ import annotations

from typing import Any

from policy.conditions.base_condition import BaseCondition, EvaluationOutcome
from policy.core.scope_resolver import as_scope_list


class PurposeCondition(BaseCondition):
    CONDITION_TYPE = "PURPOSE_IN_LIST"

    def evaluate(self, evidence_data: dict[str, Any], params: dict[str, Any]) -> EvaluationOutcome:
        purpose = str(evidence_data.get("purpose") or "").upper()
        allowed = {item.upper() for item in as_scope_list(params.get("purpose_list") or params.get("purposes"))}
        forbidden = {item.upper() for item in as_scope_list(params.get("forbidden_purposes"))}
        if not allowed and not forbidden:
            return EvaluationOutcome(result="NOT_APPLICABLE", message="No purpose list configured")
        if forbidden and purpose in forbidden:
            return EvaluationOutcome(
                result="FAIL",
                message=f"Purpose {purpose or 'UNKNOWN'} is forbidden",
            )
        if allowed and purpose not in allowed:
            return EvaluationOutcome(
                result="NOT_APPLICABLE",
                message=f"Purpose {purpose or 'UNKNOWN'} is outside {sorted(allowed)}",
            )
        return EvaluationOutcome(result="PASS", message=f"Purpose {purpose} is permitted")
