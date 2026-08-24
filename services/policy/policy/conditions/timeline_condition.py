"""TIMELINE policy condition — date-gated algorithm retirement."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from policy.conditions.base_condition import BaseCondition, EvaluationOutcome
from policy.conditions.complex_condition import _as_list, _scopes


def _parse_day(value: Any) -> date | None:
    if not value:
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    text = str(value)[:10]
    try:
        return date.fromisoformat(text)
    except ValueError:
        return None


class TimelineCondition(BaseCondition):
    CONDITION_TYPE = "TIMELINE"

    def evaluate(self, evidence_data: dict[str, Any], params: dict[str, Any]) -> EvaluationOutcome:
        required = {item.upper() for item in _as_list(params.get("required_scopes"))}
        if required and not (required & _scopes(evidence_data)):
            return EvaluationOutcome(
                result="NOT_APPLICABLE",
                message=f"Finding is outside required scopes {sorted(required)}",
            )

        algorithm = str(evidence_data.get("algorithm") or "").upper()
        purpose = str(evidence_data.get("purpose") or "").upper()
        if_purpose = {item.upper() for item in _as_list(params.get("if_purpose"))}
        if if_purpose and purpose not in if_purpose:
            return EvaluationOutcome(
                result="NOT_APPLICABLE",
                message=f"Purpose {purpose or 'UNKNOWN'} is outside timeline applicability",
            )

        retired = {item.upper() for item in _as_list(params.get("retired_algorithms"))}
        approved = {item.upper() for item in _as_list(params.get("approved_algorithms"))}
        if retired and algorithm not in retired:
            return EvaluationOutcome(
                result="NOT_APPLICABLE",
                message=f"{algorithm or 'UNKNOWN'} is not on the retirement list",
            )
        if approved and algorithm in approved:
            return EvaluationOutcome(result="PASS", message=f"{algorithm} remains approved on this timeline")

        today = _parse_day(evidence_data.get("evaluation_date")) or date.today()
        after = _parse_day(params.get("after") or params.get("retire_after"))
        warn_after = _parse_day(params.get("warn_after"))
        fail_result = str(params.get("after_result") or "FAIL").upper()
        if fail_result not in {"FAIL", "WARN"}:
            fail_result = "FAIL"

        if after and today >= after:
            return EvaluationOutcome(
                result=fail_result,  # type: ignore[arg-type]
                message=params.get("message")
                or f"{algorithm} is retired after {after.isoformat()} for {purpose or 'this purpose'}",
            )
        if warn_after and today >= warn_after:
            return EvaluationOutcome(
                result="WARN",
                message=params.get("warn_message")
                or f"{algorithm} must be replaced before {after.isoformat() if after else 'the deadline'}",
            )
        return EvaluationOutcome(result="PASS", message="Timeline control is not yet in force")
