"""COMPLEX policy condition — scoped multi-clause evaluation."""

from __future__ import annotations

from typing import Any

from policy.conditions.base_condition import BaseCondition, EvaluationOutcome


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(item) for item in value]


def _scopes(evidence: dict[str, Any]) -> set[str]:
    raw = (
        evidence.get("compliance_scopes")
        or evidence.get("scopes")
        or (evidence.get("finding_data") or {}).get("compliance_scopes")
        or []
    )
    return {str(item).upper() for item in _as_list(raw)}


class ComplexCondition(BaseCondition):
    CONDITION_TYPE = "COMPLEX"

    def evaluate(self, evidence_data: dict[str, Any], params: dict[str, Any]) -> EvaluationOutcome:
        required = {item.upper() for item in _as_list(params.get("required_scopes"))}
        if required and not (required & _scopes(evidence_data)):
            return EvaluationOutcome(
                result="NOT_APPLICABLE",
                message=f"Finding is outside required scopes {sorted(required)}",
            )

        algorithm = str(evidence_data.get("algorithm") or "").upper()
        purpose = str(evidence_data.get("purpose") or "").upper()
        mode = str(evidence_data.get("mode") or "").upper()
        key_size = evidence_data.get("key_size")
        if_purpose = {item.upper() for item in _as_list(params.get("if_purpose"))}
        if if_purpose and purpose not in if_purpose:
            return EvaluationOutcome(
                result="NOT_APPLICABLE",
                message=f"Purpose {purpose or 'UNKNOWN'} is outside {sorted(if_purpose)}",
            )

        forbidden = {item.upper() for item in _as_list(params.get("forbidden_algorithms"))}
        if algorithm and algorithm in forbidden:
            return EvaluationOutcome(
                result="FAIL",
                message=f"Algorithm {algorithm} is forbidden by this control",
            )

        forbidden_purposes = {item.upper() for item in _as_list(params.get("forbidden_purposes"))}
        if purpose and purpose in forbidden_purposes:
            return EvaluationOutcome(
                result="FAIL",
                message=f"Purpose {purpose} is forbidden for {algorithm or 'this algorithm'}",
            )

        required_algos = {item.upper() for item in _as_list(params.get("require_algorithms"))}
        if required_algos and algorithm and algorithm not in required_algos:
            return EvaluationOutcome(
                result="FAIL",
                message=f"Algorithm {algorithm} is not in the approved set {sorted(required_algos)}",
            )

        required_modes = {item.upper() for item in _as_list(params.get("require_modes"))}
        if required_modes and mode and mode not in required_modes:
            return EvaluationOutcome(
                result="FAIL",
                message=f"Mode {mode} is not approved; expected one of {sorted(required_modes)}",
            )
        if required_modes and not mode and params.get("mode_required"):
            return EvaluationOutcome(
                result="FAIL",
                message="An approved authenticated mode is required but none was declared",
            )

        min_key = params.get("min_key_size")
        if min_key is not None and key_size is not None and int(key_size) < int(min_key):
            return EvaluationOutcome(
                result="FAIL",
                message=f"Key size {key_size} is below required minimum {min_key}",
            )

        return EvaluationOutcome(result="PASS", message="Complex control requirements are satisfied")
