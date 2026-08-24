"""COMPLEX policy condition — scoped multi-clause evaluation."""

from __future__ import annotations

from typing import Any

from policy.conditions.base_condition import BaseCondition, EvaluationOutcome
from policy.core.scope_resolver import as_scope_list, missing_scopes_message, scopes_apply


def _as_list(value: Any) -> list[str]:
    return as_scope_list(value)


def _scopes(evidence: dict[str, Any]) -> set[str]:
    from policy.core.scope_resolver import evidence_scopes

    return evidence_scopes(evidence)


def _truthy_flag(evidence: dict[str, Any], name: str) -> bool:
    if not name:
        return False
    finding = evidence.get("finding_data") if isinstance(evidence.get("finding_data"), dict) else {}
    extra = evidence.get("extra") if isinstance(evidence.get("extra"), dict) else {}
    for source in (evidence, finding, extra):
        if source.get(name) in {True, "true", "True", 1, "1", "yes"}:
            return True
    return False


class ComplexCondition(BaseCondition):
    CONDITION_TYPE = "COMPLEX"

    def evaluate(self, evidence_data: dict[str, Any], params: dict[str, Any]) -> EvaluationOutcome:
        if not scopes_apply(evidence_data, params.get("required_scopes")):
            return EvaluationOutcome(
                result="NOT_APPLICABLE",
                message=missing_scopes_message(params.get("required_scopes")),
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
        if_algorithms = {item.upper() for item in _as_list(params.get("if_algorithms"))}
        if if_algorithms and algorithm not in if_algorithms:
            return EvaluationOutcome(
                result="NOT_APPLICABLE",
                message=f"Algorithm {algorithm or 'UNKNOWN'} is outside {sorted(if_algorithms)}",
            )
        allow_flag = str(params.get("allow_if_true") or "").strip()
        if allow_flag and _truthy_flag(evidence_data, allow_flag):
            return EvaluationOutcome(
                result="PASS",
                message=f"Control waived because {allow_flag} is set",
            )
        if params.get("require_purpose") and purpose in {"", "UNKNOWN", "NONE"}:
            return EvaluationOutcome(
                result="FAIL",
                message="A documented cryptographic purpose is required",
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
