"""ALGORITHM_MODE_WHITELIST condition."""

from __future__ import annotations

from typing import Any

from policy.conditions.base_condition import BaseCondition, EvaluationOutcome, algorithm_matches
from policy.models.policy_rule import AlgorithmModeWhitelistParameters


class AlgorithmModeWhitelistCondition(BaseCondition):
    CONDITION_TYPE = "ALGORITHM_MODE_WHITELIST"

    def evaluate(self, evidence_data: dict[str, Any], params: dict[str, Any]) -> EvaluationOutcome:
        typed = AlgorithmModeWhitelistParameters.model_validate(params)
        algorithm = evidence_data.get("algorithm") or ""
        normalized = evidence_data.get("normalized_crypto") or {}
        if isinstance(normalized, dict) and normalized.get("algorithm"):
            algorithm = normalized["algorithm"]
        if algorithm_matches(evidence_data, typed.algorithm) is None:
            return EvaluationOutcome("NOT_APPLICABLE", f"Rule applies only to {typed.algorithm}")

        mode = evidence_data.get("mode")
        if isinstance(normalized, dict) and normalized.get("mode"):
            mode = normalized["mode"]
        if not mode:
            return EvaluationOutcome("WARN", f"{algorithm} mode is not specified")

        mode_u = str(mode).upper()
        forbidden = {m.upper() for m in typed.forbidden_modes}
        approved = {m.upper() for m in typed.approved_modes}
        if mode_u in forbidden:
            return EvaluationOutcome("FAIL", f"{algorithm} mode {mode} is forbidden")
        if approved and mode_u not in approved:
            return EvaluationOutcome("FAIL", f"{algorithm} mode {mode} is not in the approved list")
        return EvaluationOutcome("PASS", f"{algorithm} mode {mode} is approved")
