"""ALGORITHM_IN_LIST condition."""

from __future__ import annotations

from typing import Any

from policy.conditions.base_condition import BaseCondition, EvaluationOutcome
from policy.models.policy_rule import AlgorithmInListParameters


class AlgorithmInListCondition(BaseCondition):
    CONDITION_TYPE = "ALGORITHM_IN_LIST"

    def evaluate(self, evidence_data: dict[str, Any], params: dict[str, Any]) -> EvaluationOutcome:
        typed = AlgorithmInListParameters.model_validate(params)
        forbidden = {a.upper() for a in typed.algorithm_list}
        algorithm = self._resolve_algorithm(evidence_data)
        if algorithm is None:
            return EvaluationOutcome("NOT_APPLICABLE", "Algorithm could not be determined")
        if algorithm.upper() in forbidden:
            return EvaluationOutcome(
                "FAIL",
                f"Algorithm '{algorithm}' is forbidden. List: {sorted(typed.algorithm_list)}",
            )
        return EvaluationOutcome("PASS", f"Algorithm '{algorithm}' is not forbidden")

    @staticmethod
    def _resolve_algorithm(evidence_data: dict[str, Any]) -> str | None:
        normalized = evidence_data.get("normalized_crypto") or {}
        if isinstance(normalized, dict) and normalized.get("algorithm"):
            algo = normalized["algorithm"]
            if algo != "UNKNOWN":
                return algo
        return evidence_data.get("algorithm")
