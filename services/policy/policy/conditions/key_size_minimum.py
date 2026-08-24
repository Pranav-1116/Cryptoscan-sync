"""KEY_SIZE_MINIMUM condition."""

from __future__ import annotations

from typing import Any

from policy.conditions.base_condition import BaseCondition, EvaluationOutcome
from policy.models.policy_rule import KeySizeMinimumParameters


class KeySizeMinimumCondition(BaseCondition):
    CONDITION_TYPE = "KEY_SIZE_MINIMUM"

    def evaluate(self, evidence_data: dict[str, Any], params: dict[str, Any]) -> EvaluationOutcome:
        typed = KeySizeMinimumParameters.model_validate(params)
        target = typed.algorithm.upper()
        algorithm = (evidence_data.get("algorithm") or "")
        normalized = evidence_data.get("normalized_crypto") or {}
        if isinstance(normalized, dict) and normalized.get("algorithm"):
            algorithm = normalized["algorithm"]
        if not algorithm or algorithm.upper() != target:
            return EvaluationOutcome("NOT_APPLICABLE", f"Rule applies only to {target}")

        key_size = None
        if isinstance(normalized, dict) and normalized.get("key_size") is not None:
            key_size = int(normalized["key_size"])
        elif evidence_data.get("key_size") is not None:
            key_size = int(evidence_data["key_size"])

        if key_size is None:
            return EvaluationOutcome(
                "WARN",
                f"{target} key size unknown; minimum required is {typed.minimum_key_size} bits",
            )
        if key_size < typed.minimum_key_size:
            return EvaluationOutcome(
                "FAIL",
                f"{target} key size {key_size} is below minimum {typed.minimum_key_size}",
            )
        return EvaluationOutcome(
            "PASS",
            f"{target} key size {key_size} meets minimum {typed.minimum_key_size}",
        )
