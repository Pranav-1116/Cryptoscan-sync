"""
KEY_SIZE_MINIMUM condition evaluator.
Fails if the key size is below the required minimum for a given algorithm.
"""

from __future__ import annotations

import logging
from typing import Any

from policy.conditions.base_condition import BaseCondition, EvaluationOutcome
from policy.models.policy_rule import KeySizeMinimumParams

logger = logging.getLogger(__name__)


class KeySizeMinimumCondition(BaseCondition):
    """
    Evaluates: algorithm == target_algorithm AND key_size < minimum_key_size → FAIL

    Used for:
      - RSA minimum key size enforcement (must be ≥ 2048 bits)
      - AES minimum key size (must be ≥ 128 bits)
      - EC minimum curve size

    Example rule YAML::

        condition:
          type: KEY_SIZE_MINIMUM
          parameters:
            algorithm: RSA
            minimum_key_size: 2048
    """

    CONDITION_TYPE = "KEY_SIZE_MINIMUM"

    def evaluate(
        self,
        evidence_data: dict[str, Any],
        params: dict[str, Any],
    ) -> EvaluationOutcome:
        """
        Evaluate KEY_SIZE_MINIMUM condition.

        Returns NOT_APPLICABLE if:
          - Algorithm does not match target
          - Key size is not determinable
        """
        typed_params = KeySizeMinimumParams.model_validate(params)
        target_algorithm = typed_params.algorithm.upper()
        minimum_key_size = typed_params.minimum_key_size

        # Resolve algorithm
        algorithm = self._resolve_algorithm(evidence_data)
        if algorithm is None:
            return EvaluationOutcome(
                result="NOT_APPLICABLE",
                message="Algorithm could not be determined",
            )

        if algorithm.upper() != target_algorithm:
            return EvaluationOutcome(
                result="NOT_APPLICABLE",
                message=(
                    f"Algorithm '{algorithm}' does not match target '{target_algorithm}'"
                    f" — rule does not apply"
                ),
            )

        # Resolve key size
        key_size = self._resolve_key_size(evidence_data)

        if key_size is None:
            # Can't determine key size — warn rather than fail
            return EvaluationOutcome(
                result="WARN",
                message=(
                    f"Algorithm is '{target_algorithm}' but key size could not be "
                    f"determined. Minimum required: {minimum_key_size} bits."
                ),
            )

        if key_size < minimum_key_size:
            return EvaluationOutcome(
                result="FAIL",
                message=(
                    f"Key size {key_size} bits is below minimum {minimum_key_size} bits "
                    f"for algorithm '{target_algorithm}'"
                ),
            )

        return EvaluationOutcome(
            result="PASS",
            message=(
                f"Key size {key_size} bits meets minimum {minimum_key_size} bits "
                f"requirement for '{target_algorithm}'"
            ),
        )

    @staticmethod
    def _resolve_algorithm(evidence_data: dict[str, Any]) -> str | None:
        normalized = evidence_data.get("normalized_crypto") or {}
        if isinstance(normalized, dict):
            algo = normalized.get("algorithm")
            if algo:
                return algo
        return evidence_data.get("algorithm")

    @staticmethod
    def _resolve_key_size(evidence_data: dict[str, Any]) -> int | None:
        # Try normalized_crypto.key_size first
        normalized = evidence_data.get("normalized_crypto") or {}
        if isinstance(normalized, dict):
            ks = normalized.get("key_size")
            if ks is not None:
                try:
                    return int(ks)
                except (TypeError, ValueError):
                    pass

        # Fall back to raw key_size column
        raw_ks = evidence_data.get("key_size")
        if raw_ks is not None:
            try:
                return int(raw_ks)
            except (TypeError, ValueError):
                pass

        return None