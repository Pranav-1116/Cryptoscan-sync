"""
ALGORITHM_IN_LIST condition evaluator.
Fails if the normalized algorithm is in the forbidden list.
"""

from __future__ import annotations

import logging
from typing import Any

from policy.conditions.base_condition import BaseCondition, EvaluationOutcome
from policy.models.normalization_rule import AlgorithmInListParams

logger = logging.getLogger(__name__)


class AlgorithmInListCondition(BaseCondition):
    """
    Evaluates: normalized_crypto.algorithm IN algorithm_list → FAIL

    Used for:
      - Forbidden algorithm detection (DES, MD5, RC4, etc.)
      - Quantum-vulnerable algorithm detection

    Example rule YAML::

        condition:
          type: ALGORITHM_IN_LIST
          parameters:
            algorithm_list:
              - DES
              - 3DES
              - RC4
              - MD5
              - SHA-1
    """

    CONDITION_TYPE = "ALGORITHM_IN_LIST"

    def evaluate(
        self,
        evidence_data: dict[str, Any],
        params: dict[str, Any],
    ) -> EvaluationOutcome:
        """
        Evaluate the ALGORITHM_IN_LIST condition.

        Args:
            evidence_data: Flattened evidence record fields including
                           'algorithm', 'normalized_crypto', etc.
            params: Raw parameters dict from rule YAML.

        Returns:
            EvaluationOutcome with result and message.
        """
        typed_params = AlgorithmInListParams.model_validate(params)
        forbidden_set = {a.upper() for a in typed_params.algorithm_list}

        # Resolve algorithm from evidence (prefer normalized form)
        algorithm = self._resolve_algorithm(evidence_data)

        if algorithm is None:
            return EvaluationOutcome(
                result="NOT_APPLICABLE",
                message="Algorithm could not be determined from evidence record",
            )

        algorithm_upper = algorithm.upper()

        if algorithm_upper in forbidden_set:
            return EvaluationOutcome(
                result="FAIL",
                message=(
                    f"Algorithm '{algorithm}' is in the forbidden algorithm list. "
                    f"Forbidden algorithms: {sorted(typed_params.algorithm_list)}"
                ),
            )

        return EvaluationOutcome(
            result="PASS",
            message=f"Algorithm '{algorithm}' is not in the forbidden algorithm list",
        )

    @staticmethod
    def _resolve_algorithm(evidence_data: dict[str, Any]) -> str | None:
        """
        Resolve the canonical algorithm name from evidence data.
        Priority: normalized_crypto.algorithm > algorithm column.
        """
        # Try normalized crypto first
        normalized = evidence_data.get("normalized_crypto") or {}
        if isinstance(normalized, dict):
            algo = normalized.get("algorithm")
            if algo and algo != "UNKNOWN":
                return algo

        # Fall back to raw algorithm column
        raw_algo = evidence_data.get("algorithm")
        if raw_algo:
            return raw_algo

        return None