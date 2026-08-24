"""
Abstract base class for all policy condition evaluators.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Literal


EvaluationResultType = Literal["PASS", "FAIL", "WARN", "NOT_APPLICABLE"]


@dataclass(frozen=True)
class EvaluationOutcome:
    """
    Immutable outcome of a single condition evaluation.

    Attributes:
        result: One of PASS, FAIL, WARN, NOT_APPLICABLE.
        message: Human-readable explanation of the outcome.
    """

    result: EvaluationResultType
    message: str

    def __post_init__(self) -> None:
        allowed = {"PASS", "FAIL", "WARN", "NOT_APPLICABLE"}
        if self.result not in allowed:
            raise ValueError(
                f"EvaluationOutcome.result must be one of {allowed}, got '{self.result}'"
            )
        if not self.message.strip():
            raise ValueError("EvaluationOutcome.message must not be blank")


class BaseCondition(ABC):
    """
    Abstract base class for all policy condition evaluators.

    Each subclass implements one CONDITION_TYPE and is registered
    in the ConditionFactory.

    Subclasses must:
      1. Set CONDITION_TYPE class attribute (matches YAML 'type' field)
      2. Implement the evaluate() method
      3. Return an EvaluationOutcome (never raise)
    """

    CONDITION_TYPE: str  # Set by each subclass

    @abstractmethod
    def evaluate(
        self,
        evidence_data: dict[str, Any],
        params: dict[str, Any],
    ) -> EvaluationOutcome:
        """
        Evaluate this condition against evidence record data.

        Args:
            evidence_data: Flattened evidence record as dict. Contains:
                           - algorithm: str
                           - key_size: Optional[int]
                           - mode: Optional[str]
                           - purpose: Optional[str]
                           - is_hardcoded_key: bool
                           - normalized_crypto: dict (from JSONB column)
                           - finding_data: dict (full raw finding)
            params: Raw parameters dict from rule YAML condition.

        Returns:
            EvaluationOutcome — never raises; degrade to NOT_APPLICABLE on error.
        """

    def safe_evaluate(
        self,
        evidence_data: dict[str, Any],
        params: dict[str, Any],
    ) -> EvaluationOutcome:
        """
        Evaluate with error protection — returns NOT_APPLICABLE on exceptions.
        Called by the engine instead of evaluate() directly.
        """
        try:
            return self.evaluate(evidence_data, params)
        except Exception as exc:
            import logging
            logger = logging.getLogger(self.__class__.__module__)
            logger.exception(
                "Condition evaluation raised unexpected exception: %s "
                "(condition_type=%s, evidence=%s)",
                exc,
                self.CONDITION_TYPE,
                evidence_data.get("evidence_id", "?"),
            )
            return EvaluationOutcome(
                result="NOT_APPLICABLE",
                message=f"Evaluation error in {self.CONDITION_TYPE}: {exc}",
            )