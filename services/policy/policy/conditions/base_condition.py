"""
Abstract base class for all policy condition evaluators.
"""

from __future__ import annotations

import re
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


def _canon(name: str) -> str:
    """Spelling-insensitive key: 'TLS 1.0' == 'TLS1.0' == 'TLSv1.0', 'SHA-1' == 'SHA1', '3DES' == 'TripleDES'."""
    key = re.sub(r"[\s\-_]", "", str(name).upper())
    key = re.sub(r"^(TLS|SSL|DTLS)V(?=\d)", r"\1", key)
    return {"TRIPLEDES": "3DES", "DESEDE": "3DES", "TDES": "3DES", "TDEA": "3DES", "ARCFOUR": "RC4", "ARC4": "RC4", "TLS1": "TLS1.0", "TLSV1": "TLS1.0"}.get(key, key)


def algorithm_names(evidence_data: dict[str, Any]) -> list[str]:
    """Every spelling the evidence carries for its algorithm, most specific first.

    The normaliser stores a display name (``TLS 1.0``) *and* a standard name (``TLS1.0``); the scanner's own
    name lives in ``finding_data.crypto.algorithm``. A rule list written as ``TLS1.0`` must hit all of them —
    a policy that PASSes TLS 1.0 because of a space is not a policy.
    """
    names: list[str] = []
    normalized = evidence_data.get("normalized_crypto") or {}
    if isinstance(normalized, dict):
        for k in ("standard_name", "algorithm"):
            v = normalized.get(k)
            if v and v != "UNKNOWN":
                names.append(str(v))
    v = evidence_data.get("algorithm")
    if v and v != "UNKNOWN":
        names.append(str(v))
    fd = evidence_data.get("finding_data") or {}
    crypto = fd.get("crypto") if isinstance(fd, dict) else None
    if isinstance(crypto, dict) and crypto.get("algorithm") and crypto["algorithm"] != "UNKNOWN":
        names.append(str(crypto["algorithm"]))
    out: list[str] = []
    for n in names:
        if n not in out:
            out.append(n)
    return out


def algorithm_matches(evidence_data: dict[str, Any], candidates: set[str] | list[str] | str) -> str | None:
    """The evidence spelling that matches one of ``candidates`` (spelling-insensitive), else None."""
    wanted = {_canon(c) for c in ([candidates] if isinstance(candidates, str) else candidates)}
    for n in algorithm_names(evidence_data):
        if _canon(n) in wanted:
            return n
    return None


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