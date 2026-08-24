"""
Confidence level calculator for crypto findings.

HIGH: Algorithm from string literal, direct (non-reflective) call
MEDIUM: Algorithm from local variable (traceable within method)
LOW: Algorithm from method parameter, field, or via reflection
"""

from __future__ import annotations

from scanner.models.enums import Confidence


class ConfidenceResult:
    """Result of confidence calculation."""

    def __init__(self, level: Confidence, reason: str):
        self.level = level
        self.reason = reason

    def __repr__(self) -> str:
        return f"ConfidenceResult(level={self.level}, reason={self.reason!r})"


def calculate_confidence(
    *,
    is_string_literal: bool,
    is_via_reflection: bool = False,
    is_from_parameter: bool = False,
    is_from_field: bool = False,
    is_from_local_variable: bool = False,
    is_hardcoded: bool = False,
) -> ConfidenceResult:
    """
    Calculate detection confidence level.
    
    Args:
        is_string_literal: Algorithm passed as direct string literal
        is_via_reflection: Call made via Java reflection API
        is_from_parameter: Algorithm comes from method parameter
        is_from_field: Algorithm comes from class field
        is_from_local_variable: Algorithm comes from local variable
        is_hardcoded: Hardcoded key/secret detected
        
    Returns:
        ConfidenceResult with level and human-readable reason
    """
    # Reflection = always LOW
    if is_via_reflection:
        return ConfidenceResult(
            level=Confidence.LOW,
            reason="algorithm passed via reflection - cannot determine statically",
        )

    # Parameter/field = LOW (runtime-determined)
    if is_from_parameter:
        return ConfidenceResult(
            level=Confidence.LOW,
            reason="algorithm from method parameter - determined at runtime",
        )

    if is_from_field:
        return ConfidenceResult(
            level=Confidence.LOW,
            reason="algorithm from class field - determined at runtime",
        )

    # String literal = HIGH (deterministic)
    if is_string_literal:
        if is_hardcoded:
            return ConfidenceResult(
                level=Confidence.HIGH,
                reason="hardcoded key detected in string literal",
            )
        return ConfidenceResult(
            level=Confidence.HIGH,
            reason="algorithm from string literal - deterministic static analysis",
        )

    # Local variable = MEDIUM (may be traceable)
    if is_from_local_variable:
        return ConfidenceResult(
            level=Confidence.MEDIUM,
            reason="algorithm from local variable - partially traceable",
        )

    # Default fallback
    return ConfidenceResult(
        level=Confidence.LOW,
        reason="algorithm source unknown - cannot determine statically",
    )