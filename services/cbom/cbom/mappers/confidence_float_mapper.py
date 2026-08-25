"""Map VERIFIED/HIGH/MEDIUM/LOW onto a 0.0–1.0 CycloneDX confidence."""

from __future__ import annotations

CONFIDENCE_FLOAT = {
    "VERIFIED": 1.0,
    "HIGH": 0.9,
    "MEDIUM": 0.6,
    "LOW": 0.3,
    "UNKNOWN": 0.1,
}


def confidence_to_float(value: str | None) -> float:
    if value is None:
        return 0.5
    if isinstance(value, (int, float)):
        numeric = float(value)
        return max(0.0, min(1.0, numeric if numeric <= 1 else numeric / 100.0))
    return CONFIDENCE_FLOAT.get(str(value).upper(), 0.5)
