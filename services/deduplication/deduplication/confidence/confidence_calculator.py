"""Merged confidence for multi-scanner assets."""

from __future__ import annotations

from typing import Iterable


def confidence_rank(value: str | None) -> int:
    return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "VERIFIED": 4}.get(str(value or "").upper(), 0)


def calculate_merged_confidence(values: Iterable[str | None], *, scanner_count: int = 1) -> str:
    best = "LOW"
    for value in values:
        if confidence_rank(value) > confidence_rank(best):
            best = str(value or "LOW").upper()
    if scanner_count >= 2:
        return "VERIFIED"
    return best
