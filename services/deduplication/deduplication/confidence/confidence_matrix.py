"""VERIFIED / HIGH / MEDIUM / LOW matrix for merged scanner types."""

from __future__ import annotations

from typing import Iterable

from deduplication.confidence.confidence_calculator import calculate_merged_confidence, confidence_rank

LEVELS = ("LOW", "MEDIUM", "HIGH", "VERIFIED")


def scanner_family(scanner_id: str | None) -> str:
    raw = str(scanner_id or "unknown").lower()
    if raw.startswith("static") or "static" in raw:
        return "static"
    if "container" in raw:
        return "container"
    if "binary" in raw or "jar" in raw:
        return "binary"
    if "network" in raw or "tls" in raw:
        return "network"
    if "cloud" in raw:
        return "cloud"
    token = raw.split("-", 1)[0]
    return token or "unknown"


def merged_confidence_from_sources(sources: Iterable[dict | str | None]) -> str:
    families: set[str] = set()
    values: list[str | None] = []
    for source in sources:
        if isinstance(source, dict):
            families.add(scanner_family(source.get("scanner_id")))
            values.append(source.get("confidence"))
        else:
            families.add(scanner_family(str(source) if source else None))
    if "static" in families and ("container" in families or "binary" in families):
        return "VERIFIED"
    if len(families) >= 2:
        return "HIGH"
    return calculate_merged_confidence(values or ["MEDIUM"], scanner_count=len(families))


__all__ = ["LEVELS", "confidence_rank", "merged_confidence_from_sources", "scanner_family"]
