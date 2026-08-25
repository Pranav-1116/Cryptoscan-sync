"""Track every scanner that contributed evidence to an asset."""

from __future__ import annotations

from typing import Any


def source_from_finding(finding: dict[str, Any]) -> dict[str, Any]:
    metadata = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    return {
        "scanner_id": finding.get("scanner_id"),
        "scan_id": finding.get("scan_id"),
        "confidence": metadata.get("confidence") or finding.get("confidence") or "LOW",
    }


def merge_sources(existing: list[dict[str, Any]] | None, finding: dict[str, Any]) -> list[dict[str, Any]]:
    sources = [dict(item) for item in (existing or [])]
    candidate = source_from_finding(finding)
    key = (candidate.get("scanner_id"), candidate.get("scan_id"))
    seen = {(item.get("scanner_id"), item.get("scan_id")) for item in sources}
    if key not in seen:
        sources.append(candidate)
    return sources
