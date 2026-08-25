"""Track unique locations observed for a crypto asset."""

from __future__ import annotations

from typing import Any


def location_from_finding(finding: dict[str, Any]) -> dict[str, Any]:
    source = finding.get("source") if isinstance(finding.get("source"), dict) else {}
    return {
        "type": source.get("type") or finding.get("source_type") or "SOURCE_CODE",
        "file_path": source.get("file_path") or finding.get("file_path"),
        "line_number": source.get("line_number") or finding.get("line_number") or 0,
        "container_image": source.get("image_reference") or finding.get("image"),
    }


def merge_locations(existing: list[dict[str, Any]] | None, finding: dict[str, Any]) -> list[dict[str, Any]]:
    locations = [dict(item) for item in (existing or [])]
    candidate = location_from_finding(finding)
    key = (candidate.get("type"), candidate.get("file_path"), candidate.get("line_number"))
    seen = {(item.get("type"), item.get("file_path"), item.get("line_number")) for item in locations}
    if key not in seen:
        locations.append(candidate)
    return locations
