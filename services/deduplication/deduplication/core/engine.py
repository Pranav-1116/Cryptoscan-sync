"""Cross-scanner cryptographic asset deduplication."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from deduplication.core.keys import dedup_key, identity_tuple


def _get(finding: dict[str, Any], *path: str, default: Any = None) -> Any:
    current: Any = finding
    for key in path:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
    return default if current is None else current


def identity_key(finding: dict[str, Any]) -> tuple:
    return identity_tuple(finding)


def _confidence_rank(value: str | None) -> int:
    return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "VERIFIED": 4}.get(str(value or "").upper(), 0)


class DeduplicationEngine:
    """Collapse findings that describe the same crypto use from multiple scanners."""

    def merge(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        groups: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
        for finding in findings:
            groups[identity_key(finding)].append(finding)

        assets: list[dict[str, Any]] = []
        for key, members in groups.items():
            algorithm, purpose, file_path, line = key
            scanners = sorted(
                {
                    str(item.get("scanner_id") or _get(item, "metadata", "library") or "unknown")
                    for item in members
                }
            )
            confidences = [
                str(_get(item, "metadata", "confidence") or item.get("confidence") or "LOW")
                for item in members
            ]
            best = max(confidences, key=_confidence_rank)
            if len({item.get("scanner_id") for item in members if item.get("scanner_id")}) >= 2:
                best = "VERIFIED"
            evidence_ids = [
                item.get("finding_id") or item.get("evidence_id") or item.get("id")
                for item in members
            ]
            libraries = sorted(
                {
                    str(_get(item, "metadata", "library") or item.get("library"))
                    for item in members
                    if _get(item, "metadata", "library") or item.get("library")
                }
            )
            hardcoded = any(
                bool(_get(item, "metadata", "is_hardcoded_key") or item.get("is_hardcoded_key"))
                for item in members
            )
            ranked = sorted(
                members,
                key=lambda item: _confidence_rank(
                    str(_get(item, "metadata", "confidence") or item.get("confidence") or "LOW")
                ),
                reverse=True,
            )
            member_rows = []
            for index, item in enumerate(ranked):
                member_rows.append(
                    {
                        "evidence_id": item.get("finding_id") or item.get("evidence_id") or item.get("id"),
                        "scanner_id": item.get("scanner_id"),
                        "confidence": _get(item, "metadata", "confidence") or item.get("confidence") or "LOW",
                        "role": "PRIMARY" if index == 0 else "SUPPORTING",
                        "file_path": _get(item, "source", "file_path") or item.get("file_path"),
                        "line_number": _get(item, "source", "line_number") or item.get("line_number"),
                        "library": _get(item, "metadata", "library") or item.get("library"),
                    }
                )
            primary = next((row for row in member_rows if row["role"] == "PRIMARY"), None)
            assets.append(
                {
                    "algorithm": algorithm,
                    "purpose": purpose,
                    "file_path": file_path,
                    "line_number": line,
                    "confidence": best,
                    "scanner_ids": scanners,
                    "libraries": libraries,
                    "evidence_ids": [eid for eid in evidence_ids if eid],
                    "occurrence_count": len(members),
                    "is_hardcoded_key": hardcoded,
                    "mode": _get(members[0], "crypto", "mode") or members[0].get("mode"),
                    "key_size": _get(members[0], "crypto", "key_size") or members[0].get("key_size"),
                    "source_language": _get(members[0], "source", "language")
                    or members[0].get("source_language"),
                    "dedup_key": dedup_key(members[0]),
                    "primary_evidence_id": (primary or {}).get("evidence_id"),
                    "members": member_rows,
                }
            )
        return sorted(assets, key=lambda item: (item["file_path"], item["line_number"], item["algorithm"]))
