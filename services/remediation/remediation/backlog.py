"""Order remediation suggestions into an execution backlog.

Pure grouping over the engine's suggestions: same rule -> one backlog
item carrying its sites. Priority decides the wave (P0 stop-the-bleed,
P1 weak modes, P2/P3 transition work).
"""

from __future__ import annotations

from typing import Any, Iterable

WAVE_BY_PRIORITY = {"P0": 1, "P1": 2, "P2": 3, "P3": 3}
WAVE_FOCUS = {
    1: "classically broken crypto — stop the bleed",
    2: "weak modes and deprecated primitives",
    3: "PQC transition and quantum sizing",
}
MAX_SITES_PER_ITEM = 200
_PRIORITY_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}


def build_backlog(suggestions: Iterable[dict[str, Any]]) -> dict[str, Any]:
    groups: dict[str, dict[str, Any]] = {}
    for row in suggestions:
        rule = str(row.get("rule") or "manual-review")
        item = groups.setdefault(
            rule,
            {
                "rule": rule,
                "category": row.get("category"),
                "priority": row.get("priority"),
                "replace_with": row.get("replace_with"),
                "guidance": row.get("guidance"),
                "effort": row.get("effort"),
                "site_count": 0,
                "sites": [],
            },
        )
        item["site_count"] += 1
        if len(item["sites"]) < MAX_SITES_PER_ITEM:
            item["sites"].append(
                {
                    "evidence_id": row.get("evidence_id"),
                    "algorithm": row.get("algorithm"),
                    "file_path": row.get("file_path"),
                    "line_number": row.get("line_number"),
                }
            )

    items = sorted(
        groups.values(),
        key=lambda item: (_PRIORITY_RANK.get(str(item["priority"]), 99), -item["site_count"], str(item["rule"])),
    )
    for item in items:
        item["wave"] = WAVE_BY_PRIORITY.get(str(item["priority"]), 3)

    waves: dict[str, dict[str, Any]] = {}
    for wave in (1, 2, 3):
        bucket = [item for item in items if item["wave"] == wave]
        waves[str(wave)] = {
            "focus": WAVE_FOCUS[wave],
            "rule_count": len(bucket),
            "site_count": sum(item["site_count"] for item in bucket),
        }
    return {
        "items": items,
        "total_rules": len(items),
        "total_sites": sum(item["site_count"] for item in items),
        "waves": waves,
        "ordering": "priority asc, site_count desc, rule asc",
        "note": f"sites are capped at {MAX_SITES_PER_ITEM} per item; site_count stays exact",
    }
