"""Score-history trajectory analysis. Pure, deterministic, honest.

Input rows must already be chronological (ascending).  Fewer than two
points is INSUFFICIENT_DATA — never a guess.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping


def _score(row: Mapping[str, Any]) -> int | None:
    value = row.get("agility_score", row.get("score"))
    return int(value) if value is not None else None


def analyze_history(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Classify a system's agility trajectory from saved score rows."""
    points = [
        {
            "calculated_at": row.get("calculated_at"),
            "agility_score": _score(row),
            "category": row.get("category"),
            "readiness_score": row.get("readiness_score"),
            "factor_scores": row.get("factor_scores"),
        }
        for row in rows
    ]
    scores = [point["agility_score"] for point in points if point["agility_score"] is not None]
    deltas = [second - first for first, second in zip(scores, scores[1:])] if len(scores) >= 2 else []

    if len(scores) < 2:
        trajectory = "INSUFFICIENT_DATA"
    elif all(delta > 0 for delta in deltas):
        trajectory = "IMPROVING"
    elif all(delta < 0 for delta in deltas):
        trajectory = "DECLINING"
    elif all(delta == 0 for delta in deltas):
        trajectory = "STABLE"
    else:
        trajectory = "VOLATILE"

    factor_deltas: dict[str, int] | None = None
    if len(points) >= 2:
        previous = points[-2].get("factor_scores")
        latest = points[-1].get("factor_scores")
        previous = previous if isinstance(previous, dict) else None
        latest = latest if isinstance(latest, dict) else None
        if isinstance(previous, dict) and isinstance(latest, dict):
            factor_deltas = {
                str(key): int(latest[key]) - int(previous[key])
                for key in latest
                if key in previous and isinstance(latest.get(key), (int, float)) and isinstance(previous.get(key), (int, float))
            }

    best = max(scores) if scores else None
    worst = min(scores) if scores else None
    moved = {key: delta for key, delta in (factor_deltas or {}).items() if delta != 0}
    return {
        "points": len(points),
        "trajectory": trajectory,
        "score_deltas": deltas,
        "first_score": scores[0] if scores else None,
        "latest_score": scores[-1] if scores else None,
        "best_score": best,
        "worst_score": worst,
        "net_change": (scores[-1] - scores[0]) if len(scores) >= 2 else None,
        "factor_deltas": factor_deltas,
        "factors_improved": sorted(k for k, v in moved.items() if v > 0),
        "factors_regressed": sorted(k for k, v in moved.items() if v < 0),
    }
