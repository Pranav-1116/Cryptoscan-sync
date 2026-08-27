"""Portfolio migration roadmap + trend. Pure and deterministic.

Sequencing inside a wave: readiness desc, then agility desc, then name —
no timestamps, no randomness, same input always yields the same roadmap.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

WAVE_ORDER = (1, 2, 3)
_WAVE_BY_CATEGORY = {"READY_NOW": 1, "READY_WITH_PREP": 2, "NOT_READY": 2, "BLOCKED": 3}


def wave_for(readiness_category: str | None) -> int:
    return _WAVE_BY_CATEGORY.get(str(readiness_category or ""), 3)


def build_roadmap(entries: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Order systems into migration waves with a deterministic rationale."""
    rows = [dict(entry) for entry in entries]
    waves: dict[int, list[dict[str, Any]]] = {wave: [] for wave in WAVE_ORDER}
    for row in rows:
        wave = int(row.get("wave") or wave_for(row.get("readiness_category")))
        row["wave"] = wave
        waves.setdefault(wave, []).append(row)
    ordered: dict[str, list[dict[str, Any]]] = {}
    for wave in sorted(waves):
        bucket = sorted(
            waves[wave],
            key=lambda row: (
                -int(row.get("readiness_score") or 0),
                -int(row.get("agility_score") or 0),
                str(row.get("system") or row.get("system_id") or ""),
                str(row.get("system_id") or ""),
            ),
        )
        positioned = []
        for position, row in enumerate(bucket, start=1):
            rationale = (
                f"readiness {row.get('readiness_score')}/100, agility {row.get('agility_score')}/100"
            )
            if int(row.get("dependency_count") or 0) > 10:
                rationale += f", {row['dependency_count']} dependencies to sequence first"
            positioned.append({**row, "position": position, "rationale": rationale})
        ordered[str(wave)] = positioned
    flat = [row for wave in ordered for row in ordered[wave]]
    return {
        "waves": ordered,
        "wave_order": [int(wave) for wave in ordered],
        "total_systems": len(flat),
        "sequencing": "readiness desc, agility desc, name asc",
    }


def portfolio_trend(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Compare current agility vs the previous saved score per system.

    Systems without history count as no_history — never guessed.
    """
    improving = declining = flat = no_history = 0
    deltas: dict[str, int] = {}
    for row in rows:
        system_id = str(row.get("system_id") or "")
        current = row.get("agility_score")
        previous = row.get("previous_agility_score")
        if current is None:
            no_history += 1
            continue
        if previous is None:
            no_history += 1
            continue
        delta = int(current) - int(previous)
        deltas[system_id] = delta
        if delta > 0:
            improving += 1
        elif delta < 0:
            declining += 1
        else:
            flat += 1
    return {
        "improving": improving,
        "declining": declining,
        "flat": flat,
        "no_history": no_history,
        "deltas": deltas,
    }
