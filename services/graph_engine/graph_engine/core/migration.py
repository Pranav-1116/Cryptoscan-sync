"""Migration wave planning under dependency-cycle constraints.

Pure function: joins readiness waves (computed by the caller, e.g. from
agility.roadmap.wave_for) with graph cycles (find_cycles). Systems in a
dependency cycle cannot be migrated in independent waves — every member
is held to the most conservative (highest) wave among its cycle peers.
"""

from __future__ import annotations

from typing import Any


def _bare(member: str) -> str:
    return member.split(":", 1)[1] if ":" in member else member


def merge_cycle_constraints(entries: list[dict[str, Any]], cycles: list[dict[str, Any]]) -> dict[str, Any]:
    """Apply cycle constraints to wave assignments and position systems."""
    rows = [dict(entry) for entry in entries]
    index = {str(row.get("system_id")): row for row in rows}

    cycle_groups = 0
    bumped: list[str] = []
    for order, cycle in enumerate(cycles, start=1):
        members = [_bare(str(member)) for member in cycle.get("members") or []]
        if cycle.get("self_loop") or len(members) < 2:
            continue  # a self-call does not couple two systems' waves
        present = [member for member in members if member in index]
        if len(present) < 2:
            continue
        cycle_groups += 1
        group_id = f"cycle-{order}"
        target_wave = max(int(index[member].get("wave") or 1) for member in present)
        for member in present:
            row = index[member]
            if int(row.get("wave") or 1) < target_wave:
                bumped.append(member)
            row["wave"] = target_wave
            row["cycle_group"] = group_id

    waves: dict[int, list[dict[str, Any]]] = {}
    for row in rows:
        waves.setdefault(int(row.get("wave") or 1), []).append(row)
    flat: list[dict[str, Any]] = []
    ordered: dict[str, list[dict[str, Any]]] = {}
    for wave in sorted(waves):
        bucket = sorted(
            waves[wave],
            key=lambda row: (
                -int(row.get("readiness_score") or 0),
                -int(row.get("agility_score") or 0),
                str(row.get("name") or ""),
                str(row.get("system_id") or ""),
            ),
        )
        positioned = []
        for position, row in enumerate(bucket, start=1):
            row["position"] = position
            rationale = row.get("rationale") or ""
            if row.get("cycle_group"):
                rationale = (rationale + "; " if rationale else "") + (
                    f"held in wave {wave} with its dependency cycle {row['cycle_group']}"
                )
            if row.get("unscored"):
                rationale = (rationale + "; " if rationale else "") + "no agility score yet — conservatively last"
            row["rationale"] = rationale or None
            positioned.append(row)
        ordered[str(wave)] = positioned
        flat.extend(positioned)
    return {
        "waves": ordered,
        "wave_order": [int(wave) for wave in ordered],
        "total_systems": len(flat),
        "cycle_groups": cycle_groups,
        "systems_bumped": sorted(set(bumped)),
        "constraint": "cycle members share the most conservative wave among their group",
    }
