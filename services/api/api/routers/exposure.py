"""Exposure path queries (report 58 P3 #14).

Answers "which weak crypto is reachable from an externally-facing entry
system, through which dependency chain?" — walking the persisted system
dependency graph from *entry candidate* systems (cloud-hosted or
URL/git-remote scan targets) to the crypto assets attached to each reached
system.

Honest about what this is: the platform does not scan network topology, so
"entry candidate" is a heuristic over persisted system metadata, not a
verified internet-facing surface. Paths are bounded (depth and count) and
reported with their weakest algorithm designation along the chain.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from db.repositories.system_repository import SystemRepository
from shared_models.algorithm_registry import parse_algorithm

router = APIRouter(prefix="/exposure", tags=["exposure"])

MAX_DEPTH = 4
MAX_PATHS = 100

_DESIGNATION_RANK = {
    "DISALLOWED": 4,
    "DEPRECATED": 3,
    "RESTRICTED": 3,
    "ALLOWED": 1,
}


def _is_entry_candidate(system: Any) -> bool:
    """Heuristic externally-reachable surface: cloud-hosted or remote target."""
    if getattr(system, "cloud_provider", None):
        return True
    target = str(getattr(system, "scan_target", "") or "").lower()
    return target.startswith(("http://", "https://", "git@", "ssh://", "ftp://"))


def _entry_reason(system: Any) -> str:
    if getattr(system, "cloud_provider", None):
        return f"cloud-hosted ({system.cloud_provider})"
    return "remote scan target"


@router.get("/paths")
def exposure_paths(
    algorithm: str | None = Query(
        None, description="Only paths ending at crypto assets of this algorithm (e.g. RSA)"),
    min_rank: int = Query(
        0, ge=0, le=4,
        description="Only assets at/above this weakness rank (4=DISALLOWED, 3=DEPRECATED, 1=ALLOWED)"),
    limit: int = Query(50, ge=1, le=MAX_PATHS),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Bounded exposure paths: entry-candidate system → dependencies → crypto asset.

    Each path is ``[entry system, ..., system holding the asset]`` plus the
    asset and its designation. Pure read over persisted graph data; no
    topology inference beyond the entry heuristic.
    """
    repo = SystemRepository(db)
    systems, systems_truncated = repo.list_all_bounded()
    by_id = {s.id: s for s in systems}

    # adjacency: parent -> children (parent depends on child)
    children: dict[str, list[str]] = {}
    for s in systems:
        for edge in (s.outgoing or []):
            if edge.child_id in by_id:
                children.setdefault(s.id, []).append(edge.child_id)

    # assets per system, filtered by designation rank and optional algorithm
    assets_by_system: dict[str, list[dict[str, Any]]] = {}
    for s in systems:
        matched = []
        for asset in repo.assets_for(s.id) or []:
            info = parse_algorithm(asset.algorithm or "")
            rank = _DESIGNATION_RANK.get(str(info.status or "").upper(), 0)
            if rank < min_rank:
                continue
            if algorithm and (info.canonical or asset.algorithm or "").upper() != algorithm.upper():
                continue
            matched.append({
                "asset_id": str(asset.id),
                "algorithm": info.canonical or asset.algorithm,
                "key_size": asset.key_size,
                "designation": str(info.status or "UNKNOWN").upper(),
                "quantum_impact": str(info.quantum_impact or "").lower() or None,
                "rank": rank,
            })
        if matched:
            assets_by_system[s.id] = matched

    paths: list[dict[str, Any]] = []
    entries = [s for s in systems if _is_entry_candidate(s)]
    for entry in entries:
        # BFS over dependency edges, bounded depth
        frontier: list[tuple[str, list[str]]] = [(entry.id, [entry.id])]
        seen_chains: set[tuple[str, ...]] = set()
        while frontier and len(paths) < limit:
            node, chain = frontier.pop(0)
            if len(chain) > MAX_DEPTH:
                continue
            if tuple(chain) in seen_chains:
                continue
            seen_chains.add(tuple(chain))
            for asset in assets_by_system.get(node, []):
                if len(paths) >= limit:
                    break
                paths.append({
                    "entry_system": {"id": str(entry.id), "name": entry.name,
                                     "reason": _entry_reason(entry)},
                    "chain": [
                        {"id": str(c), "name": by_id[c].name, "cloud_provider": by_id[c].cloud_provider}
                        for c in chain
                    ],
                    "asset": asset,
                    "depth": len(chain) - 1,
                    "weakest_designation": asset["designation"],
                    "weakest_rank": asset["rank"],
                })
            for child in children.get(node, []):
                if child not in chain:  # no cycles
                    frontier.append((child, chain + [child]))

    paths.sort(key=lambda p: (-p["weakest_rank"], p["depth"]))
    return {
        "paths": paths,
        "path_count": len(paths),
        "entry_candidates": [
            {"id": str(s.id), "name": s.name, "reason": _entry_reason(s)} for s in entries
        ],
        "entry_candidate_count": len(entries),
        "bounds": {
            "max_depth": MAX_DEPTH,
            "max_paths": MAX_PATHS,
            "returned": len(paths),
            "systems_truncated": systems_truncated,
        },
        "heuristic": (
            "entry candidates are cloud-hosted or remote-target systems; "
            "the platform does not verify network reachability"
        ),
    }
