"""§29 Platform risk engine — fuses the eight risk factors into one
CRITICAL / HIGH / MEDIUM / LOW score for an asset or the whole estate.

    Crypto Risk + Business Criticality + Exposure + Dependency Count +
    Quantum Risk + Migration Complexity + Vendor Dependency + Hardware Dependency

Deterministic weighted sum; weights are constants (documented), not model
output. Missing factors are counted as zero and reported honestly.
"""

from __future__ import annotations

from typing import Any, Optional

#: factor → (max points, weight). Scores are normalized to 0–100.
_FACTORS = {
    "crypto_risk": (4, 0.20),          # weak/deprecated crypto in use
    "business_criticality": (4, 0.20), # how business-critical the asset is
    "exposure": (4, 0.15),             # reachable / internet-facing
    "dependency_count": (4, 0.10),     # dependents in the graph
    "quantum_risk": (4, 0.15),         # quantum-vulnerable crypto
    "migration_complexity": (4, 0.10), # effort to migrate
    "vendor_dependency": (4, 0.05),    # single-vendor lock-in
    "hardware_dependency": (4, 0.05),  # depends on HSM/TPM availability
}

_LEVELS = [
    ("CRITICAL", 80), ("HIGH", 60), ("MEDIUM", 40), ("LOW", 0),
]


def _level(score: float) -> str:
    for name, floor in _LEVELS:
        if score >= floor:
            return name
    return "LOW"


def risk_score(asset: Optional[dict[str, Any]] = None,
               **factors: Any) -> dict[str, Any]:
    """Score one asset. ``factors`` may carry 0–4 integer levels per factor;
    ``asset`` may carry them under ``risk_factors`` or flat keys."""
    merged: dict[str, int] = {}
    if asset:
        for key in _FACTORS:
            value = (asset.get("risk_factors") or {}).get(key,
                     asset.get(key, 0))
            merged[key] = int(value or 0)
    for key, value in factors.items():
        if key in _FACTORS:
            merged[key] = int(value or 0)
    total = 0.0
    detail: dict[str, Any] = {}
    for key, (max_points, weight) in _FACTORS.items():
        level = min(max(merged.get(key, 0), 0), max_points)
        points = (level / max_points) * 100 * weight
        total += points
        detail[key] = {"level": level, "points": round(points, 2)}
    score = round(total, 1)
    return {
        "score": score,
        "level": _level(score),
        "factors": detail,
        "missing_factors": [k for k in _FACTORS if k not in merged],
    }


def estate_risk(assets: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate risk across the estate (max level + mean score)."""
    scored = [risk_score(a) for a in assets]
    if not scored:
        return {"score": 0.0, "level": "LOW", "count": 0}
    mean = round(sum(s["score"] for s in scored) / len(scored), 1)
    return {
        "score": mean,
        "level": _level(mean),
        "count": len(scored),
        "by_level": {lv: sum(1 for s in scored if s["level"] == lv)
                     for lv in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
    }
