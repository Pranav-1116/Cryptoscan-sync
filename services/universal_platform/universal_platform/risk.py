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


# ---------------------------------------------------------------------------
# §29b Unified risk normalization — the enterprise risk contract.
#
#    Technical + Crypto + PQC + Exposure + Business Criticality +
#    Dependency Impact + Evidence Confidence + Threat  ->  ONE score.
#
# Deterministic weighted sum (no model output). Every factor is a 0–4 level
# (0 = none/unknown, 4 = severe) supplied by a risk source or derived honestly
# from persisted observations. Unknown factors are counted as 0 and reported.
# ---------------------------------------------------------------------------

#: blueprint factor → (max level, weight). Weights sum to 1.00.
UNIFIED_FACTORS = {
    "technical": (4, 0.18),           # vulnerability / failing finding severity
    "crypto": (4, 0.16),              # weak / deprecated / disallowed crypto
    "pqc": (4, 0.16),                 # quantum-vulnerable crypto (harvest-now)
    "exposure": (4, 0.12),            # reachable / internet-facing / multi-region
    "business_criticality": (4, 0.14),# how business-critical the asset is
    "dependency_impact": (4, 0.10),   # blast radius / dependents in the graph
    "evidence_confidence": (4, 0.06), # certainty of the observations (0=unknown)
    "threat": (4, 0.08),              # active threat / CVE / exploitation context
}

UNIFIED_LEVELS = [
    ("CRITICAL", 80), ("HIGH", 60), ("MEDIUM", 40), ("LOW", 0),
]

#: Report 64 P0: all weights configurable. ``CRYPTOSCAN_RISK_WEIGHTS`` may
#: carry a JSON object mapping blueprint factor names to weights, e.g.
#: ``{"pqc": 0.30, "crypto": 0.10}``. Unrecognized names, non-numeric or
#: negative weights make the whole override invalid — the engine then falls
#: back to the documented defaults and says so via ``weights_source``
#: (invalid configuration is reported, never silently half-applied).
import json as _json
import os as _os

CALCULATION_VERSION = "unified-risk-v1"

_WEIGHTS_ENV_VAR = "CRYPTOSCAN_RISK_WEIGHTS"


def _env_weights() -> dict[str, float] | None:
    raw = _os.environ.get(_WEIGHTS_ENV_VAR, "").strip()
    if not raw:
        return None
    try:
        parsed = _json.loads(raw)
    except ValueError:
        return None
    if not isinstance(parsed, dict):
        return None
    out: dict[str, float] = {}
    for key, value in parsed.items():
        if key not in UNIFIED_FACTORS:
            return None
        try:
            weight = float(value)
        except (TypeError, ValueError):
            return None
        if weight < 0:
            return None
        out[key] = weight
    if not out:
        return None
    return out


def unified_weights() -> tuple[dict[str, float], str]:
    """Effective blueprint weights: (factor → weight, source label).

    Env override semantics: factors named in the override keep their
    **absolute** weight; the remaining weight budget is split among the
    unspecified factors proportionally to their defaults. If the override
    sums to more than 1.0 it is scaled down proportionally. The returned
    map always sums to 1.0.
    """
    defaults = {k: w for k, (_, w) in UNIFIED_FACTORS.items()}
    override = _env_weights()
    if override is None:
        total = sum(defaults.values()) or 1.0
        return {k: round(w / total, 6) for k, w in defaults.items()}, "default"
    if sum(override.values()) > 1.0:
        scale = 1.0 / sum(override.values())
        override = {k: round(w * scale, 6) for k, w in override.items()}
    remainder = round(1.0 - sum(override.values()), 6)
    others = {k: w for k, w in defaults.items() if k not in override}
    others_total = sum(others.values())
    merged = dict(override)
    if others and others_total > 0 and remainder > 0:
        for k, w in others.items():
            merged[k] = round(remainder * (w / others_total), 6)
    else:
        for k in others:
            merged[k] = 0.0
    return merged, f"env:{_WEIGHTS_ENV_VAR}"


def unified_level(score: float) -> str:
    for name, floor in UNIFIED_LEVELS:
        if score >= floor:
            return name
    return "LOW"


def unified_risk(levels: Optional[dict[str, Any]] = None,
                 weights: Optional[dict[str, float]] = None,
                 **factors: Any) -> dict[str, Any]:
    """Normalize a 0–4 level per blueprint factor into one 0–100 score.

    ``levels`` (or ``factors``) may carry any subset of ``UNIFIED_FACTORS``;
    missing factors contribute 0 and are listed as ``missing``. ``weights``
    overrides the effective factor weights (defaults come from
    ``unified_weights()`` — env-configurable, report 64 P0).
    """
    effective, weights_source = unified_weights()
    if weights is not None:
        effective = dict(weights)
        weights_source = "caller"
    merged: dict[str, int] = {}
    for key in UNIFIED_FACTORS:
        merged[key] = int((levels or {}).get(key, 0) or 0)
    for key, value in factors.items():
        if key in UNIFIED_FACTORS:
            merged[key] = int(value or 0)
    total = 0.0
    detail: dict[str, Any] = {}
    for key, (max_level, _) in UNIFIED_FACTORS.items():
        weight = float(effective.get(key, 0.0))
        level = min(max(int(merged.get(key, 0)), 0), max_level)
        points = (level / max_level) * 100 * weight
        total += points
        detail[key] = {"level": level, "points": round(points, 2), "weight": weight}
    score = round(total, 1)
    return {
        "score": score,
        "level": unified_level(score),
        "factors": detail,
        "missing": [k for k in UNIFIED_FACTORS if (levels or {}).get(k) is None],
        "calculation_version": CALCULATION_VERSION,
        "weights_source": weights_source,
    }


def _level_of(criticality: Optional[str]) -> int:
    """Map a persisted criticality/tier string to a 0–4 level (honest)."""
    c = str(criticality or "").upper()
    if c in {"TIER-1", "CRITICAL", "P0", "SEV1"}:
        return 4
    if c in {"HIGH", "TIER-2", "P1", "SEV2"}:
        return 3
    if c in {"MEDIUM", "TIER-3", "P2", "SEV3"}:
        return 2
    if c in {"LOW", "P3", "SEV4"}:
        return 1
    return 0


def _exposure_level(asset: dict[str, Any]) -> int:
    env = str(asset.get("environment") or asset.get("env") or "").lower()
    if env in {"prod", "production", "internet", "public", "dmz"}:
        return 4
    if env in {"staging", "stage", "preprod", "external"}:
        return 2
    return 0


def _confidence_level(asset: dict[str, Any]) -> int:
    conf = str(asset.get("confidence") or "").upper()
    if conf in {"HIGH", "CONFIRMED"}:
        return 4
    if conf in {"MEDIUM", "LIKELY"}:
        return 3
    if conf in {"LOW", "TENTATIVE"}:
        return 1
    return 0


def _crypto_level(asset: dict[str, Any]) -> int:
    alg = str(asset.get("algorithm") or "").upper()
    if any(x in alg for x in ("MD5", "SHA-1", "SHA1", "DES", "RC4", "3DES", "WEAK")):
        return 4
    if "RSA" in alg or "ECDSA" in alg or "DH" in alg:
        return 2
    return 0


def from_asset(asset: dict[str, Any]) -> dict[str, Any]:
    """Derive the 8 blueprint factor levels from a unified-inventory asset row.

    Every level is a pure, deterministic function of persisted fields (or 0
    when unknown). Nothing is invented: e.g. ``threat`` stays 0 unless a
    threat source supplied ``threat_level``.
    """
    pqc = str(asset.get("pqc") or "").lower()
    relations = asset.get("relationships") or {}
    dep_hits = sum(len(v) for v in relations.values() if isinstance(v, list))
    levels = {
        "technical": min(_level_of(asset.get("risk")), 4) if _level_of(asset.get("risk")) else int(asset.get("technical_level") or 0),
        "crypto": max(_crypto_level(asset), int(asset.get("crypto_level") or 0)),
        "pqc": 4 if pqc == "vulnerable" else (0 if pqc == "ready" else int(asset.get("pqc_level") or 0)),
        "exposure": max(_exposure_level(asset), int(asset.get("exposure_level") or 0)),
        "business_criticality": _level_of(asset.get("criticality")),
        "dependency_impact": min(dep_hits, 4),
        "evidence_confidence": _confidence_level(asset),
        "threat": int(asset.get("threat_level") or 0),
    }
    return unified_risk(levels)

