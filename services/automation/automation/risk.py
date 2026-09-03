"""Deterministic asset risk recalculation and up-chain propagation (no AI/ML).

Risk is recomputed from explicit inputs — never inferred by a model:

* base score from the count/severity of open findings on an asset,
* quantum-vulnerable crypto and weak keys add weight,
* asset criticality acts as a multiplier,
* risk propagates *up* the dependency graph: a component's risk lifts the
  systems/services that depend on it, so a new vulnerable library raises the
  application, then the business service that consumes it (section 8/12).

Scoring is pure arithmetic with fixed weights; the same inputs always yield the
same scores and the same propagation order (deterministic, auditable).
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

#: per-severity finding weight (open findings)
SEVERITY_WEIGHT = {"LOW": 1, "MEDIUM": 3, "HIGH": 7, "CRITICAL": 15}
#: multipliers by asset criticality
CRITICALITY_MULTIPLIER = {
    "LOW": 1.0, "MEDIUM": 1.25, "HIGH": 1.5, "VERY_HIGH": 2.0,
    "MISSION_CRITICAL": 3.0, "CRITICAL": 3.0, "SAFETY": 3.0, "TIER0": 3.0,
}
QUANTUM_VULN_BONUS = 6      # quantum-vulnerable crypto present
WEAK_KEY_BONUS = 5          # below-strength key
SCORE_CAP = 100


def _norm_crit(value: Any) -> str:
    return str(value or "MEDIUM").strip().upper()


def base_risk(asset: dict[str, Any]) -> int:
    """Deterministic direct risk score for one asset from its findings/state."""
    score = 0
    for finding in asset.get("findings", []) or []:
        sev = str(finding.get("severity") or "MEDIUM").strip().upper()
        score += SEVERITY_WEIGHT.get(sev, 3)
    if asset.get("quantum_vulnerable") or asset.get("pqc_vulnerable"):
        score += QUANTUM_VULN_BONUS
    if asset.get("weak_key") or asset.get("has_weak_crypto"):
        score += WEAK_KEY_BONUS
    mult = CRITICALITY_MULTIPLIER.get(_norm_crit(asset.get("criticality")), 1.25)
    return min(SCORE_CAP, int(round(score * mult)))


def risk_band(score: int) -> str:
    if score >= 60:
        return "CRITICAL"
    if score >= 35:
        return "HIGH"
    if score >= 15:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


@dataclass
class RiskResult:
    scores: dict[str, int] = field(default_factory=dict)
    bands: dict[str, str] = field(default_factory=dict)
    changed: list[str] = field(default_factory=list)
    affected_business_services: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "scores": self.scores,
            "bands": self.bands,
            "recalculated": self.changed,
            "business_services_affected": self.affected_business_services,
            "max_score": max(self.scores.values(), default=0),
            "max_band": risk_band(max(self.scores.values(), default=0)),
        }


def _reverse_edges(edges: Iterable[tuple[str, str]]) -> dict[str, list[str]]:
    """Build dependents map: node -> nodes that depend on (consume) it."""
    dependents: dict[str, list[str]] = {}
    for src, dst in edges:
        # edge src -> dst means src calls/depends-on dst; dst is depended upon.
        # a risk in dst propagates UP to src (its consumer).
        dependents.setdefault(str(dst), []).append(str(src))
    return dependents


def recalculate(
    assets: Mapping[str, dict[str, Any]],
    edges: Iterable[tuple[str, str]],
    *,
    changed_assets: Iterable[str] | None = None,
) -> RiskResult:
    """Recompute risk for changed assets and propagate it up the dependency graph.

    ``assets`` maps node_id -> asset dict (findings, criticality, flags, type).
    ``edges`` are directed caller->callee dependency edges. When an asset's risk
    changes, every transitive dependent (consumer) inherits a lift so business
    services reflect the new exposure.
    """
    dependents = _reverse_edges(edges)
    result = RiskResult()

    # seed direct scores for all assets
    direct = {str(node_id): base_risk(asset) for node_id, asset in assets.items()}
    scores = dict(direct)

    # propagation up the dependency chain: a consumer's realized risk is at least
    # a decaying share (0.8 per hop) of each dependency's realized risk, capped.
    # Start from the changed asset(s) and walk consumers until a fixed point.
    seeds = [str(a) for a in (changed_assets or assets.keys())]
    queue = deque(seeds)
    if changed_assets:
        result.changed.extend(seeds)
    while queue:
        node = queue.popleft()
        for consumer in dependents.get(node, []):
            inherited = int(round(scores.get(node, 0) * 0.8))
            if inherited > scores.get(consumer, 0):
                scores[consumer] = min(SCORE_CAP, inherited)
                result.changed.append(consumer)
                queue.append(consumer)

    for node_id, score in scores.items():
        result.scores[node_id] = score
        result.bands[node_id] = risk_band(score)
        asset = assets.get(node_id, {})
        ntype = str(asset.get("type") or asset.get("kind") or "")
        if "business_service" in ntype or "service" == ntype:
            if score > 0:
                result.affected_business_services.append(
                    str(asset.get("name") or node_id))
    result.changed = sorted(set(result.changed))
    result.affected_business_services = sorted(set(result.affected_business_services))
    return result
