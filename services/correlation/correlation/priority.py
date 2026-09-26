"""Deterministic remediation prioritization.

Folds real findings (drift events, runtime findings) through the correlation
engine and ranks them: priority = revenue_impact x severity x agility, with
effort = asset_count x complexity x (2 - agility). Every number is derived
from platform data — business-process revenue mapping and system agility
scores when linked, conservative neutral defaults otherwise. No AI, no
invented values.
"""

from __future__ import annotations

from typing import Any

from correlation.engine import analyze

# must mirror the weight map pinned inside correlation.engine.analyze()
SEVERITY_WEIGHT = {"CRITICAL": 5, "HIGH": 4, "ALERT": 3, "MEDIUM": 2, "LOW": 1}


def revenue_tier(revenue_daily: float | None, customer_count: int | None = None) -> int:
    """Deterministic 1..5 revenue-impact band from business-process facts.

    Bands (per process, per day): 0 -> 1, <10k -> 2, <100k -> 3,
    <1M -> 4, >=1M -> 5. Customer count bumps one tier at >=10k customers.
    """
    if revenue_daily is None or revenue_daily <= 0:
        tier = 1
    elif revenue_daily < 10_000:
        tier = 2
    elif revenue_daily < 100_000:
        tier = 3
    elif revenue_daily < 1_000_000:
        tier = 4
    else:
        tier = 5
    if customer_count is not None and customer_count >= 10_000 and tier < 5:
        tier += 1
    return tier


def agility_fraction(agility_score: int | float | None) -> float:
    """6-factor agility score (0..100) -> correlation agility fraction 0..1."""
    if agility_score is None:
        return 0.5  # honest neutral: unknown agility neither boosts nor sinks
    return max(0.0, min(1.0, float(agility_score) / 100.0))


def build_input(*, kind: str, severity: str, target: str, evidence: str,
                algorithm: str | None = None, asset_count: int = 1,
                complexity: float = 1.0, revenue_impact: int = 3,
                agility: float = 0.5) -> dict[str, Any]:
    """One correlation-engine finding dict with platform-derived context."""
    return {
        "kind": kind, "severity": severity, "endpoint": target,
        "evidence": evidence, "algorithm": algorithm,
        "asset_count": asset_count, "complexity": complexity,
        "revenue_impact": revenue_impact, "agility": agility,
    }


def rank_reports(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rank by priority desc, then effort asc (cheap+critical first), then id
    for full determinism."""
    ordered = sorted(
        reports,
        key=lambda r: (-float(r["priority"]), float(r["effort"]),
                       str(r.get("ref_id") or "")),
    )
    for i, r in enumerate(ordered, start=1):
        r["rank"] = i
    return ordered


def prioritize(events: list[dict[str, Any]], *, graph: dict[str, list[str]] | None = None,
               profile: str = "default") -> list[dict[str, Any]]:
    """events: pre-built correlation inputs (see build_input) each carrying
    ``ref_id``/``source`` bookkeeping keys. Returns ranked full reports."""
    reports = []
    for ev in events:
        ev = dict(ev)
        ref_id = ev.pop("ref_id", None)
        source = ev.pop("source", "finding")
        report = analyze(ev, graph=graph, profile=profile)
        report["ref_id"] = ref_id
        report["source"] = source
        report["severity_in"] = ev.get("severity")
        reports.append(report)
    return rank_reports(reports)


def counts_by_severity(ranked: list[dict[str, Any]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in ranked:
        sev = str(r.get("severity_in") or "?")
        out[sev] = out.get(sev, 0) + 1
    # always expose the standard scale for stable UI rendering
    for sev in SEVERITY_WEIGHT:
        out.setdefault(sev, 0)
    return out
