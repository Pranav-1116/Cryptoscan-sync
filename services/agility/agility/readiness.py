"""Five-factor migration readiness. Complements the 6-factor agility score."""

from __future__ import annotations

from typing import Any, Mapping


def _capacity(value: Any) -> float:
    raw = str(value or "MEDIUM").upper()
    return {"HIGH": 1.0, "MEDIUM": 0.6, "LOW": 0.3}.get(raw, 0.6)


def assess_readiness(
    *,
    agility_score: int | float = 0,
    dependency_count: int = 0,
    has_crypto_tests: bool = False,
    has_general_tests: bool = False,
    team_capacity: str = "MEDIUM",
    change_freeze: bool = False,
) -> dict[str, Any]:
    agility_factor = max(0.0, min(1.0, float(agility_score) / 100.0))
    if dependency_count <= 0:
        dependency_factor = 1.0
    elif dependency_count <= 3:
        dependency_factor = 0.8
    elif dependency_count <= 10:
        dependency_factor = 0.5
    else:
        dependency_factor = 0.2
    if has_crypto_tests:
        testing_factor = 1.0
    elif has_general_tests:
        testing_factor = 0.6
    else:
        testing_factor = 0.2
    freeze_factor = 0.5 if change_freeze else 1.0
    score = int(
        round(
            (
                agility_factor * 0.4
                + dependency_factor * 0.2
                + testing_factor * 0.2
                + _capacity(team_capacity) * 0.15
                + freeze_factor * 0.05
            )
            * 100
        )
    )
    if score >= 80:
        category = "READY_NOW"
        recommendation = "Can start migration immediately"
        wave = 1
    elif score >= 60:
        category = "READY_WITH_PREP"
        recommendation = "Needs 2-4 weeks prep"
        wave = 2
    elif score >= 40:
        category = "NOT_READY"
        recommendation = "Needs significant work (2-3 months)"
        wave = 2
    else:
        category = "BLOCKED"
        recommendation = "Cannot migrate until blockers are resolved"
        wave = 3
    return {
        "readiness_score": score,
        "readiness_category": category,
        "recommendation": recommendation,
        "wave": wave,
        "factors": {
            "agility": round(agility_factor, 3),
            "dependencies": dependency_factor,
            "testing": testing_factor,
            "team_capacity": _capacity(team_capacity),
            "freeze": freeze_factor,
        },
    }


def readiness_from_system(
    system: Mapping[str, Any],
    *,
    agility_score: int | float | None = None,
    dependency_count: int = 0,
) -> dict[str, Any]:
    extra = system.get("extra") or {}
    score = agility_score if agility_score is not None else system.get("current_agility_score") or 0
    return assess_readiness(
        agility_score=score or 0,
        dependency_count=dependency_count,
        has_crypto_tests=bool(extra.get("crypto_tests") or extra.get("has_crypto_test_suite")),
        has_general_tests=bool(extra.get("has_tests")),
        team_capacity=str(extra.get("team_capacity") or "MEDIUM"),
        change_freeze=bool(extra.get("change_freeze")),
    )
