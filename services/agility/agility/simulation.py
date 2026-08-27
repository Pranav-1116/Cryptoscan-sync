"""What-if agility simulation: re-run the real engine on a modified world.

Each action is a documented, deterministic transform of the evidence /
system payload — the score is then recomputed by calculate_agility_score
itself, so projections can never drift from the production formula.
"""

from __future__ import annotations

import copy
from typing import Any, Mapping

from agility.system_score import calculate_agility_score


def _extra(system: dict[str, Any]) -> dict[str, Any]:
    extra = system.setdefault("extra", {})
    if not isinstance(extra, dict):
        extra = {}
        system["extra"] = extra
    return extra


def _act_move_to_kms(evidence: list[dict[str, Any]], system: dict[str, Any]) -> str:
    extra = _extra(system)
    extra["kms"] = True
    extra["key_management"] = "KMS"
    return "assumes keys are managed by an external KMS (rotation and inventory off-device)"


def _act_remove_hardcoded_keys(evidence: list[dict[str, Any]], system: dict[str, Any]) -> str:
    for row in evidence:
        row["is_hardcoded_key"] = False
    _extra(system)["secrets_in_git"] = False
    return "assumes every hardcoded key is removed and no secrets remain in git"


def _act_centralize_wrapper(evidence: list[dict[str, Any]], system: dict[str, Any]) -> str:
    for row in evidence:
        row["file_path"] = "src/crypto_service/CryptoService.java"
        metadata = (row.get("finding_data") or {}).setdefault("metadata", {})
        if isinstance(metadata, dict):
            metadata["confidence_reason"] = "factory"
    return "assumes all crypto call sites route through one wrapper that selects the algorithm (factory pattern)"


def _act_externalize_config(evidence: list[dict[str, Any]], system: dict[str, Any]) -> str:
    extra = _extra(system)
    extra["configmap"] = True
    extra["config_baked_in_image"] = False
    return "assumes crypto config ships via ConfigMap/external config, not baked into the image"


def _act_add_crypto_tests(evidence: list[dict[str, Any]], system: dict[str, Any]) -> str:
    extra = _extra(system)
    extra["crypto_tests"] = True
    extra["parameterized_crypto_tests"] = True
    return "assumes a parameterized crypto test suite (known-answer vectors per algorithm)"


def _act_document_procedures(evidence: list[dict[str, Any]], system: dict[str, Any]) -> str:
    extra = _extra(system)
    extra["has_crypto_docs"] = True
    extra["has_crypto_inventory_docs"] = True
    extra["has_dr_plan"] = True
    return "assumes crypto change procedure, inventory docs, and a DR plan exist"


def _act_enable_hot_reload(evidence: list[dict[str, Any]], system: dict[str, Any]) -> str:
    _extra(system)["hot_reload"] = True
    return "assumes crypto config reloads without redeploy (watcher/SIGHUP)"


ACTIONS = {
    "move_to_kms": _act_move_to_kms,
    "remove_hardcoded_keys": _act_remove_hardcoded_keys,
    "centralize_wrapper": _act_centralize_wrapper,
    "externalize_config": _act_externalize_config,
    "add_crypto_tests": _act_add_crypto_tests,
    "document_procedures": _act_document_procedures,
    "enable_hot_reload": _act_enable_hot_reload,
}


def available_actions() -> list[str]:
    return sorted(ACTIONS)


def simulate_improvements(
    evidence: list[Mapping[str, Any]],
    system: Mapping[str, Any] | None,
    actions: list[str],
) -> dict[str, Any]:
    """Project the agility score after applying the requested actions."""
    current = calculate_agility_score(evidence, system)
    rows = copy.deepcopy([dict(row) for row in evidence])
    world = copy.deepcopy(dict(system or {}))
    applied: list[str] = []
    assumptions: list[str] = []
    unsupported: list[str] = []
    for action in actions:
        handler = ACTIONS.get(str(action))
        if handler is None:
            unsupported.append(str(action))
            continue
        assumptions.append(handler(rows, world))
        applied.append(str(action))
    projected = calculate_agility_score(rows, world)
    return {
        "projection": True,
        "actions_applied": applied,
        "unsupported_actions": unsupported,
        "assumptions": assumptions,
        "current": {
            "agility_score": current["agility_score"],
            "category": current["category"],
            "factor_scores": current["factor_scores"],
        },
        "projected": {
            "agility_score": projected["agility_score"],
            "category": projected["category"],
            "factor_scores": projected["factor_scores"],
        },
        "score_delta": projected["agility_score"] - current["agility_score"],
        "factor_deltas": {
            key: projected["factor_scores"][key] - current["factor_scores"][key]
            for key in current["factor_scores"]
        },
        "calculation_version": current["calculation_version"],
        "note": "projection only: nothing is persisted and the real system is unchanged",
    }
