"""Trust model (report 79 P0#3): the platform's evidence-trust rules, exposed.

Every trust decision the platform makes is governed by explicit, versioned
rules — which observer outranks which, how evidence classes rot with age,
how confidence bands are computed, how disagreements are surfaced. Until
now those rules lived in module docstrings and constant tables that a
consumer had to read source to find. This endpoint publishes them as one
machine-readable document, imported live from the governing modules so the
API can never drift from the code that actually enforces it.

Honesty notes (part of the model, not marketing):

* No AI runs in the deterministic path — every score here is deterministic
  string/number logic, replayable from the recorded inputs.
* Unknown provenance is UNRANKED, never guessed.
* Conflicts are annotated, never auto-resolved.
* An old verification decays but never silently becomes "no evidence".
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from api.dependencies import get_current_user

router = APIRouter(prefix="/trust-model", tags=["trust-model"])


def _authority_section() -> dict[str, Any]:
    from normalization.authority import AUTHORITY_TIERS

    return {
        "tiers": [
            {"tier": tier, "label": label,
             "meaning": {
                 "RUNTIME": "observed on the running system (live scanner, probe)",
                 "BINARY": "extracted from the built artifact (ELF/JAR/image)",
                 "STATIC": "read from the source tree (AST/regex scanners)",
                 "DECLARED": "declared in config/IaC (cloud config, pipelines)",
                 "MANUAL": "supplied by a human (import, form entry)",
                 "UNRANKED": "no recognizable provenance — never guessed",
             }.get(label)}
            for tier, label in sorted(AUTHORITY_TIERS.items())
        ],
        "usage": "conflicts carry an authority annotation: which observer the "
                 "hierarchy favors, and whether that preference is decisive",
        "module": "services/normalization/normalization/authority.py",
    }


def _confidence_section() -> dict[str, Any]:
    from universal_crypto.confidence import (CONFIRMATORY_WEIGHT, CONFIRMED_MIN,
                                             DEFAULT_WEIGHTS, HIGH_MIN, LOW_MIN,
                                             MEDIUM_MIN)

    return {
        "base_weights": DEFAULT_WEIGHTS,
        "confirmatory_weights": CONFIRMATORY_WEIGHT,
        "bands": [
            {"band": "CONFIRMED", "min": CONFIRMED_MIN, "max": 100},
            {"band": "HIGH", "min": HIGH_MIN, "max": CONFIRMED_MIN - 1},
            {"band": "MEDIUM", "min": MEDIUM_MIN, "max": HIGH_MIN - 1},
            {"band": "LOW", "min": LOW_MIN, "max": MEDIUM_MIN - 1},
            {"band": "UNCONFIRMED", "min": 0, "max": LOW_MIN - 1},
        ],
        "calibration": "weights are fitted to a labeled corpus by deterministic "
                       "coordinate ascent (F1); a test re-runs the calibration "
                       "and asserts stability",
        "module": "services/universal_crypto/universal_crypto/confidence.py",
    }


def _freshness_section() -> dict[str, Any]:
    from privacy.state import (DEFAULT_EVIDENCE_HALF_LIFE, DEFAULT_FRESHNESS,
                               EVIDENCE_HALF_LIVES, SOURCE_RELIABILITY,
                               VERIFICATION_STATES, VERIFIED_DECAY_FLOOR)

    return {
        "decay": {
            "model": "exponential: factor = 0.5 ** (age / half_life)",
            "half_life_seconds_by_evidence_class": EVIDENCE_HALF_LIVES,
            "default_half_life_seconds": DEFAULT_EVIDENCE_HALF_LIFE,
            "verified_floor": VERIFIED_DECAY_FLOOR,
            "never_observed": 0.0,
            "notes": "runtime observations rot fast (the system keeps "
                     "changing); artifact evidence persists longer",
        },
        "staleness_windows_seconds": DEFAULT_FRESHNESS,
        "source_reliability": SOURCE_RELIABILITY,
        "verification_states": list(VERIFICATION_STATES),
        "module": "services/privacy/privacy/state.py",
    }


def _conflict_section() -> dict[str, Any]:
    from normalization.conflicts import (ALGORITHM_MISMATCH, PARAMETER_MISMATCH,
                                         STATUS_MISMATCH)

    return {
        "classes": [ALGORITHM_MISMATCH, PARAMETER_MISMATCH, STATUS_MISMATCH],
        "resolution": "annotated, never auto-resolved — resolution stays a "
                      "human/policy decision",
        "retracted_evidence": "excluded — soft-deleted evidence cannot "
                              "manufacture conflicts",
        "endpoint": "GET /findings/conflicts",
        "module": "services/normalization/normalization/conflicts.py",
    }


@router.get("")
def trust_model(user: str = Depends(get_current_user)) -> dict[str, Any]:
    """The complete, enforced trust model — imported live from the modules
    that implement it, so this document cannot drift from the code."""
    return {
        "source": "trust_model",
        "authority": _authority_section(),
        "confidence": _confidence_section(),
        "freshness": _freshness_section(),
        "conflicts": _conflict_section(),
        "ai_boundary": {
            "deterministic_path": "no AI runs anywhere in scoring, detection, "
                                  "or conflict resolution; every value is "
                                  "replayable from recorded inputs",
            "labels": "surfaces that involve probabilistic components are "
                      "labeled as such at the surface itself",
        },
    }
