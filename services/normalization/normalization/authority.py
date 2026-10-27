"""Observation authority model (report 49 P0 — formal evidence authority hierarchy).

When two observations of the same site disagree (see ``normalization.conflicts``),
the platform needs to say *which side deserves more trust* without silently
auto-resolving the conflict. This module ranks observers by how the evidence
was obtained — a 6-level explicit hierarchy:

    1. RUNTIME   — observed on the running system (live scanner, runtime probe)
    2. BINARY    — extracted from the built artifact (ELF/JAR/container image)
    3. STATIC    — read from the source tree (AST/tree-sitter/regex scanners)
    4. DECLARED  — declared in config/IaC (cloud config, YAML, pipelines)
    5. MANUAL    — supplied by a human (import, form entry)
    6. UNRANKED  — no recognizable provenance signal

Everything here is deterministic string-matching over the observation's
provenance fields (``scanner_ids``, ``source``, ``scan_method``). Unknown
provenance is honestly UNRANKED — never guessed.

The model never overrides data: ``authority_preference`` only *annotates* a
conflict with which observer would win under the hierarchy and whether that
preference is decisive (strictly higher tier, unique) or a tie that needs a
human/policy decision.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

#: tier number -> label (lower number = higher authority).
AUTHORITY_TIERS: dict[int, str] = {
    1: "RUNTIME",
    2: "BINARY",
    3: "STATIC",
    4: "DECLARED",
    5: "MANUAL",
    6: "UNRANKED",
}

#: tier label -> number.
TIER_BY_LABEL: dict[str, int] = {label: tier for tier, label in AUTHORITY_TIERS.items()}

_RUNTIME_TOKENS = ("live", "runtime", "runtime-", "dynatrace", "ebpf", "jfr", "probe")
_BINARY_TOKENS = ("binary", "elf", "jar", "dex", "image", "artifact", "container", "wheel", "so-file")
_STATIC_TOKENS = ("static", "ast", "tree-sitter", "treesitter", "regex", "semgrep", "git", "source")
_DECLARED_TOKENS = ("cloud", "config", "iac", "terraform", "yaml", "pipeline", "helm", "manifest")
_MANUAL_TOKENS = ("manual", "import", "form", "csv", "upload")


def _provenance_strings(observation: Mapping[str, Any]) -> list[str]:
    """Every provenance-bearing string on an observation, lowercased."""
    out: list[str] = []
    for key in ("scanner_ids", "scanner_id", "scan_method", "source", "collector"):
        value = observation.get(key)
        if isinstance(value, (list, tuple, set)):
            out.extend(str(v).lower() for v in value if v)
        elif isinstance(value, str) and value:
            out.append(value.lower())
        elif isinstance(value, Mapping):
            # finding_data.source dicts carry e.g. {"type": "RUNTIME", "name": ...}
            for sub in value.values():
                if isinstance(sub, str) and sub:
                    out.append(sub.lower())
    return out


def _tokens_indicate(strings: list[str], tokens: tuple[str, ...]) -> bool:
    return any(token in s for s in strings for token in tokens)


def authority_tier(observation: Mapping[str, Any]) -> dict[str, Any]:
    """Classify one observation's authority tier from its provenance.

    Returns ``{"tier": int, "label": str, "basis": [matched signals]}``.
    """
    strings = _provenance_strings(observation)
    for tier, tokens in (
        (1, _RUNTIME_TOKENS),
        (2, _BINARY_TOKENS),
        (3, _STATIC_TOKENS),
        (4, _DECLARED_TOKENS),
        (5, _MANUAL_TOKENS),
    ):
        matched = sorted({s for s in strings for t in tokens if t in s})
        if matched:
            return {"tier": tier, "label": AUTHORITY_TIERS[tier], "basis": matched[:5]}
    return {"tier": 6, "label": "UNRANKED", "basis": strings[:5] or ["no provenance fields"]}


def authority_preference(observations: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Which observer of a conflicting group the hierarchy would favor.

    Reports the best tier present, which observers hold it, and whether the
    preference is decisive (exactly one observer at the best tier and that
    tier is not UNRANKED). Never mutates or drops the observations.
    """
    ranked: list[tuple[dict, dict]] = []
    for obs in observations or []:
        ranked.append((dict(obs), authority_tier(obs)))
    if not ranked:
        return {"decisive": False, "best_tier": None, "label": None, "preferred": [], "note": "no observations"}

    best = min(r["tier"] for _, r in ranked)
    holders = [obs for obs, r in ranked if r["tier"] == best]
    basis = [r for _, r in ranked if r["tier"] == best]
    if best == TIER_BY_LABEL["UNRANKED"]:
        note = "no recognizable provenance on any side — human/policy decision required"
        decisive = False
    elif len(holders) == 1:
        note = "single highest-authority observer under the evidence hierarchy"
        decisive = True
    else:
        note = "tie at the highest tier — human/policy decision required"
        decisive = False
    return {
        "decisive": decisive,
        "best_tier": best,
        "label": AUTHORITY_TIERS[best],
        "preferred": [
            {
                "observer": (obs.get("scanner_ids") or obs.get("scan_ids") or [None])[0],
                "tier": b["tier"],
                "label": b["label"],
                "basis": b["basis"],
            }
            for obs, b in zip(holders, basis)
        ],
        "note": note,
    }
