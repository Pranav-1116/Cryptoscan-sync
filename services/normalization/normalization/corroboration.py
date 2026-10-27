"""Cross-source corroboration of agreed facts (report 49 P1#5, round 29).

The conflict detector answers "where do observers disagree?". This module
answers the complementary question the report asked for: "where do
*independent* observers AGREE — and how much more should that agreed fact
be trusted?"

Corroboration rules (deterministic, and deliberately conservative):

* Only **independent observers** corroborate: distinct scanner ids (or
  scan ids when scanners are unnamed). One scanner reporting a site
  twice is duplication, not corroboration — the evidence pipeline
  already collapses byte-identical repeats.
* Only **full agreement** corroborates: same normalized algorithm AND
  same parameters (key size / mode). Partial agreement is a conflict,
  and conflicts are the other endpoint's business.
* The uplift is tier-aware: agreement that spans **distinct authority
  tiers** (a static scanner and a runtime probe both saying RSA-2048)
  is stronger evidence than two same-tier scanners, because the
  observations were obtained by genuinely different methods.
* Annotation only: the uplift is *suggested* — recorded confidence is
  never rewritten (same contract as authority and calibration).

Uplift schedule (documented, bounded):

    2 independent observers, same tier      -> +0.05
    2 independent observers, distinct tiers -> +0.10
    3+ independent observers (any mix)      -> +0.15
    cap                                     -> +0.15

Pure functions over caller-supplied observation views; no database, no
clock, no network.
"""

from __future__ import annotations

from typing import Any, Iterable

from normalization.authority import authority_tier
from normalization.conflicts import _norm, _params, _site

#: suggested confidence uplift by corroboration strength
UPLIFT_SAME_TIER = 0.05
UPLIFT_DISTINCT_TIERS = 0.10
UPLIFT_THREE_PLUS = 0.15
UPLIFT_CAP = 0.15


def _observer(finding: dict[str, Any]) -> str:
    """The single observer identity of one view (first scanner id, else
    first scan id, else 'unknown-observer')."""
    for key in ("scanner_ids", "scan_ids"):
        value = finding.get(key)
        if isinstance(value, (list, tuple)) and value:
            return str(value[0])
        if isinstance(value, str) and value:
            return value
    return "unknown-observer"


def corroborated_facts(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Facts at sites where >= 2 independent observers fully agree.

    Returns one entry per agreed (site, algorithm, parameters) group,
    worst-first is unnecessary — entries are sorted by site for stable
    output. Sites with a single observer, and sites where observers
    disagree, are simply absent: this surface reports agreement only.
    """
    by_site: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for finding in findings or []:
        if not str(finding.get("file_path") or ""):
            continue
        by_site.setdefault(_site(finding), []).append(dict(finding))

    results: list[dict[str, Any]] = []
    for (file_path, line_number), group in sorted(by_site.items()):
        # group by the agreed fact: (algorithm, parameters)
        by_fact: dict[tuple[str, tuple[Any, ...]], list[dict[str, Any]]] = {}
        for finding in group:
            by_fact.setdefault((_norm(finding.get("algorithm")), _params(finding)),
                               []).append(finding)

        for (algorithm, params), observers in sorted(
                by_fact.items(), key=lambda item: str(item[0])):
            # independent observers only: same observer twice is not
            # corroboration
            distinct = {}
            for finding in observers:
                distinct[_observer(finding)] = finding
            if len(distinct) < 2:
                continue

            tiers = sorted({authority_tier(finding)["tier"]
                            for finding in distinct.values()})
            distinct_tiers = len(tiers) > 1

            if len(distinct) >= 3:
                uplift = UPLIFT_THREE_PLUS
            elif distinct_tiers:
                uplift = UPLIFT_DISTINCT_TIERS
            else:
                uplift = UPLIFT_SAME_TIER

            results.append({
                "file_path": file_path,
                "line_number": line_number,
                "algorithm": algorithm,
                "key_size": params[0],
                "mode": params[1],
                "observers": sorted(distinct),
                "observer_count": len(distinct),
                "authority_tiers": tiers,
                "distinct_authority_tiers": distinct_tiers,
                "suggested_confidence_uplift": uplift,
                "note": (f"{len(distinct)} independent observers agree"
                         + (" across distinct authority tiers" if distinct_tiers
                            else " at the same authority tier")
                         + " — annotation only; recorded confidence is never rewritten"),
            })
    return results


def corroboration_summary(findings: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Counts + method block for the corroboration surface."""
    facts = corroborated_facts(findings)
    tier_spanned = sum(1 for fact in facts if fact["distinct_authority_tiers"])
    return {
        "corroborated_facts": facts,
        "corroborated_count": len(facts),
        "tier_spanned_count": tier_spanned,
        "same_tier_count": len(facts) - tier_spanned,
        "max_uplift": max((f["suggested_confidence_uplift"] for f in facts), default=0.0),
        "uplift_schedule": {
            "two_observers_same_tier": UPLIFT_SAME_TIER,
            "two_observers_distinct_tiers": UPLIFT_DISTINCT_TIERS,
            "three_plus_observers": UPLIFT_THREE_PLUS,
            "cap": UPLIFT_CAP,
        },
        "method": {
            "independence": "distinct scanner ids (or scan ids); one scanner "
                            "twice is duplication, not corroboration",
            "agreement": "same normalized algorithm AND parameters — partial "
                         "agreement is a conflict, not corroboration",
            "tier_awareness": "agreement across distinct authority tiers is "
                              "stronger: the observations were obtained by "
                              "different methods",
            "contract": "suggested uplift only — recorded confidence is "
                        "never rewritten",
        },
    }
