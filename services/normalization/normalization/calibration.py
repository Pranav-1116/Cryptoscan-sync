"""Detector calibration scorecards (report 49 P0#4, round 28).

Report 49 asked for per-collector calibration: track false positives /
negatives per detector and weight accordingly. Production has no labeled
ground truth, so this module measures the two honest proxies the platform
already records:

* **Retractions** — evidence soft-deleted after the fact
  (``deleted_at`` tombstone, migration 0075). A retraction is an
  operator's judgment that an observation was wrong; a detector whose
  observations keep getting retracted is manufacturing false positives.
* **Authority losses** — when observers disagree at the same site, the
  6-tier authority hierarchy (``normalization.authority``) says which
  side it would favor. A detector that repeatedly sits on the
  non-preferred side of *decisive* conflicts disagrees with better
  evidence.

Both are proxies and this module says so in every payload: a retraction
is not a labeled FP, an authority loss is disagreement, not error. The
scorecard annotates — it never rewrites recorded confidence (the same
annotate-never-override contract as conflicts and authority).

Everything is deterministic counting over the caller-supplied views and
conflicts; no database, no clock, no network.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

#: minimum observations before a tier is assigned — thin data is
#: reported as thin, never scored.
MIN_OBSERVATIONS = 20

#: tier thresholds (retraction rate, decisive-loss rate)
CALIBRATED_MAX = (0.05, 0.10)
WATCH_MAX = (0.15, 0.25)

#: annotation multiplier by tier — for consumers of the scorecard to
#: apply (or ignore) in their own scoring; never auto-applied to
#: recorded evidence.
RELIABILITY_MULTIPLIER = {
    "CALIBRATED": 1.0,
    "WATCH": 0.9,
    "DEGRADED": 0.7,
}

UNATTRIBUTED = "UNATTRIBUTED"


def detector_key(view: Mapping[str, Any]) -> str:
    """The observer identity of one evidence view, honestly resolved.

    Order: explicit ``scanner_ids``, then the provenance block's scanner
    id(s), then the finding source's scanner id. Evidence nobody claims
    is ``UNATTRIBUTED`` — a real class worth surfacing, not an error.
    """
    ids = view.get("scanner_ids") or []
    if isinstance(ids, str):
        ids = [ids]
    if ids:
        return str(ids[0])

    provenance = view.get("provenance")
    if isinstance(provenance, Mapping):
        p_ids = provenance.get("scanner_ids") or []
        if isinstance(p_ids, str):
            p_ids = [p_ids]
        if p_ids:
            return str(p_ids[0])
        if provenance.get("scanner_id"):
            return str(provenance["scanner_id"])

    finding = view.get("finding_data")
    if isinstance(finding, Mapping):
        source = finding.get("source")
        if isinstance(source, Mapping) and source.get("scanner_id"):
            return str(source["scanner_id"])
    return UNATTRIBUTED


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def detector_scorecards(views: Iterable[Mapping[str, Any]],
                        conflicts: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Score every detector over the supplied evidence views + conflicts.

    ``views`` are evidence records as dicts (the same shape the conflicts
    endpoint builds, plus a ``deleted`` flag). ``conflicts`` are entries
    from ``normalization.conflicts.detect_conflicts`` — their
    ``observers`` list and ``authority`` annotation drive the
    disagreement accounting.
    """
    observations: dict[str, int] = {}
    retractions: dict[str, int] = {}

    for view in views or []:
        key = detector_key(view)
        observations[key] = observations.get(key, 0) + 1
        if view.get("deleted"):
            retractions[key] = retractions.get(key, 0) + 1

    involved: dict[str, int] = {}
    losses: dict[str, int] = {}

    for conflict in conflicts or []:
        authority = conflict.get("authority") or {}
        preferred = {
            str(entry.get("observer"))
            for entry in (authority.get("preferred") or [])
            if entry.get("observer")
        }
        decisive = bool(authority.get("decisive"))
        for observer in conflict.get("observers") or []:
            name = str(observer)
            involved[name] = involved.get(name, 0) + 1
            # only a DECISIVE conflict has a favored side to lose;
            # a tie is a human/policy decision, not a detector failure
            if decisive and name not in preferred:
                losses[name] = losses.get(name, 0) + 1

    cards: list[dict[str, Any]] = []
    for name in sorted(observations):
        n = observations[name]
        retracted = retractions.get(name, 0)
        retraction_rate = _rate(retracted, n)
        conflict_n = involved.get(name, 0)
        lost = losses.get(name, 0)
        # loss share is measured against the detector's OWN observations,
        # not its conflict count: one disagreement out of one conflict is
        # not a pattern, one disagreement out of every fifth observation is
        loss_rate = _rate(lost, n)

        if n < MIN_OBSERVATIONS:
            tier = "INSUFFICIENT_DATA"
        elif (retraction_rate <= CALIBRATED_MAX[0]
              and loss_rate <= CALIBRATED_MAX[1]):
            tier = "CALIBRATED"
        elif (retraction_rate <= WATCH_MAX[0]
              and loss_rate <= WATCH_MAX[1]):
            tier = "WATCH"
        else:
            tier = "DEGRADED"

        cards.append({
            "detector": name,
            "observations": n,
            "retracted": retracted,
            "retraction_rate": retraction_rate,
            "conflicts_involved": conflict_n,
            "authority_losses": lost,
            "authority_loss_rate": loss_rate,
            "calibration_tier": tier,
            "reliability_multiplier": RELIABILITY_MULTIPLIER.get(tier),
        })

    tier_counts: dict[str, int] = {}
    for card in cards:
        tier_counts[card["calibration_tier"]] = tier_counts.get(card["calibration_tier"], 0) + 1

    return {
        "detectors": cards,
        "detector_count": len(cards),
        "tier_counts": tier_counts,
        "method": {
            "retraction": "soft-deleted evidence (migration 0075) as the "
                          "false-positive proxy — operator judgment, not "
                          "labeled ground truth",
            "authority_loss": "non-preferred side of a DECISIVE conflict "
                              "under the 6-tier hierarchy — disagreement, "
                              "not proven error; the loss share is measured "
                              "against the detector's own observation count",
            "thresholds": {
                "min_observations": MIN_OBSERVATIONS,
                "calibrated_max": {"retraction_rate": CALIBRATED_MAX[0],
                                   "authority_loss_rate": CALIBRATED_MAX[1]},
                "watch_max": {"retraction_rate": WATCH_MAX[0],
                              "authority_loss_rate": WATCH_MAX[1]},
            },
            "contract": "annotation only — recorded confidence is never "
                        "rewritten; consumers apply the multiplier "
                        "themselves, or not at all",
        },
    }
