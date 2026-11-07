"""Risk dimensions — five separate, explainable, reproducible scores (roadmap item 7).

Risk in a crypto estate is not one number. This module produces the five
dimensions the roadmap names — **crypto risk**, **quantum urgency**,
**operational dependency**, **evidence confidence**, **vendor risk** — each on
its own, each carrying the exact rules and evidence that produced it:

* every factor row names its rule id, its input and its contribution, so a score
  can be re-derived by hand from the report alone;
* the functions are pure and clock-free (``now`` is always passed in when age
  matters): the same inputs always produce byte-identical reports;
* a dimension with no evidence is ``None`` with a reason — "I do not know this
  value" is never scored as "this value is fine";
* the five are never blended into one opaque number unless a caller explicitly
  asks, and a blended number always shows its arithmetic and the dimensions it
  had to exclude.

Scores are 0–100 where higher means more risk, except ``EVIDENCE_CONFIDENCE``
where higher means more confidence in the data itself. The report says so at the
point of use, because a dimension misread is a decision mis-made.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

RISK_SCHEMA = "cryptoscan.risk-dimensions/1"
RISK_RULES_VERSION = "risk-dimensions/1"

#: the five dimensions, kept separate on purpose
CRYPTO_RISK = "CRYPTO_RISK"
QUANTUM_URGENCY = "QUANTUM_URGENCY"
OPERATIONAL_DEPENDENCY = "OPERATIONAL_DEPENDENCY"
EVIDENCE_CONFIDENCE = "EVIDENCE_CONFIDENCE"
VENDOR_RISK = "VENDOR_RISK"
DIMENSIONS: tuple[str, ...] = (
    CRYPTO_RISK, QUANTUM_URGENCY, OPERATIONAL_DEPENDENCY,
    EVIDENCE_CONFIDENCE, VENDOR_RISK,
)

BANDS: tuple[tuple[int, str], ...] = (
    (75, "CRITICAL"), (50, "HIGH"), (25, "MEDIUM"), (0, "LOW"),
)


def _band(score: int) -> str:
    for threshold, name in BANDS:
        if score >= threshold:
            return name
    return "LOW"


def _unknown(reason: str, *, dimension: str, sense: str = "risk") -> dict[str, Any]:
    return {
        "dimension": dimension, "score": None, "band": "UNKNOWN", "sense": sense,
        "factors": [], "evidence_ids": [],
        "reason": reason,
        "known": False,
        "note": ("an unknown dimension is not a zero: it is not scored and must "
                 "never be read as 'no risk'"),
    }


def _scored(*, dimension: str, score: int, factors: list[dict[str, Any]],
            evidence_ids: list[str], sense: str = "risk",
            reason: str | None = None) -> dict[str, Any]:
    score = max(0, min(100, int(score)))
    return {
        "dimension": dimension, "score": score,
        "band": (_band(score) if sense == "risk" else
                 ("HIGH_CONFIDENCE" if score >= 75 else
                  "MEDIUM_CONFIDENCE" if score >= 40 else "LOW_CONFIDENCE")),
        "sense": sense, "factors": factors,
        "evidence_ids": sorted(set(evidence_ids)),
        "reason": reason, "known": True,
        "rules_version": RISK_RULES_VERSION,
    }


def _info_view(algorithm_info: Any) -> Mapping[str, Any] | None:
    """Accept a registry ``AlgorithmInfo`` or a plain mapping — one view of either."""
    if algorithm_info is None:
        return None
    if isinstance(algorithm_info, Mapping):
        return algorithm_info
    if hasattr(algorithm_info, "to_dict"):
        return algorithm_info.to_dict()
    return {key: value for key, value in vars(algorithm_info).items()}


def score_crypto_risk(*, algorithm_info: Mapping[str, Any] | None,
                      usage_state: str | None = None,
                      evidence_ids: Sequence[str] = ()) -> dict[str, Any]:
    """Crypto risk from the algorithm's standing, its quantum class and its use.

    Rules (each appears in the factors with its contribution):

    * ``CR-1`` registry status — DISALLOWED +50, DEPRECATED +35, RESTRICTED +15,
      ALLOWED +0; an unrecognised algorithm is unscoreable, not safe;
    * ``CR-2`` quantum impact — Shor-broken +30, Grover-weakened +10;
    * ``CR-3`` key below the family's minimum size +25;
    * ``CR-4`` live use (NEGOTIATED/OBSERVED) +10, configured +5 — capability is
      not usage and scores less than usage.
    """
    info = _info_view(algorithm_info)
    if not info or not info.get("recognized"):
        return _unknown(
            "the algorithm is not in the registry, so its standing cannot be "
            "scored: an unrecognised algorithm is not a low-risk algorithm",
            dimension=CRYPTO_RISK)
    status = str(info.get("status") or "UNKNOWN").upper()
    impact = info.get("quantum_impact")
    factors: list[dict[str, Any]] = []
    total = 0
    evidence = [str(e) for e in evidence_ids]

    status_points = {"DISALLOWED": 50, "DEPRECATED": 35, "RESTRICTED": 15,
                     "ALLOWED": 0}.get(status)
    if status_points is None:
        return _unknown(
            f"registry status {status!r} cannot be scored",
            dimension=CRYPTO_RISK)
    factors.append({"rule": "CR-1", "input": f"registry status {status}",
                    "contribution": status_points, "evidence_ids": evidence})
    total += status_points

    if impact == "shor":
        factors.append({"rule": "CR-2", "input": "Shor-broken public-key algorithm",
                        "contribution": 30, "evidence_ids": evidence})
        total += 30
    elif impact == "grover":
        factors.append({"rule": "CR-2", "input": "Grover-weakened symmetric algorithm",
                        "contribution": 10, "evidence_ids": evidence})
        total += 10

    minimum = info.get("min_key_size")
    key_size = info.get("key_size")
    if minimum and key_size and int(key_size) < int(minimum):
        factors.append({"rule": "CR-3",
                        "input": f"key size {key_size} below family minimum {minimum}",
                        "contribution": 25, "evidence_ids": evidence})
        total += 25

    state = str(usage_state or "").upper()
    if state in {"NEGOTIATED", "OBSERVED"}:
        factors.append({"rule": "CR-4", "input": f"live use ({state})",
                        "contribution": 10, "evidence_ids": evidence})
        total += 10
    elif state == "CONFIGURED":
        factors.append({"rule": "CR-4", "input": "configured use",
                        "contribution": 5, "evidence_ids": evidence})
        total += 5

    return _scored(dimension=CRYPTO_RISK, score=total, factors=factors,
                   evidence_ids=evidence)


def score_quantum_urgency(*, algorithm_info: Mapping[str, Any] | None,
                          usage_state: str | None = None,
                          data_shelf_life_years: float = 0.0,
                          migration_lead_time_years: float = 0.0,
                          quantum_threat_horizon_years: float | None = None,
                          evidence_ids: Sequence[str] = ()) -> dict[str, Any]:
    """Quantum urgency from impact class, data lifetime and an explicit horizon.

    The threat horizon is a **policy input**: different banks and different
    authorities set different dates, and a platform that hides one inside a
    default is making national threat policy in a config file. With no horizon
    given, this dimension refuses to score.

    Rules: ``QU-1`` impact class — Shor +40, Grover +10, post-quantum +0, unknown
    class unscoreable; ``QU-2`` exposure window (shelf life + lead time − horizon)
    — over 10y +30, 1–10y +20, 0–1y +10, non-positive +0; ``QU-3`` live use
    NEGOTIATED/OBSERVED +15, CONFIGURED +8, capability +0.
    """
    if quantum_threat_horizon_years is None:
        return _unknown(
            "quantum urgency cannot be dated without an explicit threat horizon: "
            "that horizon is a policy input, not a platform default",
            dimension=QUANTUM_URGENCY)
    info = _info_view(algorithm_info)
    if not info:
        return _unknown("no algorithm to date", dimension=QUANTUM_URGENCY)
    impact = info.get("quantum_impact")
    pq = (bool(info.get("post_quantum"))
          or "pqc" in str(info.get("family") or "").lower())
    if impact not in {"shor", "grover"} and not pq:
        return _unknown(
            "the algorithm's quantum impact is unclassified, so its urgency "
            "cannot be dated: unknown is not 'not urgent'",
            dimension=QUANTUM_URGENCY)
    factors: list[dict[str, Any]] = []
    total = 0
    evidence = [str(e) for e in evidence_ids]

    if pq:
        factors.append({"rule": "QU-1", "input": "post-quantum algorithm",
                        "contribution": 0, "evidence_ids": evidence})
    elif impact == "shor":
        factors.append({"rule": "QU-1", "input": "Shor-broken: harvest-now-decrypt-later applies",
                        "contribution": 40, "evidence_ids": evidence})
        total += 40
    else:
        factors.append({"rule": "QU-1", "input": "Grover-weakened",
                        "contribution": 10, "evidence_ids": evidence})
        total += 10

    exposure = (float(data_shelf_life_years) + float(migration_lead_time_years)
                - float(quantum_threat_horizon_years))
    if exposure > 10:
        points = 30
    elif exposure > 1:
        points = 20
    elif exposure > 0:
        points = 10
    else:
        points = 0
    factors.append({
        "rule": "QU-2",
        "input": (f"exposure window {exposure:.2f}y = shelf {data_shelf_life_years}y "
                  f"+ lead {migration_lead_time_years}y − horizon "
                  f"{quantum_threat_horizon_years}y"),
        "contribution": points, "evidence_ids": evidence})
    total += points

    state = str(usage_state or "").upper()
    if state in {"NEGOTIATED", "OBSERVED"}:
        factors.append({"rule": "QU-3", "input": f"live use ({state})",
                        "contribution": 15, "evidence_ids": evidence})
        total += 15
    elif state == "CONFIGURED":
        factors.append({"rule": "QU-3", "input": "configured use",
                        "contribution": 8, "evidence_ids": evidence})
        total += 8

    return _scored(dimension=QUANTUM_URGENCY, score=total, factors=factors,
                   evidence_ids=evidence)


def score_operational_dependency(*, dependents: int,
                                 proven_chains: int = 0,
                                 inferred_chains: int = 0,
                                 unknown_chains: int = 0) -> dict[str, Any]:
    """Blast radius: how much of the estate rides on this asset.

    Rules: ``OD-1`` dependents +12 each, capped at 60; ``OD-2`` proven dependency
    chains +8 each capped at 20; ``OD-3`` inferred chains +4 each capped at 10;
    ``OD-4`` unknown chains +3 each capped at 10 — unknown chains add caution
    (the blast radius is unmeasured, which is not zero blast radius) but never
    add confidence.
    """
    count = max(0, int(dependents))
    if count == 0 and proven_chains == 0 and inferred_chains == 0 and unknown_chains == 0:
        return _scored(
            dimension=OPERATIONAL_DEPENDENCY, score=0,
            factors=[{"rule": "OD-1", "input": "no dependents recorded",
                      "contribution": 0, "evidence_ids": []}],
            evidence_ids=[], reason="nothing recorded as depending on this asset")
    factors = [
        {"rule": "OD-1", "input": f"{count} dependent(s)",
         "contribution": min(60, count * 12), "evidence_ids": []},
        {"rule": "OD-2", "input": f"{max(0, int(proven_chains))} proven chain(s)",
         "contribution": min(20, max(0, int(proven_chains)) * 8), "evidence_ids": []},
        {"rule": "OD-3", "input": f"{max(0, int(inferred_chains))} inferred chain(s)",
         "contribution": min(10, max(0, int(inferred_chains)) * 4), "evidence_ids": []},
        {"rule": "OD-4", "input": f"{max(0, int(unknown_chains))} unknown chain(s)",
         "contribution": min(10, max(0, int(unknown_chains)) * 3), "evidence_ids": []},
    ]
    total = sum(f["contribution"] for f in factors)
    return _scored(dimension=OPERATIONAL_DEPENDENCY, score=total, factors=factors,
                   evidence_ids=[], reason=None)


def score_evidence_confidence(*, records: Sequence[Mapping[str, Any]],
                              now: Any = None) -> dict[str, Any]:
    """Confidence in the data behind a subject — the one dimension where high is good.

    Rules: ``EC-1`` each record contributes by its age-tracked confidence
    (HIGH +25, MEDIUM +15, LOW +5, UNKNOWN +0), capped at 100. No records is
    ``None``: no evidence is not full confidence and not zero risk.
    """
    from shared_models.evidence_freshness import tracked_confidence  # local: no cycle

    rows = list(records)
    if not rows:
        return _unknown(
            "no evidence records: confidence in this subject's data is unknown, "
            "which is never full confidence",
            dimension=EVIDENCE_CONFIDENCE, sense="confidence")
    points = {"HIGH": 25, "MEDIUM": 15, "LOW": 5, "UNKNOWN": 0}

    def _ids(record: Mapping[str, Any]) -> list[str]:
        out = [str(e) for e in (record.get("evidence_ids") or [])]
        if record.get("evidence_id"):
            out.append(str(record["evidence_id"]))
        return out

    factors: list[dict[str, Any]] = []
    evidence: list[str] = []
    total = 0
    for record in rows:
        tracked = tracked_confidence(record, now=now)
        contribution = points.get(tracked["effective"], 0)
        ids = _ids(record)
        evidence.extend(ids)
        factors.append({
            "rule": "EC-1",
            "input": (f"record {record.get('evidence_type')} "
                      f"effective confidence {tracked['effective']} "
                      f"(freshness {tracked['freshness']['state']})"),
            "contribution": contribution, "evidence_ids": ids})
        total += contribution
    return _scored(dimension=EVIDENCE_CONFIDENCE, score=total, factors=factors,
                   evidence_ids=evidence, sense="confidence")


def score_vendor_risk(*, vendor: str | None,
                      support_state: str | None = None,
                      eol_announced: bool = False,
                      pqc_roadmap_gap: bool = False,
                      evidence_ids: Sequence[str] = ()) -> dict[str, Any]:
    """Vendor risk from support standing and roadmap facts — never from reputation.

    Rules: ``VR-1`` support state — SUPPORTED +0, LIMITED +25, MAINTENANCE +35,
    EOL +60, unknown state unscoreable; ``VR-2`` EOL announced +20;
    ``VR-3`` no PQC roadmap +15 (a quantum blocker in slow motion).
    """
    if not vendor:
        return _unknown("no vendor named: vendor risk is unknown, never zero",
                        dimension=VENDOR_RISK)
    state = str(support_state or "").upper()
    base = {"SUPPORTED": 0, "LIMITED": 25, "MAINTENANCE": 35, "EOL": 60}.get(state)
    if base is None:
        return _unknown(
            f"support state {support_state!r} for {vendor!r} cannot be scored: "
            f"unknown support is not good support",
            dimension=VENDOR_RISK)
    evidence = [str(e) for e in evidence_ids]
    factors = [{"rule": "VR-1", "input": f"{vendor} support state {state}",
                "contribution": base, "evidence_ids": evidence}]
    total = base
    if eol_announced:
        factors.append({"rule": "VR-2", "input": "end-of-life announced",
                        "contribution": 20, "evidence_ids": evidence})
        total += 20
    if pqc_roadmap_gap:
        factors.append({"rule": "VR-3", "input": "no PQC roadmap",
                        "contribution": 15, "evidence_ids": evidence})
        total += 15
    return _scored(dimension=VENDOR_RISK, score=total, factors=factors,
                   evidence_ids=evidence)


def risk_profile(*, crypto_risk: Mapping[str, Any] | None = None,
                 quantum_urgency: Mapping[str, Any] | None = None,
                 operational_dependency: Mapping[str, Any] | None = None,
                 evidence_confidence: Mapping[str, Any] | None = None,
                 vendor_risk: Mapping[str, Any] | None = None,
                 blended: bool = False) -> dict[str, Any]:
    """The five dimensions side by side. Blending is opt-in and always shows its work.

    A dimension passed as ``None`` (or not passed) is reported as UNKNOWN with a
    reason — it is excluded from any blend and named in ``excluded_dimensions``,
    because averaging around a blind spot is how blind spots become scores.
    """
    provided = {
        CRYPTO_RISK: crypto_risk,
        QUANTUM_URGENCY: quantum_urgency,
        OPERATIONAL_DEPENDENCY: operational_dependency,
        EVIDENCE_CONFIDENCE: evidence_confidence,
        VENDOR_RISK: vendor_risk,
    }
    dimensions: dict[str, Any] = {}
    excluded: list[str] = []
    contributions: list[dict[str, Any]] = []
    for name in DIMENSIONS:
        value = provided[name]
        if value is None:
            dimensions[name] = _unknown(
                "not provided to this profile: unknown, never assumed zero",
                dimension=name,
                sense="confidence" if name == EVIDENCE_CONFIDENCE else "risk")
            excluded.append(name)
        else:
            dimensions[name] = dict(value)
            if value.get("known") and value.get("sense") == "risk":
                contributions.append({"dimension": name, "score": value["score"]})
            elif not value.get("known"):
                excluded.append(name)

    blended_score: float | None = None
    arithmetic: list[str] = []
    if blended:
        if contributions:
            blended_score = round(
                sum(c["score"] for c in contributions) / len(contributions), 2)
            arithmetic = [f"{c['dimension']}={c['score']}" for c in contributions]
        else:
            blended_score = None
    return {
        "schema": RISK_SCHEMA,
        "rules_version": RISK_RULES_VERSION,
        "dimensions": dimensions,
        "blended_requested": bool(blended),
        "blended_score": blended_score,
        "blended_arithmetic": arithmetic,
        "excluded_dimensions": excluded,
        "note": ("five dimensions, five separate scores; a blended number is "
                 "optional, explicit and never replaces the dimensions — and an "
                 "unknown dimension is excluded from blends instead of being "
                 "averaged as zero"),
    }
