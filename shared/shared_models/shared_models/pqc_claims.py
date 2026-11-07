"""PQC migration-stage claims (roadmap item 3).

``pqc_readiness()`` in :mod:`shared_models.estate_graph` classifies what was
*observed*. This module tracks the five **migration-stage claims** a bank's PQC
program actually moves through, each one separately and each one evidence-backed:

* ``SUPPORT_AVAILABLE`` — something (a library, HSM, endpoint) *can* do PQC;
* ``CONFIGURED`` — PQC is configured;
* ``RUNTIME_OBSERVED`` — a PQC operation was observed at runtime;
* ``NETWORK_NEGOTIATED`` — a protocol actually negotiated PQC;
* ``MIGRATION_VALIDATED`` — the migration was verified after implementation.

The rule this module exists to enforce: **support is not readiness.** A library
supporting ML-KEM makes ``SUPPORT_AVAILABLE`` true and nothing else. Readiness is
only ever reported from validated, direct, still-fresh evidence — and a subject
with no evidence is ``NO_EVIDENCE``, which is not "fine" and not "ready".

Claims are never overwritten: two claims that disagree stay side by side and the
subject reports the contradiction instead of picking a winner.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, Mapping

from shared_models.evidence_freshness import (
    UNKNOWN as FRESHNESS_UNKNOWN,
    freshness_of,
    tracked_confidence,
)

CLAIMS_SCHEMA = "cryptoscan.pqc-claims/1"

#: the five stages. Order is the migration's own order; it is used for display,
#: never to infer one stage from an earlier one.
PQC_CLAIM_STAGES: tuple[str, ...] = (
    "SUPPORT_AVAILABLE",
    "CONFIGURED",
    "RUNTIME_OBSERVED",
    "NETWORK_NEGOTIATED",
    "MIGRATION_VALIDATED",
)

#: which evidence classes may establish which stage. A stage's claim rests on the
#: kind of proof that stage demands: validation is an observation of the migrated
#: state, never a vendor's promise that it would work.
STAGE_EVIDENCE: dict[str, frozenset[str]] = {
    "SUPPORT_AVAILABLE": frozenset(
        {"VENDOR_DECLARED", "STATIC_OBSERVED", "IMPORTED", "CONFIGURED",
         "RUNTIME_OBSERVED", "NETWORK_ACTIVE_OBSERVED", "NETWORK_PASSIVE_OBSERVED"}),
    "CONFIGURED": frozenset({"CONFIGURED", "AUDIT_OBSERVED"}),
    "RUNTIME_OBSERVED": frozenset({"RUNTIME_OBSERVED"}),
    "NETWORK_NEGOTIATED": frozenset(
        {"NETWORK_ACTIVE_OBSERVED", "NETWORK_PASSIVE_OBSERVED", "RUNTIME_OBSERVED"}),
    "MIGRATION_VALIDATED": frozenset(
        {"RUNTIME_OBSERVED", "NETWORK_ACTIVE_OBSERVED", "AUDIT_OBSERVED"}),
}

#: evidence classes that are direct observations of the running world
DIRECT_EVIDENCE: frozenset[str] = frozenset(
    {"RUNTIME_OBSERVED", "NETWORK_ACTIVE_OBSERVED", "NETWORK_PASSIVE_OBSERVED",
     "CERTIFICATE_OBSERVED", "AUDIT_OBSERVED"})

QUANTUM_CLASSES: frozenset[str] = frozenset(
    {"POST_QUANTUM", "POST_QUANTUM_HYBRID", "CLASSICAL"})

#: verdicts a subject can hold
READY_VALIDATED = "PQC_READY_VALIDATED"
OBSERVED_NOT_VALIDATED = "OBSERVED_NOT_VALIDATED"
SUPPORT_ONLY = "SUPPORT_ONLY"
NO_EVIDENCE = "NO_EVIDENCE"


def claim(*, stage: str, subject: str, evidence_ids: Iterable[str],
          evidence_type: str, observed_at: str, algorithm: str | None = None,
          quantum_class: str | None = None) -> dict[str, Any]:
    """One migration-stage claim. Refuses a claim its evidence cannot establish.

    ``evidence_ids`` are mandatory — a claim with no evidence is an assertion and
    this model will not carry one. ``evidence_type`` must be able to establish the
    stage (a vendor declaration cannot establish ``MIGRATION_VALIDATED``), and
    ``observed_at`` is mandatory because freshness tracking without a clock is
    fiction.
    """
    stage_name = str(stage or "").upper()
    if stage_name not in PQC_CLAIM_STAGES:
        raise ValueError(f"unknown PQC claim stage {stage!r}; expected one of "
                         f"{', '.join(PQC_CLAIM_STAGES)}")
    kind = str(evidence_type or "").upper()
    if kind not in STAGE_EVIDENCE[stage_name]:
        raise ValueError(
            f"{kind or '(none)'} evidence cannot establish {stage_name}: this stage "
            f"rests on {', '.join(sorted(STAGE_EVIDENCE[stage_name]))}")
    ids = [str(item) for item in evidence_ids if str(item).strip()]
    if not ids:
        raise ValueError("a PQC claim without evidence ids is an assertion, not a claim")
    if not str(observed_at or "").strip():
        raise ValueError("a PQC claim without observed_at cannot be aged, so it cannot "
                         "be tracked")
    q_class = str(quantum_class or "").upper() or None
    if q_class is not None and q_class not in QUANTUM_CLASSES:
        raise ValueError(f"unknown quantum class {quantum_class!r}; expected one of "
                         f"{', '.join(sorted(QUANTUM_CLASSES))}")
    return {
        "stage": stage_name,
        "subject": str(subject or "").strip() or "(unnamed)",
        "evidence_ids": ids,
        "evidence_type": kind,
        "observed_at": str(observed_at),
        "algorithm": str(algorithm) if algorithm else None,
        "quantum_class": q_class,
    }


def _stage_state(claims: list[dict[str, Any]], *, now: datetime | None) -> dict[str, Any]:
    if not claims:
        return {"state": "NOT_CLAIMED", "claims": [], "fresh": [], "confidence": None,
                "reason": "no claim and no evidence: this stage is unknown here, "
                          "which is never 'done' and never 'fine'"}
    fresh: list[dict[str, Any]] = []
    confidences: list[dict[str, Any]] = []
    for item in claims:
        fresh.append(freshness_of(item["observed_at"],
                                  evidence_type=item["evidence_type"], now=now))
        confidences.append(tracked_confidence(
            {"confidence": "HIGH" if item["evidence_type"] in DIRECT_EVIDENCE else "MEDIUM",
             "observed_at": item["observed_at"], "evidence_type": item["evidence_type"]},
            now=now))
    states = {entry["state"] for entry in fresh}
    usable = [entry for entry in fresh if entry["state"] not in {"STALE", "EXPIRED", FRESHNESS_UNKNOWN}]
    if usable:
        state, reason = "CLAIMED", "claimed with evidence that is still inside its policy window"
    else:
        state, reason = "CLAIMED_STALE", ("every backing record is stale, expired or "
                                          "undated: the claim stands in the history and "
                                          "cannot support a decision today")
    return {"state": state, "claims": claims, "fresh": fresh,
            "confidence": confidences, "reason": reason, "freshness_states": sorted(states)}


def _contradictions(per_stage: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Validated PQC claims vs later direct CLASSICAL claims on the same subject.

    Both rows are kept — the report shows the contradiction; it never picks a
    winner and never overwrites the older claim.
    """
    validated = per_stage.get("MIGRATION_VALIDATED", {}).get("claims", [])
    later_direct: list[dict[str, Any]] = []
    for stage in ("RUNTIME_OBSERVED", "NETWORK_NEGOTIATED"):
        later_direct.extend(per_stage.get(stage, {}).get("claims", []))
    out: list[dict[str, Any]] = []
    for good in validated:
        if good.get("quantum_class") not in {"POST_QUANTUM", "POST_QUANTUM_HYBRID"}:
            continue
        for other in later_direct:
            if other.get("quantum_class") != "CLASSICAL":
                continue
            if other["observed_at"] > good["observed_at"]:
                out.append({
                    "kind": "VALIDATION_VS_LATER_CLASSICAL_OBSERVATION",
                    "validated_claim": good, "conflicting_claim": other,
                    "reason": ("a validated post-quantum claim is contradicted by a "
                               "later direct classical observation; both records are "
                               "kept and readiness is withheld until this is resolved"),
                })
    return out


def pqc_claim_report(claims: Iterable[Mapping[str, Any]], *,
                     now: datetime | None = None) -> dict[str, Any]:
    """Per-subject migration-stage report and readiness verdict.

    Readiness ladder — and it is a ladder, never a shortcut:

    * ``PQC_READY_VALIDATED`` — a fresh ``MIGRATION_VALIDATED`` claim with direct
      evidence, and no standing contradiction;
    * ``OBSERVED_NOT_VALIDATED`` — PQC was observed or negotiated, but nobody has
      verified the migration;
    * ``SUPPORT_ONLY`` — support/configure evidence and nothing more. A library
      supporting ML-KEM lands here and the report says so in these words;
    * ``NO_EVIDENCE`` — no claims at all: unknown, which is never "ready".
    """
    rows = [claim(**dict(item)) for item in claims]
    by_subject: dict[str, list[dict[str, Any]]] = {}
    for item in rows:
        by_subject.setdefault(item["subject"], []).append(item)

    subjects: dict[str, Any] = {}
    for subject, items in sorted(by_subject.items()):
        per_stage = {
            stage: _stage_state([i for i in items if i["stage"] == stage], now=now)
            for stage in PQC_CLAIM_STAGES
        }
        contradictions = _contradictions(per_stage)
        validated = per_stage["MIGRATION_VALIDATED"]
        observed = per_stage["RUNTIME_OBSERVED"]
        negotiated = per_stage["NETWORK_NEGOTIATED"]
        configured = per_stage["CONFIGURED"]
        support = per_stage["SUPPORT_AVAILABLE"]
        if contradictions:
            verdict = "CONTRADICTION_UNRESOLVED"
            reason = ("readiness is withheld while a validated claim and a later "
                      "direct observation disagree; both records are preserved")
        elif validated["state"] == "CLAIMED":
            verdict, reason = READY_VALIDATED, (
                "the migration was verified after implementation by direct, "
                "still-fresh evidence")
        elif validated["state"] == "CLAIMED_STALE":
            verdict = "VALIDATION_STALE"
            reason = ("the validation evidence is stale, expired or undated: it "
                      "remains in the history and cannot hold readiness alone")
        elif observed["state"].startswith("CLAIMED") or negotiated["state"].startswith("CLAIMED"):
            verdict, reason = OBSERVED_NOT_VALIDATED, (
                "post-quantum behaviour was observed but the migration has not been "
                "validated after implementation")
        elif configured["state"].startswith("CLAIMED") or support["state"].startswith("CLAIMED"):
            verdict, reason = SUPPORT_ONLY, (
                "support or configuration is claimed and nothing was observed: a "
                "library supporting ML-KEM is not PQC readiness")
        else:
            verdict, reason = NO_EVIDENCE, (
                "no claim carries evidence here; the stage is unknown, which is "
                "neither ready nor fine")
        subjects[subject] = {
            "stages": per_stage,
            "readiness": verdict,
            "readiness_reason": reason,
            "contradictions": contradictions,
        }

    return {
        "schema": CLAIMS_SCHEMA,
        "subjects": subjects,
        "counts": {
            verdict: sum(1 for entry in subjects.values() if entry["readiness"] == verdict)
            for verdict in (READY_VALIDATED, OBSERVED_NOT_VALIDATED, SUPPORT_ONLY,
                            NO_EVIDENCE, "VALIDATION_STALE", "CONTRADICTION_UNRESOLVED")
        },
        "note": ("five stages, five separate claims: support is not configured, "
                 "configured is not observed, observed is not validated — and none "
                 "of them is readiness without fresh validation evidence"),
    }
