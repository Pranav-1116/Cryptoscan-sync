"""PQC decision engine (roadmap item 3).

``pqc_readiness()`` says what was observed; ``pqc_claims.py`` tracks migration
stages. This module is the **decision** layer: per subject, it plans the migration
and refuses the shortcuts that make PQC programs lie:

* classification separates post-quantum, hybrid, Grover-weakened and
  Shor-broken — and an unclassified algorithm is ``UNCLASSIFIED``, never "fine";
* a blocker is ``PROVEN`` only when evidence backs it; an unassessed dependency
  is ``UNKNOWN``, and "not assessed" is never "compatible";
* readiness is inherited from the claim stages — support alone never migrates a
  subject past ``SUPPORT_ONLY``;
* waves, rollback and validation are planned, and the whole report is a
  ``MIGRATION_PLAN``: a hypothetical planning artefact, never a production change;
* cost is rule-based across the eight scopes the roadmap names, every row citing
  its rule, so a re-run with the same inputs produces the same numbers.

Prioritisation consumes :mod:`shared_models.risk_dimensions` and shows each
dimension's contribution — and names the dimensions it could not get, because a
priority computed around blind spots must say so.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from shared_models.algorithm_registry import parse_algorithm
from shared_models.pqc_claims import (
    NO_EVIDENCE as READY_NO_EVIDENCE,
    PQC_CLAIM_STAGES,
    STAGE_EVIDENCE,
)

DECISION_SCHEMA = "cryptoscan.pqc-decision/1"
PLAN_KIND = "MIGRATION_PLAN"

#: dependency kinds whose compatibility is assessed before a migration wave
DEPENDENCY_KINDS: tuple[str, ...] = (
    "HSM", "KMS", "APPLICATION", "PROTOCOL", "CERTIFICATE", "HOST", "VENDOR")

SUPPORTS = "SUPPORTS"
LACKS = "LACKS"
NOT_ASSESSED = "NOT_ASSESSED"

#: cost rules, published so every number can be re-derived by hand
COST_RULES: dict[str, str] = {
    "APPLICATIONS": "CR-APP: 3 effort units per application dependency",
    "HOSTS": "CR-HOST: 2 effort units per host dependency",
    "HSM_KMS": ("CR-HSM: 5 units per HSM/KMS dependency, +2 more when the "
                "dependency is incompatible (firmware or replacement work)"),
    "CERTIFICATES": "CR-CERT: 2 units per certificate dependency (reissue + rollout)",
    "PROTOCOLS": "CR-PROTO: 2 units per protocol dependency (negotiation changes)",
    "TESTING": "CR-TEST: 4 units base + 1 per application dependency",
    "ROLLBACK": "CR-ROLL: 2 units base (snapshot, restore path, rollback drill)",
    "VALIDATION": "CR-VALID: 3 units base (direct-evidence validation run)",
}


def classify_algorithm(name: str | None) -> dict[str, Any]:
    """Classify one algorithm name: post-quantum, hybrid, Grover, Shor, or unknown."""
    raw = str(name or "")
    upper = raw.upper()
    info = parse_algorithm(raw)
    hybrid_tokens = ("HYBRID", "X25519MLKEM", "X25519KYBER", "SECP256R1MLKEM")
    pq_tokens = ("ML-KEM", "MLKEM", "ML-DSA", "MLDSA", "SLH-DSA", "SPHINCS",
                 "KYBER", "DILITHIUM", "FALCON", "HQC", "BIKE", "FRODO")
    if any(token in upper for token in hybrid_tokens):
        klass = "POST_QUANTUM_HYBRID"
    elif any(token in upper for token in pq_tokens):
        klass = "POST_QUANTUM"
    elif info.recognized and info.quantum_impact == "shor":
        klass = "CLASSICAL_VULNERABLE"
    elif info.recognized and info.quantum_impact == "grover":
        klass = "GROVER_AFFECTED"
    elif info.recognized:
        klass = "CLASSICAL_OTHER"
    else:
        klass = "UNCLASSIFIED"
    return {"name": raw or "(unnamed)", "class": klass,
            "recognized": bool(info.recognized),
            "quantum_impact": info.quantum_impact,
            "reason": (
                "unclassified: not in the registry, so this is unknown — never "
                "'fine'" if klass == "UNCLASSIFIED" else
                "classified from the algorithm registry")}


def _dependency_rows(dependencies: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in dependencies:
        kind = str(item.get("kind") or "UNKNOWN").upper()
        state = str(item.get("capability_state") or NOT_ASSESSED).upper()
        evidence = [str(e) for e in (item.get("evidence_ids") or [])]
        if state not in {SUPPORTS, LACKS, NOT_ASSESSED}:
            state = NOT_ASSESSED
        rows.append({"kind": kind, "name": str(item.get("name") or "(unnamed)"),
                     "capability_state": state, "evidence_ids": evidence})
    return rows


def assess_subject(*, subject: str,
                   current_algorithms: Sequence[str | Mapping[str, Any]] = (),
                   dependencies: Iterable[Mapping[str, Any]] = (),
                   claim_report: Mapping[str, Any] | None = None,
                   targets: Mapping[str, Any] | None = None,
                   quantum_threat_horizon_years: float | None = None,
                   data_shelf_life_years: float = 0.0,
                   migration_lead_time_years: float = 0.0,
                   dependents: int | None = None,
                   chain_counts: Mapping[str, int] | None = None,
                   now: Any = None) -> dict[str, Any]:
    """One subject's migration assessment: inventory, blockers, compatibility,
    priority, cost and the readiness it may honestly claim."""
    from shared_models.risk_dimensions import (
        score_crypto_risk, score_operational_dependency, score_quantum_urgency,
    )

    names: list[str] = []
    for item in current_algorithms:
        names.append(item if isinstance(item, str) else str(item.get("name") or ""))
    inventory = [classify_algorithm(name) for name in names]

    deps = _dependency_rows(dependencies)
    blockers: list[dict[str, Any]] = []
    compatibility: list[dict[str, Any]] = []
    for row in deps:
        if row["capability_state"] == LACKS:
            if row["evidence_ids"]:
                blockers.append({
                    "dependency": row["name"], "kind": row["kind"],
                    "certainty": "PROVEN",
                    "evidence_ids": row["evidence_ids"],
                    "reason": ("evidence shows this dependency lacks the required "
                               "capability: a proven migration blocker")})
            else:
                blockers.append({
                    "dependency": row["name"], "kind": row["kind"],
                    "certainty": "UNKNOWN", "evidence_ids": [],
                    "reason": ("a capability gap was asserted without evidence: it "
                               "is neither a proven blocker nor a cleared "
                               "dependency")})
        if row["capability_state"] == SUPPORTS and row["evidence_ids"]:
            compat = ("COMPATIBLE",
                      "evidence-backed support: this dependency is compatible")
        elif row["capability_state"] == LACKS:
            compat = ("INCOMPATIBLE",
                      "evidence or assertion says this dependency lacks the "
                      "capability")
        else:
            compat = ("NOT_ASSESSED",
                      "compatibility was never established: not assessed is never "
                      "compatible")
        compatibility.append({"dependency": row["name"], "kind": row["kind"],
                              "state": compat[0], "reason": compat[1],
                              "evidence_ids": row["evidence_ids"]})

    # readiness comes from the claim stages — support alone is never ready
    if claim_report and subject in (claim_report.get("subjects") or {}):
        readiness = dict(claim_report["subjects"][subject])
        readiness_source = "pqc-claims"
    else:
        readiness = {"readiness": READY_NO_EVIDENCE,
                     "readiness_reason": ("no migration-stage claims for this "
                                          "subject: unknown, which is neither "
                                          "ready nor fine"),
                     "stages": {stage: {"state": "NOT_CLAIMED"}
                                for stage in PQC_CLAIM_STAGES},
                     "contradictions": []}
        readiness_source = "no-claims"

    # prioritisation over risk dimensions, contributions visible
    chain = dict(chain_counts or {})
    urgency = score_quantum_urgency(
        algorithm_info=parse_algorithm(names[0]) if names else None,
        usage_state="OBSERVED" if names else None,
        data_shelf_life_years=data_shelf_life_years,
        migration_lead_time_years=migration_lead_time_years,
        quantum_threat_horizon_years=quantum_threat_horizon_years)
    crypto = score_crypto_risk(
        algorithm_info=parse_algorithm(names[0]) if names else None,
        usage_state="OBSERVED" if names else None)
    if dependents is None and not chain:
        # the blast radius was never measured: that is not a zero blast radius
        dependency_score = {
            "dimension": "OPERATIONAL_DEPENDENCY", "score": None,
            "known": False, "sense": "risk", "factors": [],
            "reason": ("the blast radius was never measured: unknown, never "
                       "assumed zero")}
    else:
        dependency_score = score_operational_dependency(
            dependents=int(dependents or 0),
            proven_chains=int(chain.get("proven", 0)),
            inferred_chains=int(chain.get("inferred", 0)),
            unknown_chains=int(chain.get("unknown", 0)))
    parts = [urgency, crypto, dependency_score]
    scored = [p for p in parts if p.get("known")]
    missing = [p["dimension"] for p in parts if not p.get("known")]
    if scored:
        priority_score = round(sum(p["score"] for p in scored) / len(scored), 2)
        priority = ("HIGH" if priority_score >= 60 else
                    "MEDIUM" if priority_score >= 35 else "LOW")
    else:
        priority_score, priority = None, "INCOMPLETE_ASSESSMENT"
    prioritisation = {
        "priority": priority, "priority_score": priority_score,
        "contributions": [{"dimension": p["dimension"], "score": p["score"]}
                          for p in scored],
        "missing_dimensions": missing,
        "reason": ("priority averages the dimensions that could be scored and "
                   "names the ones that could not: a priority around blind spots "
                   "must say so") if missing else
                  "priority averages the scored dimensions; all were available",
    }

    # cost across the eight scopes, rule-based
    app_deps = sum(1 for r in deps if r["kind"] == "APPLICATION")
    host_deps = sum(1 for r in deps if r["kind"] == "HOST")
    hsm_deps = [r for r in deps if r["kind"] in {"HSM", "KMS"}]
    cert_deps = sum(1 for r in deps if r["kind"] == "CERTIFICATE")
    proto_deps = sum(1 for r in deps if r["kind"] == "PROTOCOL")
    hsm_units = sum(5 + (2 if r["capability_state"] != SUPPORTS else 0)
                    for r in hsm_deps)
    cost_rows = [
        {"scope": "APPLICATIONS", "rule": "CR-APP", "units": 3 * app_deps},
        {"scope": "HOSTS", "rule": "CR-HOST", "units": 2 * host_deps},
        {"scope": "HSM_KMS", "rule": "CR-HSM", "units": hsm_units},
        {"scope": "CERTIFICATES", "rule": "CR-CERT", "units": 2 * cert_deps},
        {"scope": "PROTOCOLS", "rule": "CR-PROTO", "units": 2 * proto_deps},
        {"scope": "TESTING", "rule": "CR-TEST", "units": 4 + 1 * app_deps},
        {"scope": "ROLLBACK", "rule": "CR-ROLL", "units": 2},
        {"scope": "VALIDATION", "rule": "CR-VALID", "units": 3},
    ]
    cost = {"rows": cost_rows,
            "rules": {row["scope"]: COST_RULES[row["scope"]] for row in cost_rows},
            "total_units": sum(row["units"] for row in cost_rows)}

    target_rows = {}
    for purpose, value in (targets or {}).items():
        if isinstance(value, Mapping):
            target_rows[str(purpose)] = classify_algorithm(str(value.get("algorithm") or ""))
            if value.get("hybrid"):
                target_rows[str(purpose)]["class"] = "POST_QUANTUM_HYBRID"
        else:
            target_rows[str(purpose)] = classify_algorithm(str(value))

    return {
        "schema": DECISION_SCHEMA,
        "subject": subject,
        "inventory": inventory,
        "classification": {row["name"]: row["class"] for row in inventory},
        "blockers": blockers,
        "compatibility": compatibility,
        "prioritisation": prioritisation,
        "cost": cost,
        "targets": target_rows,
        "readiness": readiness.get("readiness"),
        "readiness_reason": readiness.get("readiness_reason"),
        "readiness_source": readiness_source,
        "claim_stages": readiness.get("stages", {}),
        "contradictions": readiness.get("contradictions", []),
        "validation_requirement": {
            "stage": "MIGRATION_VALIDATED",
            "acceptable_evidence": sorted(STAGE_EVIDENCE["MIGRATION_VALIDATED"]),
            "reason": ("a migration is validated only by direct post-implementation "
                       "evidence — never by a vendor declaration")},
        "note": ("assessment only: this is planning evidence, not a production "
                 "change"),
    }


def plan_waves(assessments: Sequence[Mapping[str, Any]], *,
               wave_capacity: int | None = None) -> dict[str, Any]:
    """Deterministic wave plan over assessments.

    Subjects with **proven** blockers go to wave 0 (remediation first — you cannot
    migrate onto a capability that is demonstrably missing). The rest are ordered
    by priority score (desc), then subject name, and chunked by ``wave_capacity``.
    Every wave carries rollback and validation plans; the report is a
    ``MIGRATION_PLAN`` and says it is hypothetical at the point of use.
    """
    rows = [dict(item) for item in assessments]

    def has_proven_blocker(row: Mapping[str, Any]) -> bool:
        return any(b.get("certainty") == "PROVEN" for b in row.get("blockers") or [])

    blocked = sorted((r for r in rows if has_proven_blocker(r)),
                     key=lambda r: str(r["subject"]))
    rest = sorted((r for r in rows if not has_proven_blocker(r)),
                  key=lambda r: (-(r.get("prioritisation", {}).get("priority_score")
                                   if r.get("prioritisation", {}).get("priority_score") is not None
                                   else -1),
                                 str(r["subject"])))

    def wave_entry(number: int, mission: str, members: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        return {
            "wave": number, "mission": mission,
            "subjects": [m["subject"] for m in members],
            "cost_total_units": sum(
                (m.get("cost") or {}).get("total_units", 0) for m in members),
            "rollback_plan": {
                "requirements": [
                    "pre-change snapshot of every touched subject, restore tested "
                    "before the wave starts",
                    "revert procedure documented per subject and rehearsed",
                    "rollback decision owner named before the change window"],
                "reason": ("a rollback plan is part of the wave, not an afterthought: "
                           "an untested restore is not a rollback")},
            "validation_plan": {
                "requirements": [
                    "post-implementation validation run producing direct evidence "
                    "(RUNTIME_OBSERVED, NETWORK_ACTIVE_OBSERVED or AUDIT_OBSERVED)",
                    "a MIGRATION_VALIDATED claim filed per subject with that evidence",
                    "if a classical algorithm is re-observed after validation, the "
                    "contradiction is filed and readiness is withheld"],
                "acceptable_evidence": sorted(STAGE_EVIDENCE["MIGRATION_VALIDATED"]),
                "reason": ("validation is observed after implementation, never "
                           "assumed from the change happening")},
        }

    waves: list[dict[str, Any]] = []
    if blocked:
        waves.append(wave_entry(
            0, "BLOCKER_REMEDIATION: make the missing capability exist first", blocked))
    capacity = int(wave_capacity) if wave_capacity else max(1, len(rest))
    capacity = max(1, capacity)
    number = 1
    for start in range(0, len(rest), capacity):
        chunk = rest[start:start + capacity]
        if not chunk:
            continue
        waves.append(wave_entry(
            number, "MIGRATION: move validated-ready subjects to their targets",
            chunk))
        number += 1

    return {
        "schema": DECISION_SCHEMA,
        "result_kind": PLAN_KIND,
        "waves": waves,
        "ordering_rule": ("wave 0 = proven blockers; then priority score "
                          "descending, subject name ascending, chunked by "
                          "wave_capacity"),
        "note": ("this plan is a hypothetical planning artefact over recorded "
                 "evidence: no wave here has been executed, and none of these "
                 "names a real production change"),
    }
