"""Migration plan records (gap analysis §H) — the reproducible plan and the
six-state validation ladder.

    "The migration plan must record its policy version, algorithm profiles,
    source snapshot, assumptions, cost model and human approvals."

    | UNKNOWN   | Insufficient evidence                      |
    | CAPABLE   | PQC capability identified                  |
    | CONFIGURED| PQC configuration identified               |
    | OBSERVED  | PQC operation observed                     |
    | NEGOTIATED| PQC negotiation observed                   |
    | VALIDATED | Migration evidence meets validation criteria |

``VALIDATED`` is reached only through :func:`validate_migration` with
post-change evidence that differs from the pre-change state — a plan never
validates itself, and capability never reads as validated readiness.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

PLAN_SCHEMA = "cryptoscan.migration-plan/1"

UNKNOWN, CAPABLE, CONFIGURED = "UNKNOWN", "CAPABLE", "CONFIGURED"
OBSERVED, NEGOTIATED, VALIDATED = "OBSERVED", "NEGOTIATED", "VALIDATED"
STATES: tuple[str, ...] = (UNKNOWN, CAPABLE, CONFIGURED, OBSERVED, NEGOTIATED,
                           VALIDATED)
#: evidence-backed states only — UNKNOWN is "no evidence", never a claim
CLAIMABLE: frozenset[str] = frozenset({CAPABLE, CONFIGURED, OBSERVED,
                                       NEGOTIATED, VALIDATED})


def make_plan(*, plan_id: str, policy_version: str,
              algorithm_profiles: Sequence[Mapping[str, Any]],
              source_snapshot: Mapping[str, Any],
              assumptions: Sequence[str], cost_model: Mapping[str, Any],
              approvals: Sequence[Mapping[str, Any]],
              waves: Sequence[Mapping[str, Any]] = (),
              blockers: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    """A migration plan that can be reproduced later.

    Refusals: an unversioned policy or unnamed source snapshot makes the plan
    un-reproducible; no assumptions recorded is a plan pretending it has none;
    a cost model with zero-cost rows is an unmeasured zero; an approval without
    a named human is the platform approving itself.
    """
    if not str(policy_version or "").strip():
        raise ValueError("policy_version is mandatory: an unversioned plan "
                         "cannot be reproduced or audited")
    if not str(source_snapshot.get("snapshot_id") or "").strip():
        raise ValueError("source_snapshot.snapshot_id is mandatory: the plan "
                         "must name the estate snapshot it was built from")
    if not str(source_snapshot.get("version") or "").strip():
        raise ValueError("source_snapshot.version is mandatory: a snapshot "
                         "without a version cannot be re-selected later")
    profiles = [dict(p) for p in algorithm_profiles]
    if not profiles:
        raise ValueError("algorithm_profiles is mandatory: a plan with no "
                         "algorithm profile plans nothing")
    rows = [str(a) for a in assumptions if str(a).strip()]
    if not rows:
        raise ValueError(
            "assumptions is mandatory and may not be silently empty: record "
            "'none' explicitly if the plan makes none, so the reader sees the "
            "word rather than an unmarked blank")
    cost = dict(cost_model or {})
    for line in cost.get("lines", []):
        if line.get("estimate") in (0, "0", None):
            raise ValueError(
                "a cost line with a zero estimate is an unmeasured zero: "
                "record UNKNOWN or a measured figure, never a bare 0")
    approved = []
    for approval in approvals:
        if not str(approval.get("actor") or "").strip():
            raise ValueError("an approval without a named human is the "
                             "platform approving itself")
        if not str(approval.get("at") or "").strip():
            raise ValueError("an approval without a timestamp cannot be "
                             "placed against the plan version it approved")
        approved.append(dict(approval))
    if not approved:
        raise ValueError("human approvals are mandatory: a plan nobody "
                         "approved is a draft, not a plan")
    return {
        "schema": PLAN_SCHEMA,
        "plan_id": str(plan_id),
        "policy_version": str(policy_version),
        "algorithm_profiles": profiles,
        "source_snapshot": dict(source_snapshot),
        "assumptions": rows,
        "cost_model": cost,
        "approvals": approved,
        "waves": [dict(w) for w in waves],
        "blockers": [dict(b) for b in blockers],
    }


def asset_state(*, evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Classify one asset's PQC state from its recorded evidence — or UNKNOWN.

    Evidence kinds map to states strictly upward in observation strength:
    capability < configuration < runtime operation < network negotiation.
    Two kinds present → the strongest recorded state wins, and the record says
    which evidence produced it. No evidence → UNKNOWN with the reason.
    """
    ladder = ((NEGOTIATED, "negotiated"), (OBSERVED, "observed"),
              (CONFIGURED, "configured"), (CAPABLE, "capable"))
    for state, key in ladder:
        ids = [str(e) for e in (evidence.get(key) or []) if str(e).strip()]
        if ids:
            return {
                "state": state, "evidence_ids": ids,
                "reason": (f"recorded {key} evidence places this asset at "
                           f"{state}"),
            }
    return {
        "state": UNKNOWN, "evidence_ids": [],
        "reason": ("insufficient evidence: no capability, configuration, "
                   "operation or negotiation record — UNKNOWN is not CAPABLE"),
    }


def validate_migration(*, asset: str, claimed_state: str,
                       before_state: str, evidence_ids: Sequence[str],
                       validated_at: str, validator: str) -> dict[str, Any]:
    """Post-migration validation: ``VALIDATED`` needs post-change evidence.

    The claim is refused when the evidence is empty (a claim without evidence
    is a wish), when the validator is unnamed (validation is a human act), or
    when the before-state is already the claimed state (nothing changed, so
    there is nothing to validate).
    """
    claim = str(claimed_state or "").upper()
    if claim != VALIDATED:
        raise ValueError(f"validate_migration claims {VALIDATED}, got "
                         f"{claimed_state!r}")
    ids = [str(e) for e in evidence_ids if str(e).strip()]
    if not ids:
        raise ValueError(
            "post-change evidence is mandatory: a migration without it is "
            "claimed, not validated")
    if not str(validated_at or "").strip():
        raise ValueError("validated_at is mandatory: an undated validation "
                         "cannot be placed after the change it validates")
    if not str(validator or "").strip():
        raise ValueError("the validator is mandatory: the platform does not "
                         "validate its own migration")
    if str(before_state or "").upper() == VALIDATED:
        raise ValueError(
            "the before-state is already VALIDATED: there is no change to "
            "validate, and re-filing the same state is not a migration")
    return {
        "schema": PLAN_SCHEMA,
        "asset": str(asset),
        "claimed_state": VALIDATED,
        "before_state": str(before_state).upper(),
        "evidence_ids": ids,
        "validated_at": str(validated_at),
        "validator": str(validator),
        "reason": ("post-change evidence differs from the pre-change state: "
                   "the migration is validated, not merely claimed"),
    }
