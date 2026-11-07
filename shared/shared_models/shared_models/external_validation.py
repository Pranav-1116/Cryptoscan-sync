"""External validation register (roadmap items 10 + standing external-only rule).

Some validations cannot be run from inside this repository and never will be:
bank triage loops, DR/PITR/soak drills, third-party penetration tests, real HSM
runs, SOC2/ISO audits, release-manifest and branch-protection checks. The
platform does not perform them and does not mark them done.

What the platform *can* do is keep the register: when an act happens **outside**
the platform, someone files the evidence here. The register's honesty rules:

* an entry is filed evidence of an external act — ``performed_by`` (the external
  party) and ``evidence_ids`` are mandatory at construction; a validation with
  no evidence is a claim, and this register does not carry claims;
* nothing auto-files. There is no code path in this module that marks a
  validation done;
* a validation with no filed entry is ``NOT_FILED`` — which reads "no evidence
  the platform holds", never "passed" and never "not applicable".
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

EXTERNAL_VALIDATION_SCHEMA = "cryptoscan.external-validation/1"

#: the validations the roadmap places outside the platform
DR_DRILL = "DR_DRILL"
PITR_DRILL = "PITR_DRILL"
SOAK_DRILL = "SOAK_DRILL"
THIRD_PARTY_PEN_TEST = "THIRD_PARTY_PEN_TEST"
REAL_HSM_RUN = "REAL_HSM_RUN"
BANK_TRIAGE_LOOP = "BANK_TRIAGE_LOOP"
SOC2_ISO_AUDIT = "SOC2_ISO_AUDIT"
RELEASE_MANIFEST_CHECK = "RELEASE_MANIFEST_CHECK"
BRANCH_PROTECTION_CHECK = "BRANCH_PROTECTION_CHECK"

EXTERNAL_KINDS: tuple[str, ...] = (
    DR_DRILL, PITR_DRILL, SOAK_DRILL, THIRD_PARTY_PEN_TEST, REAL_HSM_RUN,
    BANK_TRIAGE_LOOP, SOC2_ISO_AUDIT, RELEASE_MANIFEST_CHECK,
    BRANCH_PROTECTION_CHECK,
)

FILED = "FILED"
NOT_FILED = "NOT_FILED"

RESULTS: frozenset[str] = frozenset({"PASSED", "PARTIAL", "FAILED"})


def file_validation(*, kind: str, performed_by: str, evidence_ids: Sequence[str],
                    performed_at: str, scope: str,
                    result: str = "PASSED",
                    note: str | None = None) -> dict[str, Any]:
    """File one external act. Refuses anonymous or evidence-free filings.

    ``performed_by`` names the party that performed the validation outside the
    platform — the platform cannot file itself as the performer of an act it
    refuses to perform.
    """
    name = str(kind or "").upper()
    if name not in EXTERNAL_KINDS:
        raise ValueError(f"unknown external validation kind {kind!r}; expected "
                         f"one of {', '.join(EXTERNAL_KINDS)}")
    who = str(performed_by or "").strip()
    if not who:
        raise ValueError(
            "the performing party is mandatory: the platform cannot self-attest "
            "an act it refuses to perform")
    if who.lower() in {"cryptoscan", "crypto scan", "the platform", "platform"}:
        raise ValueError(
            f"{who!r} did not perform this: external validations are performed "
            f"outside the platform and filed here afterwards")
    ids = [str(e) for e in evidence_ids if str(e).strip()]
    if not ids:
        raise ValueError(
            "an external validation with no evidence is a claim: file the "
            "report, drill log or certificate that proves the act")
    if not str(performed_at or "").strip():
        raise ValueError("performed_at is mandatory: an undated drill is not "
                         "evidence of a drill")
    if not str(scope or "").strip():
        raise ValueError("scope is mandatory: a validation without a scope "
                         "validates nothing")
    outcome = str(result or "").upper()
    if outcome not in RESULTS:
        raise ValueError(f"unknown result {result!r}; expected one of "
                         f"{', '.join(sorted(RESULTS))}")
    return {
        "schema": EXTERNAL_VALIDATION_SCHEMA,
        "kind": name,
        "performed_by": who,
        "evidence_ids": ids,
        "performed_at": str(performed_at),
        "scope": str(scope),
        "result": outcome,
        "note": str(note) if note else None,
        "filed_by_platform": True,
        "performed_by_platform": False,
    }


def validation_status(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Per-kind status over filed entries. ``NOT_FILED`` is never "passed".

    The newest filing per kind decides the current result; the history is kept
    alongside it, because a drill that regressed is still a drill that happened.
    """
    records = [dict(r) for r in rows]
    kinds: dict[str, Any] = {}
    for kind in EXTERNAL_KINDS:
        history = sorted((r for r in records if str(r.get("kind")) == kind),
                         key=lambda r: str(r.get("performed_at") or ""))
        if not history:
            kinds[kind] = {
                "status": NOT_FILED, "latest": None, "history": [],
                "reason": ("no entry filed: this platform holds no evidence of "
                           "this external validation — not filed is not passed"),
            }
        else:
            kinds[kind] = {
                "status": FILED,
                "latest": history[-1],
                "history": history,
                "reason": (f"filed by {history[-1].get('performed_by')}: "
                           f"{history[-1].get('result')} on "
                           f"{history[-1].get('performed_at')}"),
            }
    filed = sum(1 for entry in kinds.values() if entry["status"] == FILED)
    return {
        "schema": EXTERNAL_VALIDATION_SCHEMA,
        "kinds": kinds,
        "counts": {FILED: filed, NOT_FILED: len(EXTERNAL_KINDS) - filed},
        "note": ("these validations are performed outside the platform and "
                 "filed here as evidence; the platform never marks them done "
                 "from inside itself, and a missing filing is never a pass"),
    }
