"""Compliance mapping (gap analysis §I): requirement → evidence → assessment.

    "Compliance should be mapped to specific requirements, evidence and
    assessment outcomes. A policy match is not automatically proof of
    compliance."

So the engine keeps two separate facts per requirement: whether the estate
*policy-matches* it (a mechanical comparison) and what an assessor *decided*
with evidence (a verdict). A policy match with no assessment is reported as
``POLICY_MATCH_ONLY`` — never ``COMPLIANT``. Compliance is a human verdict
about evidence, not the output of a string comparison.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

COMPLIANCE_SCHEMA = "cryptoscan.compliance-mapping/1"

COMPLIANT, NON_COMPLIANT = "COMPLIANT", "NON_COMPLIANT"
NOT_ASSESSED, POLICY_MATCH_ONLY = "NOT_ASSESSED", "POLICY_MATCH_ONLY"


def requirement(*, requirement_id: str, framework: str, clause: str,
                text: str) -> dict[str, Any]:
    """One compliance requirement, named by framework and clause."""
    for field_name, value in (("requirement_id", requirement_id),
                              ("framework", framework), ("clause", clause),
                              ("text", text)):
        if not str(value or "").strip():
            raise ValueError(f"{field_name} is mandatory: an unnamed "
                             f"requirement cannot be assessed against")
    return {
        "schema": COMPLIANCE_SCHEMA,
        "requirement_id": str(requirement_id), "framework": str(framework),
        "clause": str(clause), "text": str(text),
    }


def assessment(*, requirement_id: str, policy_match: bool | None,
               evidence_ids: Sequence[str], assessed_by: str,
               outcome: str, note: str | None = None) -> dict[str, Any]:
    """One assessment against one requirement. Verdicts need evidence + a human.

    * a verdict without evidence is refused (a verdict about nothing);
    * a verdict without an assessor is refused (the platform does not audit
      itself);
    * ``outcome=COMPLIANT`` with ``policy_match=False`` is refused — compliance
      without even the policy match contradicts the record;
    * a policy match with no verdict is stored as ``POLICY_MATCH_ONLY``.
    """
    name = str(outcome or "").upper()
    if name not in {COMPLIANT, NON_COMPLIANT}:
        raise ValueError(f"unknown outcome {outcome!r}; expected {COMPLIANT} "
                         f"or {NON_COMPLIANT}")
    ids = [str(e) for e in evidence_ids if str(e).strip()]
    if not ids:
        raise ValueError(
            "an assessment without evidence is a verdict about nothing: file "
            "the control evidence the assessor saw")
    if not str(assessed_by or "").strip():
        raise ValueError("assessed_by is mandatory: the platform does not "
                         "audit itself")
    if name == COMPLIANT and policy_match is False:
        raise ValueError(
            "a COMPLIANT verdict over a failed policy match contradicts the "
            "record: fix the estate or record the contradiction as evidence")
    return {
        "schema": COMPLIANCE_SCHEMA,
        "requirement_id": str(requirement_id),
        "policy_match": policy_match,
        "outcome": name,
        "evidence_ids": ids,
        "assessed_by": str(assessed_by),
        "note": str(note) if note else None,
    }


def compliance_status(*, requirements: Sequence[Mapping[str, Any]],
                      assessments: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Per-requirement status. A match is never a verdict.

    * assessed → the assessor's outcome (COMPLIANT / NON_COMPLIANT);
    * policy-matched but never assessed → ``POLICY_MATCH_ONLY`` ("a policy
      match is not automatically proof of compliance");
    * neither → ``NOT_ASSESSED``.
    """
    rows = [dict(a) for a in assessments]
    status: dict[str, Any] = {}
    for req in requirements:
        rid = str(req.get("requirement_id"))
        history = sorted((a for a in rows
                          if str(a.get("requirement_id")) == rid
                          and a.get("outcome")),
                         key=lambda a: str(a.get("assessed_by")))
        if history:
            latest = history[-1]
            status[rid] = {
                "requirement": dict(req),
                "status": latest["outcome"],
                "latest_assessment": latest,
                "history": history,
                "reason": (f"assessed {latest['outcome']} by "
                           f"{latest['assessed_by']} over "
                           f"{len(latest.get('evidence_ids') or [])} "
                           f"evidence record(s)"),
            }
        else:
            matched = any(a.get("policy_match") for a in rows
                          if str(a.get("requirement_id")) == rid)
            status[rid] = {
                "requirement": dict(req),
                "status": POLICY_MATCH_ONLY if matched else NOT_ASSESSED,
                "latest_assessment": None, "history": [],
                "reason": (
                    "the policy matched but nobody assessed it: a policy "
                    "match is not automatically proof of compliance"
                    if matched else
                    "no policy match and no assessment: this requirement is "
                    "unaddressed, which is not compliance"),
            }
    counts: dict[str, int] = {}
    for entry in status.values():
        counts[entry["status"]] = counts.get(entry["status"], 0) + 1
    return {
        "schema": COMPLIANCE_SCHEMA,
        "requirements": status,
        "counts": counts,
        "note": ("compliance is a human verdict over evidence, mapped to "
                 "named requirements: a policy match alone never reads as "
                 "compliant"),
    }
