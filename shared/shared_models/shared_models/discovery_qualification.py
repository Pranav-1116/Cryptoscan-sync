"""Discovery qualification tracking (roadmap item 5).

The standing directive: "Don't claim support simply because an integration has a
fixture or a connector definition. Track its actual qualification status."

So support is not a boolean someone flips — it is a qualification state backed
by evidence:

* ``DEFINED`` — a connector or driver exists. This is a statement about code,
  not about the product's ability to talk to a real target;
* ``FIXTURE_VERIFIED`` — it passes against fixtures. This is a statement about
  tests, still not about real targets;
* ``LIVE_QUALIFIED`` — someone ran it against a real live target and filed the
  evidence. Only this state may back a support claim;
* ``GAPPED`` — declared unsupported for this family, with a reason;
* ``REVOKED`` — a qualification withdrawn after a failure, with the evidence of
  the failure kept beside the original proof.

Only ``LIVE_QUALIFIED`` with resolvable evidence can support a claim. Every
other state answers the same question in the same words: not qualified yet.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

QUALIFICATION_SCHEMA = "cryptoscan.discovery-qualification/1"

DEFINED = "DEFINED"
FIXTURE_VERIFIED = "FIXTURE_VERIFIED"
LIVE_QUALIFIED = "LIVE_QUALIFIED"
GAPPED = "GAPPED"
REVOKED = "REVOKED"
QUALIFICATION_STATES: tuple[str, ...] = (
    DEFINED, FIXTURE_VERIFIED, LIVE_QUALIFIED, GAPPED, REVOKED)

#: which states may back a support claim
CLAIMABLE_STATES = frozenset({LIVE_QUALIFIED})


def qualification(*, collector: str, family: str, state: str,
                  evidence_ids: Sequence[str] = (),
                  observed_at: str | None = None,
                  reason: str | None = None) -> dict[str, Any]:
    """One qualification record. ``LIVE_QUALIFIED`` requires evidence and a clock.

    A live qualification with no evidence or no timestamp is refused at
    construction: that is exactly the claim this module exists to stop.
    """
    name = str(state or "").upper()
    if name not in QUALIFICATION_STATES:
        raise ValueError(f"unknown qualification state {state!r}; expected one of "
                         f"{', '.join(QUALIFICATION_STATES)}")
    ids = [str(e) for e in evidence_ids if str(e).strip()]
    if name == LIVE_QUALIFIED:
        if not ids:
            raise ValueError(
                "a live qualification without evidence is a fixture claim in a "
                "trench coat: file the run evidence or keep the state at "
                "FIXTURE_VERIFIED")
        if not str(observed_at or "").strip():
            raise ValueError("a live qualification without observed_at cannot be "
                             "aged or audited")
    return {
        "schema": QUALIFICATION_SCHEMA,
        "collector": str(collector or "(unnamed)"),
        "family": str(family or "(unnamed)"),
        "state": name,
        "evidence_ids": ids,
        "observed_at": str(observed_at) if observed_at else None,
        "reason": str(reason) if reason else None,
    }


def support_claim(rows: Iterable[Mapping[str, Any]], *, collector: str,
                  family: str) -> dict[str, Any]:
    """May ``collector`` be claimed as supported for ``family``? Only live
    qualification says yes — and a later REVOKED record wins over an earlier
    LIVE_QUALIFIED one, with both records preserved.

    Fixture-only support is refused in exactly these words, so the UI, the API
    and the sales deck all get the same answer.
    """
    matched = [dict(r) for r in rows
               if str(r.get("collector")) == str(collector)
               and str(r.get("family")) == str(family)]
    if not matched:
        verdict, reason = False, (
            "no qualification record for this collector and family: support is "
            "unknown, which is not supported")
    elif any(r.get("state") == REVOKED for r in matched):
        verdict, reason = False, (
            "the qualification was revoked after a failure: the records are kept "
            "on both sides and the claim is withdrawn")
    elif any(r.get("state") == LIVE_QUALIFIED and r.get("evidence_ids")
             for r in matched):
        verdict, reason = True, (
            "live-qualified with filed run evidence against a real target")
    else:
        states = sorted({str(r.get("state")) for r in matched})
        verdict, reason = False, (
            f"the strongest record here is {states[-1] if len(states) == 1 else '/'.join(states)}: "
            f"a fixture or a connector definition is not qualification — this "
            f"integration is not qualified for support claims")
    return {"collector": str(collector), "family": str(family),
            "claimable": verdict, "reason": reason,
            "records": matched}


def qualification_summary(rows: Iterable[Mapping[str, Any]],
                          families: Sequence[str]) -> dict[str, Any]:
    """Per-family qualification counts — honest about zeroes and about gaps.

    A family with no qualified collector reports ``0`` qualified *and* names the
    state its collectors actually hold: a zero here is a measured zero, not a
    failed read.
    """
    records = [dict(r) for r in rows]
    per_family: dict[str, Any] = {}
    for family in families:
        family_rows = [r for r in records if str(r.get("family")) == str(family)]
        per_family[str(family)] = {
            "counts": {state: sum(1 for r in family_rows if r.get("state") == state)
                       for state in QUALIFICATION_STATES},
            "claimable_collectors": sorted(
                {str(r.get("collector")) for r in family_rows
                 if r.get("state") in CLAIMABLE_STATES and r.get("evidence_ids")}),
        }
    return {
        "schema": QUALIFICATION_SCHEMA,
        "families": per_family,
        "totals": {state: sum(1 for r in records if r.get("state") == state)
                   for state in QUALIFICATION_STATES},
        "note": ("a fixture is not qualification and a connector definition is "
                 "not support: only live-qualified, evidence-backed collectors "
                 "may be claimed, and revoked qualifications stay visible"),
    }
