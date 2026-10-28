"""The twin opens work — REMEDIATE, the one phase that was NOT_CONNECTED (spec 94 §23).

The loop ran `… → SIMULATE → REMEDIATE → RE-DISCOVER`, and the twin could answer eleven of
its twelve phases. The twelfth was a screen: a REAL conflict, a coverage loss and a
simulation blocker were all visible, and every one of them expected an operator to write a
ticket somewhere else. Nothing in the product could then say whether the estate moved
because of that ticket, so `RE_DISCOVER` could compare two observations and never attribute
the difference to anything.

This module closes that hand-off, and it is deliberately the *narrow* version:

**Opening work is a proposal, not an action.** :func:`propose` reads what the twin already
holds and returns candidates. It writes only when the caller passes ``persist=True``, so a
dry run can be read before anything appears in someone's queue. A candidate is keyed by
``hash(source, subject, claim)``, so re-proposing refreshes the same item with the current
claim instead of filing a second ticket for the same disagreement.

**The proof is written down when the work is opened.** A work item that nobody can check is
how "remediated" becomes a claim. Each item carries a ``proof``:

* ``COVERAGE_DISPUTE`` — the asset's field has two currently-asserted values. The proof is
  that the record holds **one** current value again. It is deliberately *not* "the value I
  wanted won": this module has no opinion on which plane is right, and a resolution that
  picks a side without evidence is the thing being avoided;
* ``COLLECTOR_STATUS`` — a plane failed, was partial, or was never attempted. The proof is
  that the same plane reports ``COMPLETE`` on a later run;
* ``HUMAN`` — a simulation blocker of a kind this platform cannot yet test for. It is never
  auto-closed, and it says so.

**Closure is a citation.** :func:`reconcile` moves an item to ``PROVEN`` only when it can
name the observation row and the evidence id that closed it. No current value means
``PROOF_UNAVAILABLE`` — "the fact is no longer asserted" is not "it was fixed" — and an
unchanged world stays ``STILL_OPEN`` with the attempt counted.

Nothing here resolves a conflict, edits an asset, or touches the estate: it writes work
rows and reads observations.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Mapping

from sqlalchemy import select

from db.models.estate_catalog import EstateObservationRecord
from db.models.estate_remediation_work import EstateRemediationWork

from api import estate_conflicts

SCHEMA = "cryptoscan.estate-remediation/1"

OPEN = "OPEN"
PROVEN = "PROVEN"
ABANDONED = "ABANDONED"

CONFLICT = "CONFLICT"
COVERAGE_LOSS = "COVERAGE_LOSS"
SIMULATION_BLOCKER = "SIMULATION_BLOCKER"

PROOF_COVERAGE_DISPUTE = "COVERAGE_DISPUTE"
PROOF_COLLECTOR_STATUS = "COLLECTOR_STATUS"
PROOF_HUMAN = "HUMAN"

#: which sources this module can open work from, and which proof each one gets
PROOF_BY_SOURCE = {
    CONFLICT: PROOF_COVERAGE_DISPUTE,
    COVERAGE_LOSS: PROOF_COLLECTOR_STATUS,
    SIMULATION_BLOCKER: PROOF_HUMAN,
}

#: a plane in one of these states has nothing left to prove
COLLECTED_STATUSES = frozenset({"COMPLETE", "OK", "COLLECTED"})

LIMITS = [
    "a work item is a record that someone must act on — this module cannot execute a fix, "
    "close a ticket in another system, or verify that a fix was authorised",
    "a PROVEN item proves the observation it cites, not that the change was caused by the "
    "work item: attribution is a sequence the operator reads, not a causal proof",
    "a HUMAN proof item is never auto-closed, and one that is closed by hand keeps its "
    "assertion unverified on purpose",
    "conflict proofs test that the dispute is no longer held; they never pick a side",
]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def claim_key(source: str, subject: str, claim: str) -> str:
    """Deterministic id for one piece of work: the same disagreement is one item."""
    material = f"{source}|{subject}|{claim}"
    return "rem-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _conflict_candidates(conflicts: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Only a REAL or an UNKNOWN conflict is work. EXPLAINED is a report, not a task."""
    candidates: list[dict[str, Any]] = []
    for entry in conflicts.get("conflicts") or []:
        classification = entry.get("classification")
        if classification == "EXPLAINED":
            continue
        field = str(entry.get("field") or "unknown")
        asset_id = str(entry.get("asset_id") or "")
        # the fact type the history files it under, when the conflict came from there
        fact_type = str(entry.get("fact_type") or field)
        values = [str(item.get("value")) for item in entry.get("values") or []]
        name = entry.get("asset_name") or asset_id
        claim = f"{name}: {field} has {len(values)} currently-asserted values ({', '.join(sorted(values))})"
        candidates.append({
            "source": CONFLICT,
            "subject_id": asset_id,
            "subject_kind": "ASSET",
            "title": f"Resolve the {field} conflict on {name}",
            "claim": claim,
            "not_proven": [
                "which of the asserted values is correct — the twin holds both",
                "that either plane is wrong",
            ],
            "severity": "HIGH" if classification == "REAL" else "MEDIUM",
            "proof": {
                "kind": PROOF_COVERAGE_DISPUTE,
                "fact_type": fact_type,
                "expected": "ONE_CURRENT_VALUE",
                "note": (
                    "proven when the per-fact record holds a single CURRENT value again; "
                    "the surviving value is cited, not chosen here"
                ),
            },
            "detail": {
                "classification": classification,
                "seen_by": list(entry.get("seen_by") or []),
                "values": values,
            },
        })
    return candidates


def _coverage_candidates(graph: Any) -> list[dict[str, Any]]:
    """A plane that did not fully run is coverage debt with an owner, not a statistic."""
    if graph is None:
        return []
    candidates: list[dict[str, Any]] = []
    for row in graph.coverage().get("collectors") or []:
        plane = str(row.get("plane") or "UNKNOWN")
        status = str(row.get("status") or "UNKNOWN").upper()
        if status in COLLECTED_STATUSES:
            continue
        expected = int(row.get("expected") or 0)
        collected = int(row.get("collected") or 0)
        reason = row.get("reason")
        claim = f"{plane} reported {status} ({collected}/{expected} collected)"
        candidates.append({
            "source": COVERAGE_LOSS,
            "subject_id": plane,
            "subject_kind": "COLLECTOR_PLANE",
            "title": f"Restore {plane} coverage",
            "claim": claim if not reason else f"{claim}: {reason}",
            "not_proven": [
                "that the plane is empty — a plane that did not run observed nothing",
                "that anything else in the estate changed while it was down",
            ],
            "severity": "HIGH" if status == "FAILED" else "MEDIUM",
            "proof": {
                "kind": PROOF_COLLECTOR_STATUS,
                "plane": plane,
                "expected": "COMPLETE",
                "note": "proven when a later run reports this plane COMPLETE",
            },
            "detail": {"status": status, "expected": expected, "collected": collected,
                       "impact": row.get("impact")},
        })
    return candidates


def _blocker_candidates(simulation: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """Simulation blockers are real questions, but this platform cannot test their answer."""
    if not simulation:
        return []
    candidates: list[dict[str, Any]] = []
    simulation_id = str(simulation.get("simulation_id") or "latest")
    for blocker in simulation.get("blockers") or []:
        kind = str(blocker.get("kind") or blocker.get("blocker") or "UNKNOWN")
        subject = str(blocker.get("asset_id") or blocker.get("subject") or simulation_id)
        claim = str(blocker.get("detail") or blocker.get("message") or kind)
        candidates.append({
            "source": SIMULATION_BLOCKER,
            "subject_id": subject,
            "subject_kind": "SIMULATION",
            "title": f"Clear the {kind} blocker on {subject}",
            "claim": claim,
            "not_proven": [
                "that the blocker is the only obstacle — a simulation walks a copy, not the estate",
                "that clearing it makes the scenario safe",
            ],
            "severity": "MEDIUM",
            "proof": {
                "kind": PROOF_HUMAN,
                "expected": "HUMAN_ASSERTION",
                "note": (
                    "this platform has no test for this blocker class, so closure is an "
                    "assertion by a named person and stays unverified"
                ),
            },
            "detail": {"simulation_id": simulation_id, "kind": kind},
        })
    return candidates


def propose(
    db: Any,
    *,
    graph: Any = None,
    simulation: Mapping[str, Any] | None = None,
    tenant_id: str | None,
    persist: bool = False,
    opened_by: str | None = None,
    opened_from: str | None = None,
) -> dict[str, Any]:
    """Ask the twin what work it would open. Writes nothing unless ``persist``."""
    conflicts = estate_conflicts.survey(db, graph, tenant_id=tenant_id)
    candidates = (
        _conflict_candidates(conflicts)
        + _coverage_candidates(graph)
        + _blocker_candidates(simulation)
    )

    rows = _existing(db, tenant_id)
    created = refreshed = 0
    moment = _now()
    out: list[dict[str, Any]] = []
    for candidate in candidates:
        key = claim_key(candidate["source"], str(candidate["subject_id"]), candidate["claim"])
        row = rows.get(key)
        entry = {
            **candidate,
            "claim_key": key,
            "status": row.status if row else OPEN,
            "opened_at": _iso(row.opened_at) if row else moment.isoformat(),
        }
        if row is None:
            created += 1
            if persist:
                db.add(EstateRemediationWork(
                    tenant_id=tenant_id,
                    claim_key=key,
                    source=candidate["source"],
                    subject_id=candidate["subject_id"],
                    subject_kind=candidate["subject_kind"],
                    title=candidate["title"],
                    claim=candidate["claim"],
                    not_proven=list(candidate["not_proven"]),
                    severity=candidate["severity"],
                    status=OPEN,
                    opened_at=moment,
                    opened_by=opened_by,
                    opened_from=opened_from,
                    proof_kind=candidate["proof"]["kind"],
                    proof_fact_type=candidate["proof"].get("fact_type"),
                    proof_expected=candidate["proof"]["expected"],
                    proof_note=candidate["proof"]["note"],
                ))
            out.append(entry)
            continue
        # the same disagreement, still held: refresh the claim, keep the opening date
        refreshed += 1
        if persist:
            row.claim = candidate["claim"]
            row.title = candidate["title"]
            row.not_proven = list(candidate["not_proven"])
            row.severity = candidate["severity"]
        out.append(entry)

    if persist:
        db.commit()

    return {
        "schema": SCHEMA,
        "persisted": bool(persist),
        "candidates": out,
        "count": len(out),
        "created": created,
        "refreshed": refreshed,
        "by_source": _count_by(out, "source"),
        "by_severity": _count_by(out, "severity"),
        "conflicts_surveyed": conflicts.get("count", 0),
        "meaning": (
            "each item names the observation that would close it; nothing here resolves a "
            "conflict, edits an asset or claims a fix"
        ),
        "limits": LIMITS,
    }


def reconcile(
    db: Any,
    *,
    graph: Any = None,
    tenant_id: str | None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Check every open item against what was observed since. Closure cites its record."""
    moment = now or _now()
    rows = [row for row in _existing(db, tenant_id).values() if row.status == OPEN]
    proven: list[dict[str, Any]] = []
    still_open: list[dict[str, Any]] = []
    unavailable: list[dict[str, Any]] = []

    for row in rows:
        row.reconcile_attempts = int(row.reconcile_attempts or 0) + 1
        row.last_checked_at = moment
        verdict = _check(row, db, graph, tenant_id, moment)
        if verdict["outcome"] == PROVEN:
            row.status = PROVEN
            row.proven_at = moment
            row.proof_observation_id = verdict.get("observation_id")
            row.proof_evidence_id = verdict.get("evidence_id")
            row.proof_observed_at = verdict.get("observed_at")
            row.proof_detail = _jsonable(verdict)
            proven.append(_public(row))
        elif verdict["outcome"] == "PROOF_UNAVAILABLE":
            unavailable.append({**_public(row), "reason": verdict["reason"]})
        else:
            still_open.append({**_public(row), "reason": verdict["reason"]})

    db.commit()
    return {
        "schema": SCHEMA,
        "checked": len(rows),
        "proven": proven,
        "still_open": still_open,
        "proof_unavailable": unavailable,
        "counts": {"PROVEN": len(proven), "STILL_OPEN": len(still_open),
                   "PROOF_UNAVAILABLE": len(unavailable)},
        "meaning": (
            "PROVEN means the cited observation closed the item; PROOF_UNAVAILABLE means the "
            "fact is no longer asserted, which is not the same as fixed"
        ),
        "limits": LIMITS,
    }


def _check(
    row: EstateRemediationWork,
    db: Any,
    graph: Any,
    tenant_id: str | None,
    moment: datetime,
) -> dict[str, Any]:
    if row.proof_kind == PROOF_COVERAGE_DISPUTE:
        return _check_coverage_dispute(row, db, tenant_id)
    if row.proof_kind == PROOF_COLLECTOR_STATUS:
        return _check_collector_status(row, graph)
    return {
        "outcome": "STILL_OPEN",
        "reason": (
            "closure of a HUMAN-proof item is an assertion by a person, and this check does "
            "not accept an assertion as a proof"
        ),
    }


def _check_coverage_dispute(
    row: EstateRemediationWork, db: Any, tenant_id: str | None
) -> dict[str, Any]:
    stmt = select(EstateObservationRecord).where(
        EstateObservationRecord.asset_id == row.subject_id,
        EstateObservationRecord.fact_type == (row.proof_fact_type or ""),
        EstateObservationRecord.lifecycle_state == "CURRENT",
        EstateObservationRecord.tenant_id == tenant_id
        if tenant_id
        else EstateObservationRecord.tenant_id.is_(None),
    )
    current = list(db.execute(stmt).scalars())
    values = {str(item.value) for item in current}
    if not values:
        return {
            "outcome": "PROOF_UNAVAILABLE",
            "reason": (
                "the fact is no longer asserted at all — nothing was fixed and nothing proves "
                "the dispute was resolved"
            ),
        }
    if len(values) > 1:
        return {
            "outcome": "STILL_OPEN",
            "reason": f"{len(values)} values are still currently asserted",
            "values": sorted(values),
        }
    survivor = current[0]
    return {
        "outcome": PROVEN,
        "fact_type": survivor.fact_type,
        "value": survivor.value,
        "observation_id": survivor.id,
        "evidence_id": survivor.evidence_id,
        "observed_at": survivor.last_seen_at,
        "reason": (
            "one value is currently asserted; the twin cites the record and does not judge "
            "whether it is the right one"
        ),
    }


def _check_collector_status(row: EstateRemediationWork, graph: Any) -> dict[str, Any]:
    if graph is None:
        return {
            "outcome": "STILL_OPEN",
            "reason": "no current estate projection was supplied, so coverage was not re-read",
        }
    plane = str(row.subject_id or "")
    for entry in graph.coverage().get("collectors") or []:
        if str(entry.get("plane")) != plane:
            continue
        status = str(entry.get("status") or "UNKNOWN").upper()
        if status in COLLECTED_STATUSES:
            return {
                "outcome": PROVEN,
                "plane": plane,
                "status": status,
                "collected": int(entry.get("collected") or 0),
                "expected": int(entry.get("expected") or 0),
                "reason": "the plane reported complete on a later run",
            }
        return {"outcome": "STILL_OPEN", "reason": f"{plane} still reports {status}"}
    return {
        "outcome": "STILL_OPEN",
        "reason": f"{plane} did not run in the current projection — absence is not a pass",
    }


def listing(db: Any, *, tenant_id: str | None) -> dict[str, Any]:
    """Every work item the twin has opened, open items first."""
    rows = sorted(
        _existing(db, tenant_id).values(),
        key=lambda row: ({OPEN: 0, PROVEN: 1, ABANDONED: 2}[row.status], row.opened_at),
    )
    items = [_public(row) for row in rows]
    return {
        "schema": SCHEMA,
        "items": items,
        "count": len(items),
        "by_status": _count_by(items, "status"),
        "by_source": _count_by(items, "source"),
        "meaning": (
            "a PROVEN item names the observation that closed it; an ABANDONED item is kept so "
            "the estate remembers work that was started and dropped"
        ),
        "limits": LIMITS,
    }


def provenance(db: Any, *, tenant_id: str | None) -> dict[str, Any]:
    """What the phase needs for the lifecycle: opened, returned, and the last proof."""
    items = listing(db, tenant_id=tenant_id)
    proven = [item for item in items["items"] if item["status"] == PROVEN]
    return {
        "work_items": items["count"],
        "items": items["count"],
        "open": items["by_status"].get(OPEN, 0),
        "proven": len(proven),
        "abandoned": items["by_status"].get(ABANDONED, 0),
        "last_proven_at": max((item["proven_at"] for item in proven if item["proven_at"]), default=None),
    }


def _existing(db: Any, tenant_id: str | None) -> dict[str, EstateRemediationWork]:
    stmt = select(EstateRemediationWork).where(
        EstateRemediationWork.tenant_id == tenant_id
        if tenant_id
        else EstateRemediationWork.tenant_id.is_(None)
    )
    return {str(row.claim_key): row for row in db.execute(stmt).scalars()}


def _public(row: EstateRemediationWork) -> dict[str, Any]:
    return {
        "claim_key": row.claim_key,
        "source": row.source,
        "subject_id": row.subject_id,
        "subject_kind": row.subject_kind,
        "title": row.title,
        "claim": row.claim,
        "not_proven": list(row.not_proven or []),
        "severity": row.severity,
        "status": row.status,
        "opened_at": _iso(row.opened_at),
        "opened_by": row.opened_by,
        "opened_from": row.opened_from,
        "proof": {
            "kind": row.proof_kind,
            "fact_type": row.proof_fact_type,
            "expected": row.proof_expected,
            "note": row.proof_note,
        },
        "proven_at": _iso(row.proven_at),
        "proof_observation_id": row.proof_observation_id,
        "proof_evidence_id": row.proof_evidence_id,
        "reconcile_attempts": row.reconcile_attempts,
        "last_checked_at": _iso(row.last_checked_at),
    }


def _count_by(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = str(item.get(key) or "UNKNOWN")
        counts[value] = counts.get(value, 0) + 1
    return counts


def _jsonable(payload: Mapping[str, Any]) -> dict[str, Any]:
    """A verdict may cite a datetime; the JSON column needs it as text."""
    return {
        key: (value.isoformat() if hasattr(value, "isoformat") else value)
        for key, value in payload.items()
    }


def _iso(moment: Any) -> str | None:
    if moment is None:
        return None
    return moment.isoformat() if hasattr(moment, "isoformat") else str(moment)
