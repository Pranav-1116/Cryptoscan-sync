"""The twin's lifecycle, phase by phase, with the break named (spec 94 §2).

The specification draws a loop:

    DISCOVER → IDENTIFY → EVIDENCE → NORMALIZE → CORRELATE → MODEL → SNAPSHOT
      → MONITOR → DRIFT → SIMULATE → REMEDIATE → RE-DISCOVER

Most products that publish such a diagram draw every box the same colour and let the
reader assume the loop closes. This module answers a narrower and more useful question,
for each phase: *is something actually doing this, and does its output reach the next
phase?* Three answers, and they are not interchangeable:

* **CONNECTED** — the phase runs and its output is what the next phase reads;
* **PARTIAL** — it runs, but something about the hand-off is missing, and the gap is
  named rather than glossed;
* **NOT_CONNECTED** — the capability exists somewhere in the platform but nothing carries
  it into the twin's loop (``REMEDIATE`` was this until the twin began opening work
  from its own findings);
* **NOT_STARTED** — nothing has run yet. An empty estate is not a broken loop, and the
  module refuses to report it as one: "no observation has ever been recorded" and "the
  loop is wired" are different statements, and the last thing an operator needs is a
  dashboard that says the former while looking like the latter.

``loop_closed`` is computed, not asserted: it is true only when every phase is CONNECTED,
so the day the last hand-off is built the field flips by itself, and ``first_break`` names
the earliest phase that is not — the one worth building next.

Nothing here invents activity. Every count is read from the table its phase writes, and a
phase with no rows reports ``NOT_STARTED`` with a zero count rather than an optimistic
status.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import func, select

from db.models.estate_catalog import (
    EstateAssetRecord,
    EstateEvidenceRecord,
    EstateObservationRecord,
    EstateRelationshipRecord,
)
from db.models.estate_change_event import EstateChangeEvent
from db.models.estate_schedule import EstateSchedule
from db.models.estate_simulation_run import EstateSimulationRun
from db.models.estate_twin_snapshot import EstateTwinSnapshot

from api import estate_remediation

SCHEMA = "cryptoscan.estate-lifecycle/1"

CONNECTED = "CONNECTED"
PARTIAL = "PARTIAL"
NOT_CONNECTED = "NOT_CONNECTED"
NOT_STARTED = "NOT_STARTED"

#: the order the specification draws the loop in, which is also the order a reader needs
#: it in: a break early in the list makes everything after it worth less
PHASE_ORDER = (
    "DISCOVER",
    "IDENTIFY",
    "EVIDENCE",
    "NORMALIZE",
    "CORRELATE",
    "MODEL",
    "SNAPSHOT",
    "MONITOR",
    "DRIFT",
    "SIMULATE",
    "REMEDIATE",
    "RE_DISCOVER",
)

#: what each phase is answering. Written as a question so a reader can tell a phase that
#: is answering it from a phase that merely exists.
QUESTIONS = {
    "DISCOVER": "has anything looked at the estate, and where does that record live?",
    "IDENTIFY": "does an asset keep its identity across observations?",
    "EVIDENCE": "can every claim be traced to a record with a source and a hash?",
    "NORMALIZE": "is evidence turned into a typed model, or left as raw output?",
    "CORRELATE": "are relationships asserted with a basis and evidence?",
    "MODEL": "is there one canonical cryptographic model to ask questions of?",
    "SNAPSHOT": "can the estate as-observed be stored and compared later?",
    "MONITOR": "does discovery re-run without a human starting it?",
    "DRIFT": "is the difference between two observations named, not just flagged?",
    "SIMULATE": "can a change be tried on a copy without touching production?",
    "REMEDIATE": "does the twin open work, and does the work come back?",
    "RE_DISCOVER": "does a new observation prove the fix, closing the loop?",
}

#: the modules that do the work, so a reader can go read one
BACKED_BY = {
    "DISCOVER": "estate_discovery.py",
    "IDENTIFY": "estate_graph.identity / estate_catalog.py",
    "EVIDENCE": "estate_observations.py",
    "NORMALIZE": "estate_graph.build_graph",
    "CORRELATE": "estate_graph.assert_relationship",
    "MODEL": "estate_twin.py",
    "SNAPSHOT": "estate_twin_store.py",
    "MONITOR": "estate_schedule.py / estate_daemon.py",
    "DRIFT": "estate_change_feed.py / estate_drift.py",
    "SIMULATE": "estate_simulation_store.py",
    "REMEDIATE": "estate_remediation.py",
    "RE_DISCOVER": "estate_observations.sync",
}

GAPS = {
    "MONITOR": (
        "a schedule re-runs discovery only if one was created and enabled; nothing here "
        "creates one for you, and a schedule whose last run failed is not monitoring"
    ),
    "REMEDIATE": (
        "work opens from a REAL conflict, a coverage loss and a simulation blocker, and the "
        "proof is written down when it opens — but closing a HUMAN-proof item is still an "
        "assertion by a person, and no item can execute a fix"
    ),
    "RE_DISCOVER": (
        "a new observation does walk the whole pipeline again and is compared with the one "
        "before it, but nothing connects that observation to the remediation that caused it: "
        "the fix shows up as an unexplained change"
    ),
}


def _tenant_clause(model: Any, tenant_id: str | None) -> Any:
    column = model.tenant_id
    return column == tenant_id if tenant_id else column.is_(None)


def _count(db: Any, model: Any, tenant_id: str | None, *where: Any) -> int:
    stmt = select(func.count()).select_from(model).where(_tenant_clause(model, tenant_id), *where)
    return int(db.execute(stmt).scalar() or 0)


def _latest(db: Any, model: Any, column: Any, tenant_id: str | None) -> Any:
    stmt = select(func.max(column)).where(_tenant_clause(model, tenant_id))
    return db.execute(stmt).scalar()


def _phase(name: str, status: str, *, observed: dict[str, Any], detail: str) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "phase": name,
        "status": status,
        "question": QUESTIONS[name],
        "detail": detail,
        "backed_by": BACKED_BY[name],
        "observed": observed,
        "gap": GAPS.get(name),
    }
    return entry


def survey(db: Any, graph: Any | None = None, *, tenant_id: str | None = None) -> dict[str, Any]:
    """Every phase of the loop, with what is actually behind it."""
    observations = _count(db, EstateObservationRecord, tenant_id)
    assets = _count(db, EstateAssetRecord, tenant_id)
    relationships = _count(db, EstateRelationshipRecord, tenant_id)
    evidence = _count(db, EstateEvidenceRecord, tenant_id)
    snapshots = _count(db, EstateTwinSnapshot, tenant_id)
    changes = _count(db, EstateChangeEvent, tenant_id)
    simulations = _count(db, EstateSimulationRun, tenant_id)
    schedules = _count(db, EstateSchedule, tenant_id, EstateSchedule.enabled.is_(True))
    schedules_run = _count(
        db, EstateSchedule, tenant_id, EstateSchedule.enabled.is_(True),
        EstateSchedule.last_run_at.is_not(None),
    )
    last_observation = _latest(db, EstateObservationRecord, EstateObservationRecord.last_seen_at, tenant_id)

    phases: list[dict[str, Any]] = []

    phases.append(_phase(
        "DISCOVER",
        CONNECTED if observations else NOT_STARTED,
        observed={"recorded_facts": observations},
        detail=(
            "evidence collection writes a record per fact, so a run that collected nothing "
            "leaves no rows and cannot look like a run"
            if observations
            else "no observation has ever been recorded for this estate"
        ),
    ))
    phases.append(_phase(
        "IDENTIFY",
        CONNECTED if assets else NOT_STARTED,
        observed={"assets": assets},
        detail=(
            "assets are derived ids that survive re-observation, so a second run updates a "
            "record instead of creating a second one"
            if assets
            else "no asset has been identified yet"
        ),
    ))
    phases.append(_phase(
        "EVIDENCE",
        CONNECTED if evidence else NOT_STARTED,
        observed={"evidence_records": evidence},
        detail=(
            "every evidence record is stored once, keyed by its own content, and every claim "
            "cites one"
            if evidence
            else "no evidence record has been stored yet"
        ),
    ))
    phases.append(_phase(
        "NORMALIZE",
        CONNECTED if (graph is not None or assets) else NOT_STARTED,
        observed={"assets": assets, "graph_available": graph is not None},
        detail=(
            "raw collector output is turned into typed assets and facts"
            if (graph is not None or assets)
            else "nothing has been normalised into a model yet"
        ),
    ))
    phases.append(_phase(
        "CORRELATE",
        CONNECTED if relationships else NOT_STARTED,
        observed={"relationships": relationships},
        detail=(
            "relationships are asserted with a basis and evidence; an assumed edge is marked "
            "as assumed rather than dropped"
            if relationships
            else "no relationship has been asserted yet, so nothing is connected to anything"
        ),
    ))
    phases.append(_phase(
        "MODEL",
        CONNECTED if graph is not None else NOT_STARTED,
        observed={"graph_available": graph is not None},
        detail=(
            "one canonical graph answers the twin's questions; the graph store receives a copy "
            "of it, never an authority"
            if graph is not None
            else "there is no current observation to build a model from"
        ),
    ))
    phases.append(_phase(
        "SNAPSHOT",
        CONNECTED if snapshots else NOT_STARTED,
        observed={"snapshots": snapshots},
        detail=(
            "snapshots are content-addressed by projection id, so re-observing identical "
            "evidence advances a counter instead of inventing a history"
            if snapshots
            else "no snapshot has been stored; comparisons between runs are derived, not stored"
        ),
    ))
    if not schedules:
        monitor = _phase(
            "MONITOR",
            NOT_CONNECTED,
            observed={"enabled_schedules": 0, "schedules_that_have_run": 0},
            detail="discovery runs when a human or an API call starts it; nothing is scheduled",
        )
    elif not schedules_run:
        monitor = _phase(
            "MONITOR",
            PARTIAL,
            observed={"enabled_schedules": schedules, "schedules_that_have_run": 0},
            detail=(
                f"{schedules} schedule(s) exist but none has run yet, so monitoring is configured "
                "and not proven"
            ),
        )
    else:
        monitor = _phase(
            "MONITOR",
            CONNECTED,
            observed={"enabled_schedules": schedules, "schedules_that_have_run": schedules_run},
            detail=f"{schedules_run} of {schedules} enabled schedule(s) have run",
        )
    phases.append(monitor)
    phases.append(_phase(
        "DRIFT",
        CONNECTED if changes else NOT_STARTED,
        observed={"change_events": changes},
        detail=(
            "each observation is compared with the one before it and produces named claims "
            "with what they do not prove"
            if changes
            else "no change has been recorded — either the estate is unchanged or nothing has "
            "been compared yet, and this phase cannot tell you which"
        ),
    ))
    phases.append(_phase(
        "SIMULATE",
        CONNECTED if simulations else NOT_STARTED,
        observed={"stored_simulations": simulations},
        detail=(
            "a stored simulation is a question asked of a copy: quarantined, not estate state"
            if simulations
            else "no simulated change has been stored"
        ),
    ))
    # the hand-off exists now, so the phase is computed like the rest: work opened is
    # PARTIAL until a cited observation closes one — an open ticket is not a fix
    work = estate_remediation.provenance(db, tenant_id=tenant_id)
    if not work["items"]:
        remediate = _phase(
            "REMEDIATE",
            NOT_STARTED,
            observed={"work_items": 0},
            detail=(
                "the twin opens work from a REAL conflict, a coverage loss or a simulation "
                "blocker, and nothing has asked for any yet"
            ),
        )
    elif work["proven"]:
        remediate = _phase(
            "REMEDIATE",
            CONNECTED,
            observed=work,
            detail=(
                f"{work['proven']} of {work['items']} work item(s) were closed by a cited "
                "observation; the rest are still open"
            ),
        )
    else:
        remediate = _phase(
            "REMEDIATE",
            PARTIAL,
            observed=work,
            detail=(
                f"{work['open']} work item(s) are open and none has been closed by an "
                "observation yet, so the hand-off exists but has not returned"
            ),
        )
    phases.append(remediate)
    # RE_DISCOVER is the phase that answers "does a new observation prove the fix". It is
    # CONNECTED once a work item was actually closed by a cited observation, and PARTIAL
    # while observations are being compared but nothing attributes the difference to a fix.
    if work["proven"]:
        rediscover = _phase(
            "RE_DISCOVER",
            CONNECTED,
            observed={"recorded_facts": observations, "snapshots": snapshots,
                      "work_proven_by_observation": work["proven"],
                      "latest_fact_seen_at": _iso(last_observation)},
            detail=(
                "a new observation walks the pipeline again, is compared with the previous "
                "one, and closes the work item that predicted it — the change is attributed "
                "to a named fix rather than to nothing"
            ),
        )
    else:
        rediscover = _phase(
            "RE_DISCOVER",
            PARTIAL if observations else NOT_STARTED,
            observed={"recorded_facts": observations, "snapshots": snapshots,
                      "latest_fact_seen_at": _iso(last_observation)},
            detail=(
                "a new observation walks the pipeline again and is compared with the previous "
                "one; what is missing is the attribution — no work item has been closed by an "
                "observation yet, so a change cannot name the fix that caused it"
                if observations
                else "nothing has been re-discovered yet"
            ),
        )
    phases.append(rediscover)

    by_status: dict[str, int] = {CONNECTED: 0, PARTIAL: 0, NOT_CONNECTED: 0, NOT_STARTED: 0}
    for entry in phases:
        by_status[entry["status"]] += 1

    first_break = next(
        (entry["phase"] for entry in phases if entry["status"] in (PARTIAL, NOT_CONNECTED)),
        None,
    )
    loop_closed = by_status[CONNECTED] == len(phases)

    return {
        "schema": SCHEMA,
        "phases": phases,
        "by_status": by_status,
        "loop_closed": loop_closed,
        "first_break": first_break,
        "phase_order": list(PHASE_ORDER),
        "meaning": (
            "each phase says whether something is doing it and whether its output reaches the "
            "next phase — the loop is reported as closed only when every phase is CONNECTED, "
            "and the earliest break is named"
            if not loop_closed
            else "every phase is CONNECTED: the loop closes, and a remediation is proven by the "
            "observation that follows it"
        ),
        "limits": [
            "NOT_STARTED is not a defect: an estate nothing has observed yet has an unwalked "
            "loop, and the counts behind every phase are in this payload so the difference is "
            "visible",
            "a count is evidence that a phase wrote something, never that what it wrote is "
            "correct — correctness is evidence strength and coverage, elsewhere in the twin",
            "loop_closed is computed from the phases above; it flips when the last hand-off is "
            "built and is not maintained by hand",
        ],
    }


def _iso(moment: Any) -> str | None:
    if moment is None:
        return None
    value = moment if getattr(moment, "tzinfo", None) else moment.replace(tzinfo=None)
    return value.isoformat()
