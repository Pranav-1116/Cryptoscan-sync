"""Live change detection for the estate, and the feed of what moved (spec 94 §17–§18, §23).

Drift as an endpoint you call is a report. Change detection as a *consequence of
every observation* is monitoring — and monitoring is only useful if it answers the
question this module exists for: **what changed, specifically?**

So the unit here is not "drift detected". It is a list of claims, each naming a
subject, what it was, what it is now, and what that does and does not mean:

    COVERAGE_DEGRADED   HSM: COMPLETE → FAILED
                        the plane stopped answering, so its estate is UNKNOWN,
                        not absent
    CRYPTO_DEMOTED      Payment API AES-256-GCM: OBSERVED → SUPPORTED
                        proof was lost; the cryptography was not necessarily removed
    ASSET_CHANGED       Payment API: environment production → staging
    RELATIONSHIP_LOST   Payment API —uses_hsm→ HSM-03 (PKCS11_REFERENCE)
    ASSET_ADDED         HSM-04 (HSM) — first observed in this run

Three rules keep that list honest, and each is enforced rather than documented:

1. **A change is described from evidence, never inferred.** Every claim is derived
   from :func:`shared_models.estate_twin.compare`, which reads the two projection
   payloads; nothing is re-collected to make a change look bigger, and nothing is
   guessed about a subject that is absent from one side.
2. **A plane that stopped collecting outranks everything.** Losing coverage is
   ``CRITICAL`` because the estate under it becomes ``UNKNOWN``; a crypto movement
   while a plane is dark is not an improvement, and the severity function says so
   before it says anything else.
3. **"Nothing changed" is not a feed entry.** The feed records movement. An
   identical re-observation returns ``NONE`` and stores nothing — the run itself is
   the record that someone looked. Storing a row per quiet scan would bury the one
   afternoon something did move.
4. **A simulation is not an observation.** Nothing in this module reads
   ``estate_simulation_runs``; a "what if" cannot enter the feed, and a test asserts
   it.

The recording layer is deliberately dumb: it appends the digest of one comparison,
keyed by ``(baseline projection id, current projection id)`` so a re-run of the same
detection increments an observation counter instead of duplicating the event. The
findings are immutable; only acknowledgement moves.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Mapping

from sqlalchemy import select

from db.models.estate_change_event import EstateChangeEvent
from shared_models import estate_twin

SCHEMA = "cryptoscan.estate-change-event/1"
FEED_SCHEMA = "cryptoscan.estate-change-feed/1"

#: severity is a *consequence* order, not a confidence order: coverage loss makes
#: the estate unknown, so nothing can outrank it
SEVERITY_ORDER = ("NONE", "INFO", "WARNING", "CRITICAL")

SEVERITY_MEANING = {
    "CRITICAL": (
        "a plane stopped answering or stronger evidence was lost. Everything under it is UNKNOWN "
        "until collection is restored — this is not a change to read, it is a measurement that "
        "stopped happening"
    ),
    "WARNING": (
        "cryptographic artefacts, usage states, assets or relationships moved. The scan covered what "
        "it claims, so these are observations of the estate rather than gaps in it"
    ),
    "INFO": (
        "the projection ids differ but no compared surface did — treat it as unexplained. An "
        "unexplained difference is not a clean one"
    ),
    "NONE": "the two observations are identical; that is not a statement that the estate is safe",
    "BASELINE": "this is the first observation; it becomes the baseline. Nothing has been compared yet",
}

NEXT_ACTION = {
    "COVERAGE_DEGRADED": (
        "restore the plane: check its credentials, network path and the collector log. Until it "
        "answers, the BOMs that depend on it under-report and its estate is UNKNOWN, not absent"
    ),
    "EVIDENCE_LOST": (
        "stronger evidence disappeared: re-collect the affected asset and confirm the collector that "
        "produced it still runs. Losing proof is not the same as the cryptography being removed, and "
        "it must not be reported as either"
    ),
    "CRYPTO_CHANGED": (
        "review the affected BOM and the asset: a usage-state move changes what the bank can claim, "
        "and a demotion changes what it can prove"
    ),
    "ESTATE_CHANGED": (
        "review the new or changed assets and relationships before the next BOM export: an asset "
        "that appeared without a matching change ticket is the interesting case"
    ),
    "UNEXPLAINED": (
        "the evidence digest moved with no compared surface changing — find out why before treating "
        "the estate as steady"
    ),
    "BASELINE": (
        "no action: this observation is the baseline for the next comparison"
    ),
}


def _iso(moment: Any) -> str | None:
    if moment is None:
        return None
    if isinstance(moment, str):
        return moment
    value = moment if getattr(moment, "tzinfo", None) else moment.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _subject(entry: Mapping[str, Any]) -> str:
    name = entry.get("name") or entry.get("subject_name") or entry.get("asset_name")
    identity = entry.get("asset_id") or entry.get("subject") or ""
    if name and identity:
        return f"{name} ({identity})"
    return str(name or identity or "unidentified subject")


def _crypto_label(item: Mapping[str, Any]) -> str:
    label = item.get("algorithm") or item.get("protocol") or item.get("curve") or "unspecified primitive"
    if item.get("key_size"):
        label = f"{label}-{item['key_size']}"
    if item.get("mode"):
        label = f"{label}-{item['mode']}"
    return str(label)


def _change(kind: str, *, severity: str, subject: str, detail: str, before: Any = None,
            after: Any = None, means: str | None = None, evidence_ids: Any = None) -> dict[str, Any]:
    return {
        "kind": kind,
        "severity": severity,
        "subject": subject,
        "before": before,
        "after": after,
        "detail": detail,
        "means": means,
        "evidence_ids": list(evidence_ids or []),
    }


def _from_compare(comparison: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Turn a twin comparison into named claims. One claim per thing that moved."""
    changes: list[dict[str, Any]] = []

    for plane in comparison.get("coverage", {}).get("degraded") or []:
        changes.append(_change(
            "COVERAGE_DEGRADED",
            severity="CRITICAL",
            subject=str(plane.get("plane")),
            before=plane.get("before"),
            after=plane.get("after"),
            detail=(
                f"{plane.get('plane')} went {plane.get('before')} → {plane.get('after')}"
                + (f" — {plane['reason']}" if plane.get("reason") else "")
                + f" (collected {plane.get('before_collected')} → {plane.get('after_collected')})"
            ),
            means=(
                "the estate under this plane is UNKNOWN now, not absent. Anything this plane fed is a "
                "gap in measurement, so a 'change' observed elsewhere in the same window is suspect"
            ),
        ))

    for plane in comparison.get("coverage", {}).get("improved") or []:
        changes.append(_change(
            "COVERAGE_IMPROVED",
            severity="INFO",
            subject=str(plane.get("plane")),
            before=plane.get("before"),
            after=plane.get("after"),
            detail=f"{plane.get('plane')} went {plane.get('before')} → {plane.get('after')}",
            means="more of this plane is observed than before, so its rows become comparable again",
        ))

    evidence = comparison.get("evidence") or {}
    gained = int(evidence.get("stronger_gained") or 0)
    lost = int(evidence.get("stronger_lost") or 0)
    if lost > gained:
        changes.append(_change(
            "EVIDENCE_LOST",
            severity="CRITICAL",
            subject="estate evidence strength",
            before=gained,
            after=lost,
            detail=(
                f"stronger evidence fell by {lost - gained} record(s) across the estate "
                f"({lost} lost, {gained} gained)"
            ),
            means=(
                "the same facts may still be claimed, but with weaker proof than before. A weaker "
                "BOM is a weaker audit position even when nothing appears to have moved"
            ),
        ))

    crypto = comparison.get("crypto") or {}
    for item in crypto.get("demoted") or []:
        changes.append(_change(
            "CRYPTO_DEMOTED",
            severity="WARNING",
            subject=str(item.get("asset_name") or item.get("asset_id")),
            before=item.get("before"),
            after=item.get("after"),
            detail=(
                f"{_crypto_label(item)} on {item.get('asset_name') or item.get('asset_id')}: "
                f"{item.get('before')} → {item.get('after')}"
            ),
            means=(
                "proof was lost, not necessarily the cryptography. The artefact may still be in use; "
                "what changed is what we can evidence"
            ),
        ))
    for item in crypto.get("promoted") or []:
        changes.append(_change(
            "CRYPTO_PROMOTED",
            severity="WARNING",
            subject=str(item.get("asset_name") or item.get("asset_id")),
            before=item.get("before"),
            after=item.get("after"),
            detail=(
                f"{_crypto_label(item)} on {item.get('asset_name') or item.get('asset_id')}: "
                f"{item.get('before')} → {item.get('after')}"
            ),
            means="stronger evidence now supports this artefact than before",
        ))
    for item in crypto.get("added") or []:
        changes.append(_change(
            "CRYPTO_ADDED",
            severity="WARNING",
            subject=str(item.get("asset_name") or item.get("asset_id")),
            after=item.get("usage_state"),
            detail=(
                f"{_crypto_label(item)} ({item.get('usage_state')}) first evidenced on "
                f"{item.get('asset_name') or item.get('asset_id')}"
            ),
            means=(
                "a new artefact is evidenced. SUPPORTED would be capability, not use — read the "
                "usage_state before calling it deployed"
            ),
            evidence_ids=item.get("evidence_ids"),
        ))
    for item in crypto.get("removed") or []:
        changes.append(_change(
            "CRYPTO_REMOVED",
            severity="WARNING",
            subject=str(item.get("asset_name") or item.get("asset_id")),
            before=item.get("usage_state"),
            detail=(
                f"{_crypto_label(item)} ({item.get('usage_state')}) is no longer evidenced on "
                f"{item.get('asset_name') or item.get('asset_id')}"
            ),
            means=(
                "no evidence mentions it now. That is not proof it was removed — a collector that "
                "stopped reading this asset produces the same picture, which is why a lost plane "
                "outranks this claim"
            ),
        ))

    assets = comparison.get("assets") or {}
    for asset in assets.get("added") or []:
        changes.append(_change(
            "ASSET_ADDED", severity="WARNING", subject=_subject(asset),
            after=asset.get("type"),
            detail=(
                f"{asset.get('name')} ({asset.get('type')}"
                + (f", {asset['environment']}" if asset.get("environment") else "")
                + ") first observed in this run"
            ),
            means=(
                "an asset exists that did not before. An asset that appeared without a change ticket "
                "is the case worth looking at"
            ),
        ))
    for asset in assets.get("removed") or []:
        changes.append(_change(
            "ASSET_REMOVED", severity="WARNING", subject=_subject(asset),
            before=asset.get("type"),
            detail=f"{asset.get('name')} ({asset.get('type')}) is no longer observed",
            means="the asset is gone from this observation, which is not the same as decommissioned",
        ))
    for asset in assets.get("changed") or []:
        fields = list(asset.get("changed_fields") or [])
        changes.append(_change(
            "ASSET_CHANGED", severity="INFO", subject=_subject(asset),
            before=asset.get("before"),
            after=asset.get("after"),
            detail=f"{asset.get('name')} changed: {', '.join(fields) or 'unlisted fields'}",
            means=(
                "metadata moved. If one of these fields identifies the asset (name, hostname, serial), "
                "the next run may report an add+remove instead — identity drift looks like churn"
            ),
        ))

    relationships = comparison.get("relationships") or {}
    for edge in relationships.get("established") or []:
        changes.append(_change(
            "RELATIONSHIP_ESTABLISHED", severity="INFO",
            subject=f"{edge.get('subject_name') or edge.get('subject')} —{edge.get('predicate')}→ "
                    f"{edge.get('object_name') or edge.get('object')}",
            after=edge.get("basis"),
            detail=(
                f"new edge {edge.get('predicate')} from {edge.get('subject_name')} to "
                f"{edge.get('object_name')} (basis {edge.get('basis')}, confidence "
                f"{edge.get('confidence')})"
            ),
            means="a correlation was established from evidence this run; it is not an assumption",
        ))
    for edge in relationships.get("lost") or []:
        changes.append(_change(
            "RELATIONSHIP_LOST", severity="WARNING",
            subject=f"{edge.get('subject_name') or edge.get('subject')} —{edge.get('predicate')}→ "
                    f"{edge.get('object_name') or edge.get('object')}",
            before=edge.get("basis"),
            detail=(
                f"edge {edge.get('predicate')} from {edge.get('subject_name')} to "
                f"{edge.get('object_name')} is no longer established (was basis "
                f"{edge.get('basis')})"
            ),
            means=(
                "the correlation is no longer supported by evidence. Blast-radius answers that used "
                "this edge are now narrower and less complete"
            ),
        ))

    unknown = comparison.get("unknown") or {}
    delta = int(unknown.get("delta") or 0)
    if delta > 0:
        changes.append(_change(
            "UNKNOWN_GAINED", severity="WARNING", subject="unknown inventory",
            before=unknown.get("before"), after=unknown.get("after"),
            detail=f"{delta} more asset(s) carry no cryptographic evidence than before",
            means="open work grew: these assets are uncharacterised, not crypto-free",
        ))
    elif delta < 0:
        changes.append(_change(
            "UNKNOWN_REDUCED", severity="INFO", subject="unknown inventory",
            before=unknown.get("before"), after=unknown.get("after"),
            detail=f"{-delta} fewer asset(s) carry no cryptographic evidence",
            means="open work shrank, usually because a plane that fed those assets answered",
        ))

    gained_unresolved = int(unknown.get("unresolved_gained") or 0)
    if gained_unresolved:
        changes.append(_change(
            "UNRESOLVED_GAINED" if gained_unresolved > 0 else "UNRESOLVED_REDUCED",
            severity="WARNING" if gained_unresolved > 0 else "INFO",
            subject="unresolved relationships",
            after=gained_unresolved,
            detail=(
                f"{abs(gained_unresolved)} relationship candidate(s) "
                f"{'gained' if gained_unresolved > 0 else 'resolved'} since the last observation"
            ),
            means=(
                "an unresolved candidate is an edge nobody has established. It widens the space a "
                "real path could hide in; it is not an edge, and it is never counted as one"
            ),
        ))

    return changes


def describe(
    before: Any | None,
    after: Any,
    *,
    run_id: str | None = None,
    trigger: str = "manual",
) -> dict[str, Any]:
    """What moved between two observed twins, as named claims.

    Pure: two graphs in, one object out. ``before=None`` is ``BASELINE``, never
    "no change", because a first observation has nothing to differ from.
    """
    if before is None:
        return {
            "schema": SCHEMA,
            "verdict": "BASELINE",
            "severity": "BASELINE",
            "changed": None,
            "headline": "first observation: it becomes the baseline",
            "reason": "nothing has been compared yet, so no change can be reported or ruled out",
            "changes": [],
            "counts": {},
            "run_id": run_id,
            "trigger": trigger,
            "baseline_projection_id": None,
            "current_projection_id": after.fingerprint(),
            "next_action": NEXT_ACTION["BASELINE"],
            "severity_meaning": SEVERITY_MEANING["BASELINE"],
            "meaning": (
                "BASELINE is not 'no change'. The next observation is compared against this one, and "
                "until that happens this estate has no change history"
            ),
            "storable": True,
        }

    comparison = estate_twin.compare(before, after)
    verdict = str(comparison.get("verdict") or "ESTATE_CHANGED")
    changes = _from_compare(comparison)
    counts: dict[str, int] = {}
    for change in changes:
        counts[change["kind"]] = counts.get(change["kind"], 0) + 1

    if verdict == "NO_CHANGE":
        severity = "NONE"
    elif verdict == "COVERAGE_DEGRADED" or any(c["severity"] == "CRITICAL" for c in changes):
        severity = "CRITICAL"
    elif changes:
        severity = "WARNING" if any(c["severity"] == "WARNING" for c in changes) else "INFO"
    else:
        severity = "INFO"

    if severity == "NONE":
        headline = "no change: the two observations are identical"
    elif verdict == "COVERAGE_DEGRADED":
        headline = "coverage lost: " + ", ".join(
            sorted({c["subject"] for c in changes if c["kind"] == "COVERAGE_DEGRADED"})
        ) if any(c["kind"] == "COVERAGE_DEGRADED" for c in changes) else "coverage degraded"
    elif changes:
        summary = ", ".join(f"{count}× {kind.lower().replace('_', ' ')}" for kind, count in sorted(counts.items()))
        headline = f"{len(changes)} change(s): {summary}"
    else:
        headline = "the projection ids differ but no compared surface did"

    action_key = (
        "COVERAGE_DEGRADED" if any(c["kind"] == "COVERAGE_DEGRADED" for c in changes)
        else "EVIDENCE_LOST" if any(c["kind"] == "EVIDENCE_LOST" for c in changes)
        else "CRYPTO_CHANGED" if any(c["kind"].startswith("CRYPTO_") for c in changes)
        else "ESTATE_CHANGED" if any(
            c["kind"].startswith(("ASSET_", "RELATIONSHIP_", "UNKNOWN_", "UNRESOLVED_")) for c in changes
        )
        else "UNEXPLAINED" if severity == "INFO" and verdict != "NO_CHANGE"
        else None
    )

    return {
        "schema": SCHEMA,
        "verdict": verdict,
        "severity": severity,
        "changed": verdict != "NO_CHANGE",
        "headline": headline,
        "reason": comparison.get("reason"),
        "changes": changes,
        "counts": counts,
        "run_id": run_id,
        "trigger": trigger,
        "baseline_projection_id": comparison.get("before", {}).get("projection_id"),
        "current_projection_id": comparison.get("after", {}).get("projection_id"),
        "before": comparison.get("before"),
        "after": comparison.get("after"),
        "next_action": NEXT_ACTION.get(action_key) if action_key else None,
        "severity_meaning": SEVERITY_MEANING[severity],
        "meaning": (
            "this is what moved between two observations of the same estate. A quiet feed is not a "
            "safe estate — it means nothing moved between the observations that ran"
        ),
        "comparison": comparison,
        #: identical evidence is a fact about the pair of observations, not an event.
        #: Storing it would bury real changes under a row per quiet scan.
        "storable": severity not in {"NONE"},
    }


def event_id_for(before_id: str | None, after_id: str, verdict: str) -> str:
    """Deterministic id: one event per (baseline, current, verdict) transition.

    A restart, a retried detection or a replayed run must not create a second
    "the estate changed" that an operator has to read twice.
    """
    body = f"{before_id or 'baseline'}|{after_id}|{verdict}"
    return "chg_" + hashlib.sha256(body.encode("utf-8")).hexdigest()[:32]


def record(
    db: Any,
    detection: Mapping[str, Any],
    *,
    tenant_id: str | None,
    detected_by: str | None = None,
) -> tuple[EstateChangeEvent | None, bool]:
    """Append one detection. Returns ``(row, created)``; ``(None, False)`` if not storable.

    Not storable is a real outcome, not an error: ``NONE`` (identical evidence) is
    not a change event, and the caller is expected to say so rather than write a
    row saying nothing happened.
    """
    if not detection.get("storable"):
        return None, False

    verdict = str(detection.get("verdict") or "")
    after_id = str(detection.get("current_projection_id") or "")
    before_id = detection.get("baseline_projection_id")
    event_id = event_id_for(before_id, after_id, verdict)
    now = datetime.now(timezone.utc)

    stmt = select(EstateChangeEvent).where(EstateChangeEvent.event_id == event_id)
    stmt = stmt.where(
        EstateChangeEvent.tenant_id == tenant_id
        if tenant_id
        else EstateChangeEvent.tenant_id.is_(None)
    )
    row = db.execute(stmt).scalars().first()
    if row is not None:
        row.observations = int(row.observations or 0) + 1
        row.last_detected_at = now
        db.commit()
        return row, False

    row = EstateChangeEvent(
        tenant_id=tenant_id,
        event_id=event_id,
        verdict=verdict,
        severity=str(detection.get("severity") or ""),
        changed=detection.get("changed"),
        headline=str(detection.get("headline") or ""),
        reason=detection.get("reason"),
        next_action=detection.get("next_action"),
        changes=list(detection.get("changes") or []),
        counts=dict(detection.get("counts") or {}),
        baseline_projection_id=before_id,
        current_projection_id=after_id,
        run_id=detection.get("run_id"),
        trigger=str(detection.get("trigger") or "manual"),
        detected_by=detected_by,
        observations=1,
        first_detected_at=now,
        last_detected_at=now,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row, True


def observe(
    db: Any,
    before: Any | None,
    after: Any,
    *,
    tenant_id: str | None,
    run_id: str | None = None,
    trigger: str = "manual",
    detected_by: str | None = None,
    previous_error: str | None = None,
) -> dict[str, Any]:
    """Describe an observation and append it to the feed if anything moved.

    One call site for both the collector path and the ingest path, so the two ways an
    observation enters the product cannot drift into different answers. Never raises
    for a feed problem: a broken feed must not cost a scan, and the caller gets the
    description with an ``error`` instead.
    """
    detection = describe(before, after, run_id=run_id, trigger=trigger)
    if previous_error:
        # the baseline existed but could not be rebuilt: say so, because "no change"
        # against a baseline we failed to read is not a comparison
        detection["baseline_error"] = previous_error
        detection["verdict_note"] = (
            "the previous observation could not be rebuilt, so this was compared against nothing. "
            "Treat the baseline as unknown rather than as identical"
        )
        detection["storable"] = False
        detection["recorded"] = {
            "created": False,
            "event_id": None,
            "note": "not stored: the baseline was unreadable, so this is not a comparison",
        }
        return detection

    if not hasattr(db, "execute"):
        detection["recorded"] = {
            "created": False,
            "event_id": None,
            "note": "no database session was supplied, so the detection was described but not stored",
        }
        return detection

    if not detection.get("storable"):
        detection["recorded"] = {
            "created": False,
            "event_id": None,
            "note": (
                "nothing moved between the two observations, so no change event was written — "
                "this run is the record that the estate was looked at"
            ),
        }
        return detection

    try:
        row, created = record(db, detection, tenant_id=tenant_id, detected_by=detected_by or trigger)
    except Exception as exc:  # noqa: BLE001 — a feed failure cannot fail the observation
        detection["recorded"] = {
            "created": False,
            "event_id": None,
            "error": f"{type(exc).__name__}: {exc}",
            "note": "detection was computed but could not be stored; the feed is missing this event",
        }
        rollback = getattr(db, "rollback", None)
        if callable(rollback):
            try:
                rollback()
            except Exception:  # noqa: BLE001
                pass
        return detection

    detection["recorded"] = {
        "created": bool(created),
        "event_id": getattr(row, "event_id", None),
        "note": (
            "new change event"
            if created
            else "this transition was already recorded; the observation counter advanced"
        ),
    }
    return detection


def list_events(
    db: Any,
    *,
    tenant_id: str | None,
    severity: str | None = None,
    kind: str | None = None,
    include_acknowledged: bool = True,
    limit: int = 50,
) -> list[EstateChangeEvent]:
    stmt = select(EstateChangeEvent).order_by(
        EstateChangeEvent.first_detected_at.desc(), EstateChangeEvent.id.desc()
    ).limit(max(1, min(limit, 200)))
    stmt = stmt.where(
        EstateChangeEvent.tenant_id == tenant_id
        if tenant_id
        else EstateChangeEvent.tenant_id.is_(None)
    )
    if severity:
        stmt = stmt.where(EstateChangeEvent.severity == str(severity).upper())
    if not include_acknowledged:
        stmt = stmt.where(EstateChangeEvent.acknowledged_at.is_(None))
    rows = list(db.execute(stmt).scalars())
    if kind:
        wanted = str(kind).upper()
        rows = [
            row for row in rows
            if any(str(change.get("kind") or "").upper() == wanted for change in (row.changes or []))
        ]
    return rows


def get_event(db: Any, identifier: str, *, tenant_id: str | None) -> EstateChangeEvent | None:
    identifier = str(identifier or "").strip()
    if not identifier:
        return None
    stmt = select(EstateChangeEvent).where(
        (EstateChangeEvent.event_id == identifier) | (EstateChangeEvent.id == identifier)
    )
    stmt = stmt.where(
        EstateChangeEvent.tenant_id == tenant_id
        if tenant_id
        else EstateChangeEvent.tenant_id.is_(None)
    )
    return db.execute(stmt).scalars().first()


def acknowledge(
    db: Any,
    identifier: str,
    *,
    tenant_id: str | None,
    user: str | None,
    note: str | None = None,
) -> EstateChangeEvent | None:
    """Mark a change as seen. Only the acknowledgement moves; the findings do not.

    Editing what was detected would make the feed a place where history can be
    rewritten, which is the one thing an audit trail cannot be.
    """
    row = get_event(db, identifier, tenant_id=tenant_id)
    if row is None:
        return None
    if row.acknowledged_at is None:
        row.acknowledged_at = datetime.now(timezone.utc)
        row.acknowledged_by = user
        row.acknowledgement_note = note
        db.commit()
        db.refresh(row)
    return row


def public_event(row: EstateChangeEvent) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "event_id": row.event_id,
        "verdict": row.verdict,
        "severity": row.severity,
        "severity_meaning": SEVERITY_MEANING.get(str(row.severity)),
        "changed": row.changed,
        "headline": row.headline,
        "reason": row.reason,
        "next_action": row.next_action,
        "changes": row.changes or [],
        "counts": row.counts or {},
        "baseline_projection_id": row.baseline_projection_id,
        "current_projection_id": row.current_projection_id,
        "run_id": row.run_id,
        "trigger": row.trigger,
        "detected_by": row.detected_by,
        "observations": row.observations,
        "first_detected_at": _iso(row.first_detected_at),
        "last_detected_at": _iso(row.last_detected_at),
        "acknowledged_at": _iso(row.acknowledged_at),
        "acknowledged_by": row.acknowledged_by,
        "acknowledgement_note": row.acknowledgement_note,
        "acknowledged": row.acknowledged_at is not None,
        "source": "observation",
        "is_estate_state": True,
        "note": (
            "a change event is a statement about two observations of the estate. It is never a "
            "simulation: what-if runs are stored separately and quarantined"
        ),
    }


def feed(db: Any, *, tenant_id: str | None, **kwargs: Any) -> dict[str, Any]:
    """The feed, with the counts an operator triaging it needs."""
    rows = list_events(db, tenant_id=tenant_id, **kwargs)
    events = [public_event(row) for row in rows]
    unacknowledged = [event for event in events if not event["acknowledged"]]
    by_severity: dict[str, int] = {}
    by_kind: dict[str, int] = {}
    for event in events:
        by_severity[event["severity"]] = by_severity.get(event["severity"], 0) + 1
        for kind, count in (event["counts"] or {}).items():
            by_kind[kind] = by_kind.get(kind, 0) + int(count)
    filters = {
        "severity": kwargs.get("severity"),
        "kind": kwargs.get("kind"),
        "include_acknowledged": bool(kwargs.get("include_acknowledged", True)),
    }
    return {
        "schema": FEED_SCHEMA,
        "count": len(events),
        "filtered": any(value is not None and value is not True for value in filters.values()),
        "filters": filters,
        "unacknowledged": len(unacknowledged),
        "by_severity": by_severity,
        "by_kind": by_kind,
        "events": events,
        "meaning": (
            "the feed records movement between observations. An empty feed means nothing moved while "
            "the collectors were running — not that the estate is safe, and not that anything was "
            "looked at recently"
        ),
        "limits": [
            "detection compares observations; it never re-collects to confirm a change",
            "a quiet feed cannot distinguish a stable estate from a scheduler that stopped running — "
            "check the run history and coverage for that",
            "only discovery observations produce events; simulations are quarantined separately",
        ],
    }


__all__ = [
    "FEED_SCHEMA",
    "observe",
    "SCHEMA",
    "SEVERITY_ORDER",
    "acknowledge",
    "describe",
    "event_id_for",
    "feed",
    "get_event",
    "list_events",
    "public_event",
    "record",
]
