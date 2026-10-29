"""Correlating stored change events into attack *patterns* — and stopping short of a verdict.

A single change is a fact. The reason a live estate can say something stronger than
"this file appeared" is that it holds the surrounding graph: which process the library
belongs to, which endpoints terminate TLS, which HSM the payment path depends on. This
module is the part that reads several changes inside one window and asks whether they
describe one event rather than several.

What it refuses to do:

* **it never calls anything a compromise.** The strongest thing produced here is a
  ``CORRELATED_PATTERN``: several independent patterns coinciding in one window. It lists
  what would have to be checked by a human, and it says what a change feed cannot see;
* **it never assigns ``SECURITY_INCIDENT``.** That level exists in the vocabulary because a
  responder needs it, but the platform has no engagement, no authorisation and no external
  intelligence match here — a rule that promoted correlation to incident would be inventing
  the one claim this product must not invent;
* **a collection gap outranks the activity inside it.** Changes seen while a plane was
  blind are reported as *unattributable*, not as suspicious change on their own;
* **it does not read the clock to fill a window.** When ``now`` is not supplied the newest
  event anchors the window, so the same stored events always correlate the same way.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

SCHEMA = "cryptoscan.attack-patterns/1"

#: the evidence ladder. Higher is not "more certain" — it is "more correlated".
LEVELS: dict[int, dict[str, str]] = {
    0: {
        "name": "NORMAL_CHANGE",
        "meaning": "a change with no corroborating signal; most changes are this",
    },
    1: {
        "name": "UNEXPECTED_CHANGE",
        "meaning": "a change worth a look: it weakened evidence, appeared unexpectedly, or lost coverage",
    },
    2: {
        "name": "SUSPICIOUS_ACTIVITY",
        "meaning": "several related changes in one window that a single change cannot explain",
    },
    3: {
        "name": "SECURITY_INCIDENT",
        "meaning": (
            "reserved for a human or an external intelligence match; this engine never sets it, "
            "because a correlated change feed is not an incident declaration"
        ),
    },
    4: {
        "name": "CORRELATED_PATTERN",
        "meaning": (
            "two or more independent patterns coincide in one window — priority for review, "
            "still not proof of compromise"
        ),
    },
}

#: change kinds that mean "this plane stopped seeing as much as it did"
COVERAGE_KINDS = ("COVERAGE_DEGRADED", "EVIDENCE_LOST")

#: change kinds that mean the estate moved
ACTIVITY_KINDS = (
    "ASSET_ADDED",
    "ASSET_REMOVED",
    "ASSET_CHANGED",
    "CRYPTO_ADDED",
    "CRYPTO_CHANGED",
    "CRYPTO_REMOVED",
    "CRYPTO_DEMOTED",
    "CRYPTO_PROMOTED",
    "RELATIONSHIP_ESTABLISHED",
    "RELATIONSHIP_LOST",
)

#: asset types whose appearance means executable/loadable code arrived
CODE_TYPES = {"PACKAGE", "LIBRARY", "IMAGE", "CONTAINER", "POD", "BINARY", "EXECUTABLE"}

DEFAULT_WINDOW_SECONDS = 3600

#: a burst is several *different* kinds inside this many seconds
BURST_WINDOW_SECONDS = 300

NOT_PROVEN_BASE = [
    "a pattern is not proof of compromise: every claim here rests on changes the platform "
    "observed, and an attacker who changed nothing observable leaves no pattern",
    "level 3 (SECURITY_INCIDENT) is never assigned by this engine; that decision belongs to "
    "a responder with the estate in front of them",
    "correlation quality is bounded by collector coverage in the same window — a blind plane "
    "hides activity, and this module reports that gap instead of scoring around it",
]

LIMITS = [
    "only changes that were stored can be correlated: an estate nobody observes produces an "
    "empty result, not a clean one",
    "the window is fixed per call and stated in the response; widening it finds more patterns "
    "and more coincidence",
    "asset type is taken from the change record; an untyped change is correlated by kind only",
    "no external threat intelligence, no attacker identity and no attribution are involved",
    "corroboration counts the collectors whose stored evidence stands behind a pattern; it is "
    "reported beside the level and never folded into it, and a pattern whose evidence was not "
    "stored shows no collector rather than a plausible one",
]


def _parse(moment: Any) -> datetime | None:
    if moment is None:
        return None
    if isinstance(moment, datetime):
        return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(moment).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _iso(moment: datetime | None) -> str | None:
    return moment.astimezone(timezone.utc).isoformat() if moment else None


def _signals(events: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Flatten events into one signal per named change, carrying its event and time."""
    out: list[dict[str, Any]] = []
    for event in events:
        at = _parse(event.get("last_detected_at") or event.get("first_detected_at"))
        for change in event.get("changes") or []:
            kind = str(change.get("kind") or "").upper()
            if not kind:
                continue
            out.append(
                {
                    "event_id": event.get("event_id") or event.get("id"),
                    "run_id": event.get("run_id"),
                    "kind": kind,
                    "severity": str(change.get("severity") or event.get("severity") or ""),
                    "subject": str(change.get("subject") or ""),
                    "detail": change.get("detail"),
                    "before": change.get("before"),
                    "after": change.get("after"),
                    "evidence_ids": list(change.get("evidence_ids") or []),
                    "at": at,
                }
            )
    return out


def _asset_type(signal: Mapping[str, Any]) -> str:
    for key in ("after", "before"):
        value = signal.get(key)
        if isinstance(value, Mapping):
            found = str(value.get("type") or "").upper()
            if found:
                return found
        elif isinstance(value, str) and value and value.upper() == value:
            return value.upper()
    return ""


def _pattern(
    name: str,
    level: int,
    signals: list[Mapping[str, Any]],
    *,
    why: str,
    next_action: str,
    extra_not_proven: Iterable[str] = (),
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    event_ids = sorted({str(signal.get("event_id")) for signal in signals if signal.get("event_id")})
    kinds = sorted({str(signal["kind"]) for signal in signals})
    seed = hashlib.sha256(
        "|".join([name, *event_ids, *kinds, *sorted({str(s.get("subject") or "") for s in signals})]).encode()
    ).hexdigest()[:16]
    moments = [signal["at"] for signal in signals if signal.get("at")]
    return {
        "pattern_id": f"PAT-{seed}",
        "name": name,
        "level": level,
        "level_name": LEVELS[level]["name"],
        "level_meaning": LEVELS[level]["meaning"],
        "headline": _headline(name, signals),
        "why": why,
        "subjects": sorted({str(signal.get("subject") or "") for signal in signals if signal.get("subject")}),
        "change_kinds": kinds,
        "signals": [
            {
                "event_id": signal.get("event_id"),
                "run_id": signal.get("run_id"),
                "kind": signal["kind"],
                "severity": signal.get("severity"),
                "subject": signal.get("subject"),
                "detail": signal.get("detail"),
                "at": _iso(signal.get("at")),
                "evidence_ids": signal.get("evidence_ids") or [],
            }
            for signal in signals
        ],
        "event_ids": event_ids,
        "first_seen": _iso(min(moments)) if moments else None,
        "last_seen": _iso(max(moments)) if moments else None,
        "not_proven": [*NOT_PROVEN_BASE, *extra_not_proven],
        "next_action": next_action,
        **(dict(extra or {})),
    }


def _headline(name: str, signals: list[Mapping[str, Any]]) -> str:
    subjects = sorted({str(s.get("subject") or "") for s in signals if s.get("subject")})
    shown = ", ".join(subjects[:3]) + ("…" if len(subjects) > 3 else "")
    readable = name.replace("_", " ").lower()
    return f"{readable}: {shown}" if shown else readable


def _collectors_for(
    signal: Mapping[str, Any],
    by_evidence: Mapping[str, str],
    by_subject: Mapping[str, Iterable[str]],
) -> tuple[list[str], list[str]]:
    """Which collectors stand behind one signal, and which evidence ids cannot be traced.

    Evidence ids are the authoritative route: the store knows which collector recorded
    each fact. A subject fallback exists because a change can be attributed to an asset
    whose evidence was recorded under a different id; it is used only when the signal
    cites no evidence at all, and it is never used to invent an id.
    """
    evidence_ids = [str(item) for item in (signal.get("evidence_ids") or []) if item]
    missing = [item for item in evidence_ids if item not in by_evidence]
    found = [by_evidence[item] for item in evidence_ids if item in by_evidence]
    if not evidence_ids:
        subject = str(signal.get("subject") or "").strip()
        found = [str(item) for item in (by_subject.get(subject) or []) if item]
    return found, missing


def _corroboration(
    signals: list[Mapping[str, Any]],
    by_evidence: Mapping[str, str],
    by_subject: Mapping[str, Iterable[str]],
) -> dict[str, Any]:
    """The provenance block: how much of this pattern a second plane can confirm."""
    collectors: list[str] = []
    unmapped: list[str] = []
    with_provenance = 0
    for signal in signals:
        found, missing = _collectors_for(signal, by_evidence, by_subject)
        for collector in found:
            if collector not in collectors:
                collectors.append(collector)
        for item in missing:
            if item not in unmapped:
                unmapped.append(item)
        if found:
            with_provenance += 1
    collectors.sort()
    unmapped.sort()
    total = len(signals)
    independent = len(collectors)
    single = independent < 2
    if not total:
        note = "this pattern cites no signal, so no collector corroborates it"
    elif not independent:
        note = (
            "no collector corroborates this pattern: none of its evidence traced back to a stored "
            "record, which is not the same as a single source"
        )
    elif single:
        note = (
            f"single source: {collectors[0]} is the only collector behind this pattern, so it "
            "rests on one plane's view"
        )
    else:
        note = f"{independent} independent collectors corroborate this pattern: {', '.join(collectors)}"
    return {
        "collectors": collectors,
        "independent_sources": independent,
        "single_source": single,
        "signals_total": total,
        "signals_with_provenance": with_provenance,
        "unmapped_evidence_ids": unmapped,
        "note": note,
        "does_not_change_level": (
            "corroboration is reported beside the level, not folded into it: two collectors "
            "seeing the same change is a stronger claim about the estate and says nothing about "
            "intent"
        ),
    }


def correlate(
    events: Iterable[Mapping[str, Any]],
    *,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    now: datetime | None = None,
    collectors_by_evidence: Mapping[str, str] | None = None,
    collectors_by_subject: Mapping[str, Iterable[str]] | None = None,
) -> dict[str, Any]:
    """Group the changes inside one window into patterns, with their level and their gaps.

    ``collectors_by_evidence`` maps a stored evidence id to the collector that recorded it,
    and ``collectors_by_subject`` maps a subject to the collectors that observed it. When
    neither is supplied every pattern reports zero collectors — an honest "not traced"
    rather than a guessed one.
    """
    window = max(1, int(window_seconds or DEFAULT_WINDOW_SECONDS))
    materialised = [event for event in events if isinstance(event, Mapping)]
    signals = _signals(materialised)
    moments = [signal["at"] for signal in signals if signal.get("at")]
    anchor = now or (max(moments) if moments else datetime.now(timezone.utc))
    if anchor.tzinfo is None:
        anchor = anchor.replace(tzinfo=timezone.utc)
    start = anchor.timestamp() - window
    in_window = [
        signal for signal in signals if signal["at"] is not None and start <= signal["at"].timestamp() <= anchor.timestamp()
    ]
    undated = [signal for signal in signals if signal["at"] is None]

    patterns: list[dict[str, Any]] = []
    patterns.extend(_collection_patterns(in_window))
    patterns.extend(_crypto_patterns(in_window))
    patterns.extend(_code_patterns(in_window))
    patterns.extend(_burst_pattern(in_window))
    patterns.extend(_correlated(patterns, in_window))

    by_evidence = {str(key): str(value) for key, value in (collectors_by_evidence or {}).items() if value}
    by_subject = {str(key): list(value) for key, value in (collectors_by_subject or {}).items()}

    for pattern in patterns:
        # corroboration is computed from the signals this pattern cites, so it answers
        # "who saw this", not "who saw anything in the window"
        pattern["corroboration"] = _corroboration(pattern["signals"], by_evidence, by_subject)

    patterns.sort(key=lambda item: (-item["level"], item["name"], item["pattern_id"]))
    by_level: dict[str, int] = {}
    for pattern in patterns:
        key = str(pattern["level"])
        by_level[key] = by_level.get(key, 0) + 1

    return {
        "schema": SCHEMA,
        "window_seconds": window,
        "window": {"from": _iso(datetime.fromtimestamp(start, timezone.utc)), "to": _iso(anchor)},
        "events_considered": len(materialised),
        "signals_considered": len(in_window),
        "undated_signals": len(undated),
        "patterns": patterns,
        "count": len(patterns),
        "by_level": by_level,
        "highest_level": max((p["level"] for p in patterns), default=0),
        "level_definitions": {str(level): definition for level, definition in LEVELS.items()},
        "corroboration": {
            "evidence_mapped": len(by_evidence),
            "subjects_mapped": len(by_subject),
            "single_source_patterns": len([p for p in patterns if p["corroboration"]["single_source"]]),
            "note": (
                "corroboration counts independent collectors whose stored evidence stands behind "
                "a pattern; it is reported, never used to raise a level"
            ),
        },
        "note": (
            "an empty result means nothing in this window met a correlation rule — not that the "
            "estate is safe; a blind plane is reported as COLLECTION_LOSS, never as quiet"
        ),
        "limits": LIMITS,
    }


def _collection_patterns(signals: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    coverage = [signal for signal in signals if signal["kind"] in COVERAGE_KINDS]
    if not coverage:
        return []
    activity = [signal for signal in signals if signal["kind"] in ACTIVITY_KINDS]
    if activity:
        return [
            _pattern(
                "COLLECTION_BLIND_SPOT",
                2,
                coverage + activity,
                why=(
                    "the estate changed during a window in which a plane reported less than before; "
                    "the change cannot be attributed between the estate and the collector that "
                    "stopped reading it"
                ),
                next_action=(
                    "restore the reporting plane first, then re-observe before treating any change "
                    "in this window as settled"
                ),
                extra_not_proven=[
                    "a change inside a blind window may be a change the collector could no longer "
                    "see, rather than a change that happened",
                ],
                extra={"attributable": False, "coverage_signals": [s["kind"] for s in coverage]},
            )
        ]
    return [
        _pattern(
            "COLLECTION_LOSS",
            1,
            coverage,
            why=(
                "a plane stopped reporting. This is a measurement failure, not an attack — and it "
                "is also the state in which an attack is easiest to hide"
            ),
            next_action="restore the collector for that plane and confirm its coverage block recovered",
            extra={"attributable": False, "coverage_signals": [s["kind"] for s in coverage]},
        )
    ]


def _crypto_patterns(signals: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    demoted = [signal for signal in signals if signal["kind"] == "CRYPTO_DEMOTED"]
    removed = [signal for signal in signals if signal["kind"] == "CRYPTO_REMOVED"]
    crypto = [signal for signal in signals if signal["kind"].startswith("CRYPTO_")]
    edges = [signal for signal in signals if signal["kind"] in ("RELATIONSHIP_ESTABLISHED", "RELATIONSHIP_LOST")]

    demoted_subjects = {str(signal.get("subject")) for signal in demoted}
    if len(demoted_subjects) >= 2 or (demoted and removed):
        out.append(
            _pattern(
                "CRYPTOGRAPHIC_REGRESSION",
                2,
                demoted + removed,
                why=(
                    "evidence for cryptography weakened in more than one place inside one window. "
                    "A collector that lost access looks like this — and so does deliberate removal "
                    "of the proof"
                ),
                next_action=(
                    "compare the affected assets' evidence types: a drop to a weaker type across "
                    "unrelated collectors is a collection problem, within one collector it is not"
                ),
                extra_not_proven=[
                    "the cryptography may still be deployed; what moved is what can be evidenced",
                ],
            )
        )
    elif demoted:
        out.append(
            _pattern(
                "EVIDENCE_WEAKENED",
                1,
                demoted,
                why="evidence for a cryptographic artefact became weaker than the previous observation",
                next_action="re-read the asset with the collector that produced the stronger evidence",
            )
        )

    if crypto and edges:
        out.append(
            _pattern(
                "TRUST_PATH_MUTATION",
                2,
                crypto + edges,
                why=(
                    "a cryptographic artefact and the graph edge that made it reachable moved in the "
                    "same window — the two facts that together describe a trust path"
                ),
                next_action=(
                    "walk the affected asset's relationships in the twin and confirm the new path was "
                    "intended by a change record"
                ),
                extra_not_proven=[
                    "a new edge can be a new observation of a pre-existing relationship, not a new "
                    "connection",
                ],
            )
        )
    return out


def _code_patterns(signals: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    added_code = [
        signal
        for signal in signals
        if signal["kind"] == "ASSET_ADDED" and _asset_type(signal) in CODE_TYPES
    ]
    crypto_added = [signal for signal in signals if signal["kind"] == "CRYPTO_ADDED"]
    if added_code and crypto_added:
        out.append(
            _pattern(
                "NEW_CRYPTO_SURFACE",
                2,
                added_code + crypto_added,
                why=(
                    "loadable code appeared and new cryptographic artefacts were first evidenced in "
                    "the same window; a deployment and an implant look the same from here"
                ),
                next_action=(
                    "match the additions to a recorded deployment: no change ticket means "
                    "investigate the host and the process that loaded it"
                ),
                extra_not_proven=[
                    "the platform has not seen the binary execute; presence and crypto artefacts are "
                    "not execution",
                ],
            )
        )
    elif added_code:
        out.append(
            _pattern(
                "NEW_CODE_PRESENT",
                1,
                added_code,
                why="loadable code was first observed on assets that did not carry it before",
                next_action="confirm the addition against a deployment record",
            )
        )
    return out


def _burst_pattern(signals: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Several *different* kinds of change inside a few minutes."""
    dated = [signal for signal in signals if signal.get("at")]
    if len(dated) < 3:
        return []
    ordered = sorted(dated, key=lambda signal: signal["at"])
    best: list[Mapping[str, Any]] = []
    for index, signal in enumerate(ordered):
        span = [
            later
            for later in ordered[index:]
            if (later["at"] - signal["at"]).total_seconds() <= BURST_WINDOW_SECONDS
        ]
        if len({item["kind"] for item in span}) >= 3 and len(span) > len(best):
            best = span
    if not best:
        return []
    return [
        _pattern(
            "RAPID_CHANGE_BURST",
            2,
            best,
            why=(
                f"{len({item['kind'] for item in best})} different kinds of change inside "
                f"{BURST_WINDOW_SECONDS}s — routine maintenance is usually one kind of change at a "
                "time, batched windows are not"
            ),
            next_action="check the change calendar for this window before investigating individual assets",
            extra={"span_seconds": int((max(s['at'] for s in best) - min(s['at'] for s in best)).total_seconds())},
        )
    ]


def _correlated(patterns: list[dict[str, Any]], signals: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Two or more independent level-2 patterns in one window become one correlated pattern."""
    serious = [pattern for pattern in patterns if pattern["level"] >= 2]
    if len(serious) < 2:
        return []
    signals_by_event = {signal.get("event_id"): signal for signal in signals}
    participants = [signal for pattern in serious for signal in pattern["signals"]]
    reconstructed: list[Mapping[str, Any]] = []
    for participant in participants:
        reconstructed.append(
            {
                "event_id": participant.get("event_id"),
                "run_id": participant.get("run_id"),
                "kind": participant.get("kind"),
                "severity": participant.get("severity"),
                "subject": participant.get("subject"),
                "detail": participant.get("detail"),
                "evidence_ids": participant.get("evidence_ids"),
                "at": _parse(participant.get("at")) or signals_by_event.get(participant.get("event_id"), {}).get("at"),
            }
        )
    return [
        _pattern(
            "CORRELATED_ACTIVITY",
            4,
            reconstructed,
            why=(
                "independent patterns coincide in one window: "
                + "; ".join(f"{pattern['name']} ({pattern['level_name'].lower()})" for pattern in serious)
            ),
            next_action=(
                "open an investigation with the affected subjects and the evidence ids below; "
                "confirm or dismiss each pattern separately — do not treat the combination as one finding"
            ),
            extra_not_proven=[
                "a combination of patterns raises review priority; it does not establish that a "
                "single actor, a motive or a compromise exists",
            ],
            extra={"pattern_ids": [pattern["pattern_id"] for pattern in serious],
                   "pattern_names": [pattern["name"] for pattern in serious]},
        )
    ]


def summarise(patterns: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Counts by level, for a screen that must not invent a score."""
    counts: dict[str, int] = {str(level): 0 for level in LEVELS}
    for pattern in patterns:
        key = str(pattern.get("level"))
        counts[key] = counts.get(key, 0) + 1
    return {
        "schema": SCHEMA,
        "total": sum(counts.values()),
        "by_level": counts,
        "level_names": {str(level): definition["name"] for level, definition in LEVELS.items()},
        "note": "these are counts of patterns, not a risk score: a level is a correlation level, not a probability",
    }
