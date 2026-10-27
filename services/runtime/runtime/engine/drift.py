"""Runtime crypto drift between two observation windows (spec 92 §31).

Drift answers a question a single snapshot cannot: *did the running estate's
crypto change?* A key size that dropped from 3072 to 2048, a process that
started calling DES, an application that stopped using a library — all are
observable by comparing two runs.

One honesty rule dominates: **"removed" means "not observed in the newer
window"**, not "stopped happening". A quiet collection window, a rotated pod or
a scope that no longer covers the host produces exactly the same signal, so
every removal carries that caveat instead of being reported as a fact about the
application.
"""

from __future__ import annotations

from typing import Any, Iterable

MODEL = "cryptoscan.runtime-crypto-drift/1"


def _key(event: dict[str, Any]) -> tuple:
    identity = event.get("identity") or {}
    decomposition = event.get("decomposition") or {}
    return (
        str(event.get("algorithm") or "UNKNOWN"),
        str(event.get("key_size")),
        str(decomposition.get("mode")),
        str(identity.get("application")),
        str(identity.get("process")),
    )


def _label(key: tuple) -> dict[str, Any]:
    algorithm, key_size, mode, application, process = key
    return {
        "algorithm": None if algorithm == "UNKNOWN" else algorithm,
        "key_size": None if key_size == "UNKNOWN" else key_size,
        "mode": None if mode == "None" else mode,
        "application": None if application == "None" else application,
        "process": None if process == "None" else process,
    }


def _index(events: Iterable[dict[str, Any]]) -> dict[tuple, dict[str, Any]]:
    index: dict[tuple, dict[str, Any]] = {}
    for event in events:
        key = _key(event)
        bucket = index.setdefault(
            key,
            {
                "observations": 0,
                "levels": {},
                "operations": {},
                "sources": set(),
                "event_ids": [],
            },
        )
        bucket["observations"] += int(event.get("observation_count") or 1)
        level = str(event.get("attribution_level"))
        bucket["levels"][level] = bucket["levels"].get(level, 0) + 1
        operation = str(event.get("operation"))
        bucket["operations"][operation] = bucket["operations"].get(operation, 0) + 1
        bucket["sources"].add(str(event.get("source")))
        bucket["event_ids"].append(event.get("event_id"))
    return index


def compare_runs(
    previous: Iterable[dict[str, Any]],
    current: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Compare two runtime windows: what appeared, what vanished, what changed."""
    previous_events = list(previous)
    current_events = list(current)
    before = _index(previous_events)
    after = _index(current_events)

    new_keys = sorted(set(after) - set(before))
    gone_keys = sorted(set(before) - set(after))
    common = sorted(set(before) & set(after))

    new = [
        {**_label(key), "observations": after[key]["observations"], "operations": after[key]["operations"]}
        for key in new_keys
    ]
    removed = [
        {
            **_label(key),
            "observations": before[key]["observations"],
            "note": "not observed in the newer window — that is not proof the operation stopped",
        }
        for key in gone_keys
    ]
    changed: list[dict[str, Any]] = []
    for key in common:
        old, new_bucket = before[key], after[key]
        level_moved = set(old["levels"]) != set(new_bucket["levels"])
        operations_moved = set(old["operations"]) != set(new_bucket["operations"])
        volume_ratio = (
            round(new_bucket["observations"] / old["observations"], 2) if old["observations"] else None
        )
        if level_moved or operations_moved:
            changed.append(
                {
                    **_label(key),
                    "attribution_levels": {"before": old["levels"], "after": new_bucket["levels"]},
                    "operations": {"before": old["operations"], "after": new_bucket["operations"]},
                    "observations": {"before": old["observations"], "after": new_bucket["observations"]},
                    "volume_ratio": volume_ratio,
                    "note": (
                        "observation depth or operation mix changed; a level drop means weaker evidence, "
                        "not a crypto change"
                        if level_moved
                        else "operation mix changed"
                    ),
                }
            )

    return {
        "model": MODEL,
        "previous_events": len(previous_events),
        "current_events": len(current_events),
        "new": new,
        "removed": removed,
        "changed": changed,
        "unchanged": len(common) - len(changed),
        "summary": {
            "new": len(new),
            "removed": len(removed),
            "changed": len(changed),
            "unchanged": len(common) - len(changed),
            "previous_events": len(previous_events),
            "current_events": len(current_events),
        },
        "verdict": (
            "NO_EVIDENCE"
            if not previous_events and not current_events
            else "BASELINE_ESTABLISHED"
            if not previous_events
            else "NO_CHANGE"
            if not (new or removed or changed)
            else "DRIFT"
        ),
        "limitations": [
            "a removal means 'not observed in this window', not 'the operation stopped'",
            "a quieter window or a narrower scope produces removals without any real change",
            "drift compares observations, not intent: an application can still hold crypto it never exercised",
        ],
    }
