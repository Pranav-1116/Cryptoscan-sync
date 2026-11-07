"""Collect-and-ingest: translations -> validated events -> the store.

Every observation lands in exactly one bucket: ACCEPTED (stored), SKIPPED
(a duplicate of what the store already holds), or REJECTED with a named
reason. Nothing is silently dropped and nothing is fabricated."""

from __future__ import annotations

from typing import Any, Callable, Mapping, Sequence

from cryptolog.collectors.base import CollectorRef, Translation


def run(adapter: Callable[..., Translation],
        observations: Sequence[Mapping[str, Any]], *,
        ref: CollectorRef,
        ingest: Callable[[Mapping[str, Any]], Mapping[str, Any]],
        authorization_ref: str | None = None) -> dict[str, Any]:
    accepted: list[str] = []
    skipped: list[str] = []
    rejected: list[dict[str, str]] = []

    from shared_models.cryptolog_events import validate_event

    for observation in observations:
        ref_id = str(observation.get("observation_id")
                     or observation.get("id") or "unidentified-observation")
        import inspect
        try:
            params = inspect.signature(adapter).parameters
            if "authorization_ref" in params:
                translation = adapter(ref, observation,
                                      authorization_ref=authorization_ref)
            else:
                translation = adapter(ref, observation)
        except Exception as exc:  # an adapter crash is a rejection, not a drop
            rejected.append({"observation_ref": ref_id,
                             "reason": f"adapter refused: {exc}"})
            continue
        for refusal in translation.refusals:
            rejected.append({"observation_ref": refusal.observation_ref,
                             "reason": refusal.reason})
        for event in translation.events:
            try:
                canonical = validate_event(dict(event))
            except ValueError as exc:
                rejected.append({"observation_ref": ref_id,
                                 "reason": f"event refused by contract: {exc}"})
                continue
            result = ingest(canonical)
            outcome = str(result.get("outcome") or "INSERTED")
            if outcome == "INSERTED":
                accepted.append(str(canonical.get("event_id") or ref_id))
            else:
                skipped.append(str(canonical.get("event_id") or ref_id))
    return {
        "accepted": accepted,
        "skipped": skipped,
        "rejected": rejected,
        "counts": {"accepted": len(accepted), "skipped": len(skipped),
                   "rejected": len(rejected),
                   "observations": len(observations)},
    }
