"""Queue worker tick — the durable event consumer loop, one step at a time.

Processes cp_queued_events: leases the highest-priority due event (subject to
safe-scan), runs the appropriate deterministic handler, then completes or
backoff-fails it. Designed to be called by a background worker loop (Redis
transport in prod; the table is the durable outbox). Each tick is pure given
a repository, so it is unit-testable and idempotent.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from control_plane.orchestrator import scanner_for_event
from control_plane.safety import evaluate_scan


@dataclass
class TickResult:
    processed: int = 0
    leased: list[str] = field(default_factory=list)
    blocked: list[dict] = field(default_factory=list)
    failed: list[dict] = field(default_factory=list)
    empty: bool = False


def process_event(event: dict, *, policy_provider: Callable[[dict], dict | None] | None = None,
                  handler: Callable[[dict], None] | None = None) -> dict:
    """Process a single leased event. Returns an outcome descriptor.

    Scan events are gated through safe-scan policy; a handler performs the
    actual (deterministic) side effect. Exceptions are converted to a
    'failed' outcome so the caller can backoff/dead-letter.
    """
    etype = event.get("event_type", "")
    payload = event.get("payload") or {}
    if str(etype).startswith(("scan", "discovery")):
        policy = policy_provider(payload) if policy_provider else None
        decision = evaluate_scan(policy, asset=payload.get("asset"), port=payload.get("port"),
                                 protocol=payload.get("protocol"), is_ot=bool(payload.get("is_ot")))
        if not decision.permitted:
            return {"event_id": event.get("id"), "outcome": "blocked",
                    "reason": decision.reason, "scanner": None}
        scanner = scanner_for_event(etype, payload)
        try:
            if handler:
                handler(event)
            return {"event_id": event.get("id"), "outcome": "processed",
                    "scanner": scanner, "mode": decision.mode}
        except Exception as exc:  # noqa: BLE001 - convert to retry outcome
            return {"event_id": event.get("id"), "outcome": "error", "error": str(exc)[:300]}
    # non-scan events (siem.*, findings, itsm, etc.) — just invoke handler
    try:
        if handler:
            handler(event)
        return {"event_id": event.get("id"), "outcome": "processed", "scanner": None}
    except Exception as exc:  # noqa: BLE001
        return {"event_id": event.get("id"), "outcome": "error", "error": str(exc)[:300]}


def worker_tick(repo, *, worker_id: str = "worker-1", batch: int = 10,
                policy_provider=None, handler=None, now: datetime | None = None) -> TickResult:
    """Process up to ``batch`` due events from the durable queue."""
    from db.tenancy import tenant_scope

    now = now or datetime.now(timezone.utc)
    result = TickResult()
    for _ in range(batch):
        # Leasing is a deliberate platform-global operation; once an event is
        # selected, all handler reads/writes and the terminal state transition
        # run inside that event's authorized tenant scope.
        leased = repo.lease_next(worker_id, now=now)
        if leased is None:
            result.empty = True
            break
        with tenant_scope(getattr(leased, "tenant_id", None)):
            outcome = process_event(leased.to_dict(), policy_provider=policy_provider, handler=handler)
            if outcome["outcome"] == "blocked":
                # not retriable via backoff — complete with a record of the block
                repo.complete_event(leased.id)
                result.blocked.append({"event_id": leased.id, "reason": outcome["reason"]})
            elif outcome["outcome"] == "error":
                repo.fail_event(leased.id, outcome.get("error", "processing failed"))
                result.failed.append({"event_id": leased.id, "error": outcome.get("error")})
            else:
                repo.complete_event(leased.id)
                result.processed += 1
                result.leased.append(leased.id)
    return result
