"""Scan orchestration engine — the central brain.

Decides *what to scan, when, how deeply and with which scanner* by combining
safe-scan policy with a durable priority queue:

    Scheduler -> Orchestrator -> priority queue -> workers -> domain scanners

This module is pure/deterministic and operates on plain dicts + a small
repository protocol, so it is unit-testable without a broker. The API layer
persists queued events (cp_queued_events); Redis is the transport in prod;
this orchestrator provides the dispatch/lease/retry/concurrency semantics.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol

from control_plane import queue as q
from control_plane.safety import evaluate_scan, should_auto_stop


class EventRepo(Protocol):
    def list_events(self, status: str | None = None, limit: int = ...) -> list: ...
    def enqueue(self, event_type: str, payload: dict, *, source: str = ...,
                priority: str = ..., max_attempts: int = ...): ...


@dataclass
class OrchestratorConfig:
    worker_id: str = "worker-1"
    max_concurrency: int = 4
    scan_budget_minutes: int = 240
    default_priority: str = "normal"


@dataclass
class DispatchResult:
    leased_id: str | None
    event_type: str | None = None
    permitted: bool = True
    mode: str | None = None
    reason: str = ""
    cancelled: bool = False


#: event types that, when present with engaged=True, halt dispatch
STOP_EVENTS = {"safe_scan.emergency_stop", "scan.emergency_stop"}


def emergency_engaged(events: list[dict]) -> bool:
    for e in events:
        if e.get("event_type") in STOP_EVENTS and (e.get("payload") or {}).get("engaged", False):
            # a later disengage clears it; evaluate in time order
            pass
    # evaluate in created order: latest matching event wins
    latest = None
    for e in sorted(events, key=lambda x: str(x.get("created_at") or "")):
        if e.get("event_type") in STOP_EVENTS:
            latest = e
    return bool(latest and (latest.get("payload") or {}).get("engaged", False))


def _row_to_event(row) -> dict:
    return row.to_dict() if hasattr(row, "to_dict") else dict(row)


@dataclass
class Orchestrator:
    """Pops the next due, highest-priority event that safe-scan permits and
    leases it to a worker. Honors emergency stop, per-scan safe policy,
    concurrency cap and cancellation requests."""

    repo: EventRepo
    config: OrchestratorConfig = field(default_factory=OrchestratorConfig)
    policy_provider: Callable[[dict], dict | None] | None = None
    runtime_provider: Callable[[], dict] | None = None
    active_leases: set[str] = field(default_factory=set)
    cancelled: set[str] = field(default_factory=set)

    def at_concurrency(self) -> bool:
        return len(self.active_leases) >= self.config.max_concurrency

    def cancel(self, event_id: str) -> None:
        self.cancelled.add(event_id)

    def dispatch_next(self, *, now: datetime | None = None) -> DispatchResult:
        now = now or datetime.now(timezone.utc)

        # global emergency stop overrides everything
        try:
            recent = self.repo.list_events(None, limit=500)
            if emergency_engaged([_row_to_event(r) for r in recent]):
                return DispatchResult(None, reason="emergency stop engaged — dispatch halted",
                                       permitted=False, cancelled=True)
        except Exception:  # noqa: BLE001 - never block dispatch on read failure of the stop flag? fail closed
            return DispatchResult(None, reason="could not evaluate safety state — fail closed",
                                   permitted=False)

        if self.at_concurrency():
            return DispatchResult(None, permitted=False,
                                   reason=f"concurrency cap {self.config.max_concurrency} reached")

        queued = [_row_to_event(r) for r in self.repo.list_events("queued", limit=200)]
        event = q.next_available(queued, now=now)
        if event is None:
            return DispatchResult(None, reason="no due events")

        if event.get("id") in self.cancelled:
            return DispatchResult(None, event_type=event.get("event_type"),
                                   cancelled=True, reason="scan cancelled before lease")

        # safe-scan gating for scan events
        if str(event.get("event_type", "")).startswith(("scan", "discovery")):
            payload = event.get("payload") or {}
            policy = self.policy_provider(payload) if self.policy_provider else None
            decision = evaluate_scan(
                policy,
                asset=payload.get("asset"), port=payload.get("port"),
                protocol=payload.get("protocol"), is_ot=bool(payload.get("is_ot")),
                now=now,
            )
            if not decision.permitted:
                return DispatchResult(event.get("id"), event_type=event.get("event_type"),
                                       permitted=False, mode=decision.mode, reason=decision.reason)
            # automatic stop-condition check
            if self.runtime_provider and policy and policy.get("auto_stop_conditions"):
                stop, why = should_auto_stop(policy["auto_stop_conditions"], self.runtime_provider())
                if stop:
                    return DispatchResult(event.get("id"), event_type=event.get("event_type"),
                                           permitted=False, reason=f"auto-stop: {why}")

        q.lease_event(event, self.config.worker_id, now=now)
        leased_id = event.get("id")
        self.active_leases.add(leased_id)
        return DispatchResult(leased_id, event_type=event.get("event_type"),
                               permitted=True, mode=None, reason="leased to worker")

    def complete(self, event_id: str) -> None:
        self.active_leases.discard(event_id)
        self.cancelled.discard(event_id)

    def fail(self, event: dict, *, now: datetime | None = None) -> dict:
        """Record a processing failure -> backoff retry or dead-letter."""
        now = now or datetime.now(timezone.utc)
        self.active_leases.discard(event.get("id"))
        return q.classify_after_failure(event, now=now)


def scanner_for_event(event_type: str, payload: dict) -> str:
    """Deterministic scanner selection from event/domain — the universal
    engine never asks the user 'which scanner'; it routes by asset/domain."""
    domain = (payload.get("domain") or payload.get("kind") or "").lower()
    et = event_type.lower()
    if "cloud" in domain or "cloud" in et:
        return "cloud_scanner"
    if "network" in domain or "network" in et:
        return "network_scanner"
    if "hardware" in domain or "hsm" in domain or "hardware" in et:
        return "ot_scanner"
    if "vendor" in domain or "vendor" in et:
        return "universal_vendor"
    if "container" in domain or "k8s" in domain or "container" in et:
        return "container_scanner"
    if "application" in domain or "repo" in domain or "code" in et or "scan.repo" in et:
        return "universal_crypto"
    return "universal_crypto"
