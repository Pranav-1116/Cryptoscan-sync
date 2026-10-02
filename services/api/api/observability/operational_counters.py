"""Process-local counters for the operational events update.md section 5 names.

Section 5 asks for persistence failure alerts, tenant-isolation violation
alerts, evidence-redaction alerts, timeout counters, event replay-gap
counters and queue saturation. Most of those cannot be derived from a table
after the fact: a tenant-isolation violation that was correctly refused
leaves no row, and a scan that timed out leaves no finding. They have to be
counted where they happen.

Deliberately dependency-free and in-process:

* no Redis, so a counter still increments while Redis is the thing that
  broke -- which is exactly when an operator is reading the dashboard;
* monotonic, never reset, so Prometheus ``rate()`` and ``increase()`` behave;
* per-replica, which is correct for a counter -- Prometheus aggregates
  across replicas by label, and a shared counter would hide which replica
  is failing.

These count *security and reliability events*, so a zero is a meaningful
claim. Increment only where the event genuinely occurred.
"""
from __future__ import annotations

import threading
from collections import Counter

_lock = threading.Lock()
_counts: Counter[str] = Counter()

#: Events that are actually instrumented, so /metrics can emit a 0 line
#: before the first occurrence. A metric that springs into existence on the
#: first failure cannot be alerted on beforehand -- the rule would reference
#: a series that does not exist and would never fire.
#:
#: Only names with a real increment site belong here. Listing an
#: uninstrumented event would publish a permanent 0, which does not read as
#: "not measured", it reads as "never happened" -- a stronger and false
#: claim, and precisely the kind this product exists to catch elsewhere.
#:
#: Instrumented today (grep the name to find the site):
#:   tenant_isolation_violation  api/middleware/tenant_scope.py
#:   event_replay_gap            api/routers/events.py
#:   persistence_failure         api/routers/trigger.py
#:
#: Deliberately absent until someone instruments them: evidence_redaction,
#: scan_timeout and queue_saturation live in the database and worker
#: services, which must not import from the API layer. Wiring them needs the
#: counter moved to shared/, and an uninstrumented zero is worse than a
#: missing series.
KNOWN = (
    "tenant_isolation_violation",
    "event_replay_gap",
    "persistence_failure",
)


def incr(event: str, amount: int = 1) -> None:
    """Record one occurrence. Unknown names are accepted but flagged."""
    with _lock:
        _counts[event] += amount


def snapshot() -> dict[str, int]:
    """Current values, including a zero for every known-but-unseen event."""
    with _lock:
        seen = dict(_counts)
    return {name: seen.get(name, 0) for name in KNOWN} | {
        k: v for k, v in seen.items() if k not in KNOWN
    }


def reset_for_tests() -> None:
    with _lock:
        _counts.clear()
