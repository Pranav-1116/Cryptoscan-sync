"""Suspicious-access detection — the pattern side of authentication.

Rate limiting stops bursts; the audit chain records what happened. This
module answers the operator's question between the two: *is anyone
probing right now?* A bounded sliding window counts failed logins per
(user, source) and flags what crosses the threshold. Success does not
erase history (a valid guess after a hundred wrong ones is exactly what
must stay visible); time does, and the window is bounded — a monitor
that can exhaust memory is a second outage.

Nothing here decides anything: flags are observations for the security
posture surface and the metrics page. Lockout remains the rate
limiter's and the auth store's job.
"""
from __future__ import annotations

import time
from collections import deque
from threading import Lock
from typing import Any

#: window and threshold: ≥5 failures for one (user, source) within 5
#: minutes is suspicious on a bank's authentication surface
WINDOW_SECONDS = 300.0
THRESHOLD = 5
#: bounded per key and in total — the monitor never grows without limit
MAX_PER_KEY = 50
MAX_KEYS = 1000

_LOCK = Lock()
_FAILURES: dict[tuple[str, str], deque[float]] = {}


def _prune(bucket: deque[float], now: float) -> None:
    while bucket and now - bucket[0] > WINDOW_SECONDS:
        bucket.popleft()


def record_failure(user: str, source: str, *, now: float | None = None) -> dict[str, Any]:
    """Record one failed authentication. Returns the key's current state
    (window count + whether it is now suspicious)."""
    moment = time.time() if now is None else float(now)
    key = (user or "unknown", source or "unknown")
    with _LOCK:
        if key not in _FAILURES and len(_FAILURES) >= MAX_KEYS:
            # bounded: drop the oldest key outright (a monitor that dies
            # under load is worse than a monitor with a short memory)
            oldest = min(_FAILURES, key=lambda k: _FAILURES[k][0] if _FAILURES[k] else 0)
            _FAILURES.pop(oldest, None)
        bucket = _FAILURES.setdefault(key, deque(maxlen=MAX_PER_KEY))
        bucket.append(moment)
        _prune(bucket, moment)
        count = len(bucket)
    return {"user": key[0], "source": key[1], "window_failures": count,
            "suspicious": count >= THRESHOLD}


def suspicious(*, now: float | None = None) -> dict[str, Any]:
    """The current suspicion surface: flagged keys + totals. Every key is
    re-pruned against the clock at read time — stale suspicion is never
    reported as current."""
    moment = time.time() if now is None else float(now)
    flagged: list[dict[str, Any]] = []
    total = 0
    with _LOCK:
        for key, bucket in list(_FAILURES.items()):
            _prune(bucket, moment)
            if not bucket:
                _FAILURES.pop(key, None)
                continue
            total += len(bucket)
            if len(bucket) >= THRESHOLD:
                flagged.append({"user": key[0], "source": key[1],
                                "window_failures": len(bucket),
                                "first_failure": bucket[0], "latest_failure": bucket[-1]})
    flagged.sort(key=lambda f: f["window_failures"], reverse=True)
    return {
        "window_seconds": WINDOW_SECONDS,
        "threshold": THRESHOLD,
        "total_failures_in_window": total,
        "suspicious_keys": flagged,
        "suspicious": bool(flagged),
    }


def reset() -> None:
    """Test seam — the window is process state, not durable evidence."""
    with _LOCK:
        _FAILURES.clear()
