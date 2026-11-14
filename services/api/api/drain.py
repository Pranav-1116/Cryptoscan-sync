"""Load-balancer drain state: \"stop sending me new traffic, I am going away\".

The probes have distinct jobs (the health.py contract): ``/healthz`` is
liveness — it stays 200 while the process can serve, even through a database
outage, so an orchestrator never restart-storms a healthy process. ``/readyz``
is readiness for the load balancer — 503 drains the route. The missing third
state was the process's OWN retirement: on SIGTERM (rolling restart, scale
down, promotion shuffle) a replica must flip readiness to 503 *while it
finishes in-flight requests*, or the load balancer keeps routing to a socket
that is about to close and clients see resets instead of drain.

``begin_drain`` is that flip. It is idempotent, thread-safe, and answers
``as_dict()`` with the reason and the moment — an operator watching a rolling
restart sees which replica drained when, not a silent disappearance.
"""

from __future__ import annotations

import threading
import time
from typing import Optional

_lock = threading.Lock()
_drain: Optional[dict] = None


def begin_drain(reason: str = "process_shutdown") -> None:
    """Flip this process to draining. Idempotent: the first reason wins and
    later calls do not rewrite history."""
    global _drain
    with _lock:
        if _drain is None:
            _drain = {"reason": str(reason), "at": time.time()}


def is_draining() -> bool:
    with _lock:
        return _drain is not None


def as_dict() -> dict:
    with _lock:
        if _drain is None:
            return {"draining": False}
        return {"draining": True, **_drain}


def reset() -> None:
    """Test-only: forget the drain (a process cannot un-retire in life)."""
    global _drain
    with _lock:
        _drain = None
