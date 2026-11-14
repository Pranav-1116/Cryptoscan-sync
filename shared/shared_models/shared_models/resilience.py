"""Fault-tolerance primitives: circuit breaker, retry, bulkhead, deadline.

One canonical implementation for the pattern every service eventually
hand-rolls (a breaker in alert dispatch, retry in cloud scans, backoff in the
Redis sync). The primitives are small on purpose and honest about what they
cannot do:

* ``CircuitBreaker`` — closed → open → half-open with a *probe* discipline:
  while half-open only ``success_threshold`` consecutive successes close the
  circuit and one failure reopens it immediately. Thread-safe. Drop-in
  compatible with the alert dispatcher's local breaker (``is_open`` /
  ``record_success`` / ``record_failure``).
* ``retry_with_backoff`` — bounded retries with exponential backoff plus
  jitter, and a ``is_retryable`` classifier so a permanent error is never
  retried into a bigger outage.
* ``Bulkhead`` — a counted semaphore: concurrent calls are bounded, waiting
  is bounded, and every rejection is counted — overload refuses loudly.
* ``call_with_deadline`` — runs the call on a worker thread and abandons it
  at the deadline. Honest boundary: Python cannot kill a running thread; the
  caller stops waiting (and counts the abandonment) while the call itself
  runs to completion in the background. Never claim a hard cancel here.

Every primitive reports ``as_dict()`` — production operations need the
numbers (counts, state, next recovery time), not vibes.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Tuple

logger = logging.getLogger(__name__)

CLOSED = "closed"
OPEN = "open"
HALF_OPEN = "half-open"


class CircuitOpenError(RuntimeError):
    """Raised by ``call`` while the circuit refuses traffic."""

    def __init__(self, name: str, state: str) -> None:
        super().__init__(
            f"circuit {name!r} is {state}: calls are refused until the "
            "recovery timeout lets a probe through — a broken dependency is "
            "cheaper to refuse than to pile onto")
        self.name = name
        self.state = state


class CircuitBreaker:
    """Closed → open → half-open with probe discipline. Thread-safe."""

    def __init__(self, name: str = "circuit", *,
                 failure_threshold: int = 5,
                 recovery_timeout: float = 60.0,
                 success_threshold: int = 2,
                 clock: Callable[[], float] = time.monotonic) -> None:
        if failure_threshold <= 0 or success_threshold <= 0:
            raise ValueError("thresholds are positive — a zero-threshold "
                             "breaker is a coin flip, not a control")
        if recovery_timeout <= 0:
            raise ValueError("recovery_timeout is positive — an instant "
                             "recovery retries a dead dependency forever")
        self.name = name
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._success_threshold = success_threshold
        self._clock = clock
        self._lock = threading.Lock()
        self._state = CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[float] = None
        self._refused = 0

    @property
    def state(self) -> str:
        with self._lock:
            self._maybe_half_open()
            return self._state

    @property
    def is_open(self) -> bool:
        """True while the circuit refuses traffic. Reading this property is
        what advances an expired open circuit to half-open (the probe window)
        — the same contract the alert dispatcher's breaker had."""
        with self._lock:
            self._maybe_half_open()
            if self._state == OPEN:
                self._refused += 1
                return True
            return False

    def record_success(self) -> None:
        with self._lock:
            if self._state == HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self._success_threshold:
                    self._state = CLOSED
                    self._failure_count = 0
                    self._success_count = 0
            else:
                self._failure_count = 0
                self._state = CLOSED

    def record_failure(self) -> None:
        opened = False
        with self._lock:
            self._last_failure_time = self._clock()
            if self._state == HALF_OPEN:
                # One failed probe reopens immediately: the dependency is
                # still down, stop paying for discovery.
                self._state = OPEN
                self._success_count = 0
                opened = True
            else:
                self._failure_count += 1
                if self._failure_count >= self._failure_threshold:
                    self._state = OPEN
                    opened = True
        if opened:
            logger.warning("circuit_breaker_opened name=%s failures=%d threshold=%d",
                           self.name, self._failure_count, self._failure_threshold)

    def call(self, fn: Callable[[], Any]) -> Any:
        """Run ``fn`` under the breaker: refused while open."""
        if self.is_open:
            raise CircuitOpenError(self.name, OPEN)
        try:
            result = fn()
        except Exception:
            self.record_failure()
            raise
        self.record_success()
        return result

    def as_dict(self) -> dict:
        with self._lock:
            self._maybe_half_open()
            next_probe_in = None
            if self._state == OPEN and self._last_failure_time is not None:
                next_probe_in = round(max(
                    0.0, self._recovery_timeout
                    - (self._clock() - self._last_failure_time)), 3)
            return {
                "name": self.name, "state": self._state,
                "failure_count": self._failure_count,
                "failure_threshold": self._failure_threshold,
                "success_threshold": self._success_threshold,
                "recovery_timeout_seconds": self._recovery_timeout,
                "next_probe_in_seconds": next_probe_in,
                "refused_total": self._refused,
            }

    def _maybe_half_open(self) -> None:
        if self._state == OPEN and self._last_failure_time is not None:
            elapsed = self._clock() - self._last_failure_time
            if elapsed >= self._recovery_timeout:
                self._state = HALF_OPEN
                self._success_count = 0


def retry_with_backoff(
        call: Callable[[], Any], *,
        retries: int = 3,
        base_delay: float = 0.2,
        max_delay: float = 10.0,
        jitter: float = 0.2,
        is_retryable: Optional[Callable[[Exception], bool]] = None,
        sleep: Callable[[float], None] = time.sleep) -> Tuple[bool, Any, Optional[Exception]]:
    """Run ``call``, retrying transient failures with jittered exponential
    backoff. Returns ``(ok, value, error)`` — the boundary convention shared
    with ``cloud_scanner.core.reliability``.

    ``is_retryable`` decides what transient means; without it, every
    exception is transient (the caller that knows better should say so).
    """
    if retries < 0:
        raise ValueError("retries is non-negative")
    last_error: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            return True, call(), None
        except Exception as exc:  # noqa: BLE001 — boundary: classify then retry
            last_error = exc
            if attempt == retries:
                break
            if is_retryable is not None and not is_retryable(exc):
                break
            delay = min(max_delay, base_delay * (2 ** attempt))
            delay += random.uniform(0, jitter)
            sleep(delay)
    return False, None, last_error


@dataclass
class Bulkhead:
    """Counted concurrency limit: overload refuses loudly, never queues
    without bound. Waiting is bounded by ``max_wait``; every rejection is
    counted for operators."""

    name: str = "bulkhead"
    max_concurrent: int = 8
    max_wait: float = 0.0
    _semaphore: threading.Semaphore = field(init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _in_flight: int = field(default=0, init=False)
    _refused: int = field(default=0, init=False)
    _completed: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        if self.max_concurrent <= 0:
            raise ValueError("max_concurrent is positive — an unlimited "
                             "bulkhead is how one slow dependency becomes "
                             "the outage")
        if self.max_wait < 0:
            raise ValueError("max_wait is non-negative")
        self._semaphore = threading.Semaphore(self.max_concurrent)

    def acquire(self) -> bool:
        got = self._semaphore.acquire(timeout=self.max_wait) \
            if self.max_wait > 0 else self._semaphore.acquire(blocking=False)
        with self._lock:
            if got:
                self._in_flight += 1
            else:
                self._refused += 1
        return got

    def release(self) -> None:
        with self._lock:
            self._in_flight -= 1
            self._completed += 1
        self._semaphore.release()

    def as_dict(self) -> dict:
        with self._lock:
            return {
                "name": self.name,
                "max_concurrent": self.max_concurrent,
                "max_wait_seconds": self.max_wait,
                "in_flight": self._in_flight,
                "completed_total": self._completed,
                "refused_total": self._refused,
            }


def call_with_deadline(call: Callable[[], Any], seconds: float,
                       *, name: str = "call") -> Tuple[bool, Any, Optional[Exception]]:
    """Run ``call``, stopping the *wait* at ``seconds``.

    Honest boundary: the call runs on a worker thread that Python cannot
    kill — at the deadline the caller stops waiting and counts the
    abandonment while the thread runs to completion (or blocks forever) in
    the background. A timeout here is a truth about the caller's patience,
    never a claim that the work stopped.
    """
    if seconds <= 0:
        raise ValueError("seconds is positive")
    outcome: dict = {}

    def _runner() -> None:
        try:
            outcome["value"] = call()
            outcome["ok"] = True
        except Exception as exc:  # noqa: BLE001 — forwarded to the caller
            outcome["error"] = exc

    thread = threading.Thread(target=_runner, name=f"deadline-{name}", daemon=True)
    thread.start()
    thread.join(seconds)
    if thread.is_alive():
        return False, None, TimeoutError(
            f"{name} exceeded its {seconds}s deadline — the wait was "
            "abandoned; the call itself cannot be killed and may still "
            "complete in the background")
    if outcome.get("ok"):
        return True, outcome.get("value"), None
    return False, None, outcome.get("error")
