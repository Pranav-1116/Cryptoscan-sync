"""Read/write splitting for a PostgreSQL primary/replica deployment.

``deploy/ha`` runs the topology (pg-primary, pg-replica, promote-replica.sh,
drill.sh); this module is the application's half: routes READ sessions to
replicas and WRITE sessions to the primary, with two honesty rules that a
naive router forgets:

* **Read-your-writes** — once a request has written (``write_session``),
  every later read *in that request's context* is pinned to the primary.
  A replica that has not caught up must never feed a caller fresh from its
  own write the stale version.
* **Fallback counts** — a dead replica falls back to the primary (the
  availability-correct choice) and the fallback is COUNTED and logged. A
  silently degraded deployment is the failure mode this product never ships.

Honest boundary — replica lag is real and never hidden: a read served from
a replica may miss a write that has not yet replicated. Cross-request
freshness is the deployment's to set (``synchronous_commit``,
``hot_standby_feedback``); this router only guarantees the one contract it
can: a writer reads its own writes on the primary.

Usage: ``write_session()``/``read_session()`` context managers around a
session factory each (primary + replicas). With no replicas configured the
router is a pure pass-through to the primary — single-database deployments
see no behavior change.
"""

from __future__ import annotations

import contextvars
import itertools
import logging
import threading
from contextlib import contextmanager
from typing import Any, Callable, Iterator, Optional

logger = logging.getLogger(__name__)

_pin = contextvars.ContextVar("read_router_primary_pin", default=False)


class ReadRouter:
    """Round-robin reads across replicas with counted primary fallback."""

    def __init__(self, primary_factory: Callable[[], Any],
                 replica_factories: Optional[list[Callable[[], Any]]] = None) -> None:
        self._primary = primary_factory
        self._replicas = list(replica_factories or [])
        self._cycle = itertools.cycle(range(len(self._replicas))) \
            if self._replicas else None
        self._lock = threading.Lock()
        self._reads = 0
        self._replica_reads = 0
        self._fallbacks = 0

    @property
    def replica_count(self) -> int:
        return len(self._replicas)

    @contextmanager
    def read_session(self) -> Iterator[Any]:
        """Yield a read session: a replica when one is usable and this
        context is unpinned, else the primary."""
        self._reads += 1
        if _pin.get() or self._cycle is None:
            session = self._primary()
            try:
                yield session
            finally:
                session.close()
            return
        with self._lock:
            start = next(self._cycle)
        order = [(start + i) % len(self._replicas)
                 for i in range(len(self._replicas))]
        for index in order:
            factory = self._replicas[index]
            try:
                session = factory()
            except Exception as exc:  # noqa: BLE001 — fallback is the policy
                self._fallbacks += 1
                logger.warning(
                    "read_replica_unavailable_falling_back_to_primary "
                    "replica=%d error_type=%s", index, type(exc).__name__)
                continue
            self._replica_reads += 1
            try:
                yield session
            finally:
                session.close()
            return
        # Every replica was unusable: the primary serves, loudly counted.
        session = self._primary()
        try:
            yield session
        finally:
            session.close()

    @contextmanager
    def write_session(self) -> Iterator[Any]:
        """Yield a primary session and pin this context to the primary: the
        reads that follow a write see the write (read-your-writes)."""
        _pin.set(True)
        session = self._primary()
        try:
            yield session
        finally:
            session.close()

    def as_dict(self) -> dict:
        return {
            "replicas": len(self._replicas),
            "reads_total": self._reads,
            "replica_reads_total": self._replica_reads,
            "primary_fallbacks_total": self._fallbacks,
            "pinned_to_primary": bool(_pin.get()),
            "note": ("reads round-robin replicas with counted fallback to "
                     "the primary; a context that writes is pinned to the "
                     "primary so a caller always reads its own writes — "
                     "replica lag across independent requests is real and "
                     "is the deployment's synchronous_commit to bound"),
        }
