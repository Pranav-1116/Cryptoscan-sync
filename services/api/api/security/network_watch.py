"""24/7 scope-bound cryptographic network observation (spec 67 §3, §30).

The Live Monitor already polls inventory. This worker is different: it runs the
*observation* path on a timer, so network crypto posture is re-measured
continuously rather than only when an operator clicks.

Non-negotiable properties:

* **Scope-bound.** Every tick re-reads the saved approved scope. No scope, an
  expired scope, or a destination that no longer matches → the tick is skipped
  and the reason recorded. The worker can never widen what was approved.
* **Budgeted.** Each tick reserves connections from the rolling traffic budget
  before probing; an exhausted budget skips the tick instead of spending past
  the approval.
* **Never overlapping.** One tick at a time, like the live-scan runner.
* **Honest.** A skipped tick is reported as skipped with a reason; it is not
  counted as a successful observation.

The worker is an in-process daemon thread with persisted configuration, not a
distributed scheduler. ``distributed: false`` is reported so nobody mistakes it
for HA scheduling.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Any, Callable

logger = logging.getLogger(__name__)

MIN_INTERVAL = 120
MAX_INTERVAL = 24 * 3600


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class NetworkCryptoWatcher:
    """Interval loop over the approved scope; one observation tick at a time."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.interval = 900
        self.inventory_id = "default"
        self.tenant_id: str | None = None
        self.started_at: str | None = None
        self.last_tick_at: str | None = None
        self.last_result: dict[str, Any] | None = None
        self.ticks = 0
        self.observed_ticks = 0
        self.skipped_ticks = 0
        self.failed_ticks = 0

    # -- lifecycle ---------------------------------------------------------
    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive() and not self._stop.is_set())

    def start(
        self,
        *,
        interval: int,
        inventory_id: str = "default",
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        interval = max(MIN_INTERVAL, min(MAX_INTERVAL, int(interval)))
        with self._lock:
            if self.running:
                return self.status()
            self.interval = interval
            self.inventory_id = inventory_id
            self.tenant_id = tenant_id
            self._stop.clear()
            self.started_at = _now()
            self._thread = threading.Thread(
                target=self._loop, name="network-crypto-watch", daemon=True
            )
            self._thread.start()
        logger.info("network_crypto_watch_started interval=%s", interval)
        return self.status()

    def stop(self) -> dict[str, Any]:
        self._stop.set()
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=5.0)
        self._thread = None
        logger.info("network_crypto_watch_stopped")
        return self.status()

    def status(self) -> dict[str, Any]:
        return {
            "schema": "cryptoscan.network-crypto-watch/1",
            "running": self.running,
            "interval_seconds": self.interval,
            "inventory_id": self.inventory_id,
            "started_at": self.started_at,
            "last_tick_at": self.last_tick_at,
            "last_result": self.last_result,
            "ticks": self.ticks,
            "observed_ticks": self.observed_ticks,
            "skipped_ticks": self.skipped_ticks,
            "failed_ticks": self.failed_ticks,
            "distributed": False,
            "boundary": (
                "in-process interval worker over the approved scope; "
                "a skipped tick is not an observation"
            ),
        }

    # -- loop --------------------------------------------------------------
    def _loop(self) -> None:
        # first tick immediately so an operator sees evidence without waiting
        while not self._stop.is_set():
            self.tick()
            if self._stop.wait(self.interval):
                break

    def tick(self, runner: Callable[..., dict[str, Any]] | None = None) -> dict[str, Any]:
        """Run one observation cycle. Never raises; returns the tick record."""
        self.ticks += 1
        self.last_tick_at = _now()
        try:
            result = (runner or default_tick)(inventory_id=self.inventory_id)
        except Exception as exc:  # noqa: BLE001 — a failed tick must not kill the loop
            result = {"status": "FAILED", "reason": f"{type(exc).__name__}: {exc}"}
            logger.warning("network_crypto_watch_tick_failed: %s", exc)
        status = str(result.get("status") or "UNKNOWN")
        # counted exactly once, in one place
        if status == "OBSERVED":
            self.observed_ticks += 1
        elif status == "SKIPPED":
            self.skipped_ticks += 1
        else:
            self.failed_ticks += 1
        self.last_result = result
        return result


_WATCHER: NetworkCryptoWatcher | None = None


def get_watcher() -> NetworkCryptoWatcher:
    global _WATCHER
    if _WATCHER is None:
        _WATCHER = NetworkCryptoWatcher()
    return _WATCHER


def reset_watcher_for_tests() -> None:
    global _WATCHER
    if _WATCHER is not None:
        _WATCHER.stop()
    _WATCHER = None


def default_tick(*, inventory_id: str = "default") -> dict[str, Any]:
    """One scope-checked, budget-checked observation of the approved scope.

    Returns ``SKIPPED`` with an explicit reason when there is nothing valid to
    observe — never a fabricated success.
    """
    from contextlib import contextmanager


    from db.connection.session import SessionLocal

    from api.security.network_budget import reserve
    from api.security.network_scope import ScopeViolation, check_scope

    with SessionLocal() as db:
        from api.routers.network import _load_crypto_scope  # local import: avoid cycle

        scope = _load_crypto_scope(db, inventory_id)
        if not scope:
            return {"status": "SKIPPED", "reason": "no approved scope — nothing may be observed"}
        destinations = list(scope.get("destinations") or [])
        if not destinations:
            return {"status": "SKIPPED", "reason": "approved scope has no destinations"}
        try:
            check_scope(scope, destinations, protocol="TLS")
            reserve(db, scope, inventory_id=inventory_id, connections=len(destinations), user="network-watch")
        except ScopeViolation as exc:
            return {"status": "SKIPPED", "reason": exc.reason, "code": exc.code}

        from api.security.network_collection import network_run, persist_network
        from network_scanner.core.scanner import NetworkTlsScanner
        from network_scanner.inventory.network_evidence import build_evidence, summarize

        result = NetworkTlsScanner(live=True, timeout=5.0, workers=min(8, len(destinations))).scan_hosts(destinations)
        evidence = [
            build_evidence(
                finding,
                observed_at=_now(),
                scope_name=scope.get("name"),
                scope_revision=str(scope.get("saved_at") or "") or None,
                extra={"trigger": "watch"},
            )
            for finding in (result.get("findings") or [])
        ]
        summary = summarize(evidence)

        @contextmanager
        def _durable_run():
            with network_run(
                db,
                user="network-watch",
                target=",".join(destinations)[:2000],
                admission={
                    "schema": "cryptoscan.network-admission/1",
                    "decision": "PERMITTED",
                    "protocol": "TLS",
                    "checked_targets": len(destinations),
                    "trigger": "watch",
                },
                kind="crypto-watch",
                profile={"trigger": "watch", "scope_name": scope.get("name")},
            ) as run:
                stored = persist_network(
                    db,
                    {**result, "network_evidence": evidence, "network_evidence_summary": summary},
                    run,
                    kind="crypto-watch",
                    collection_metadata={"trigger": "WATCH", "scope_name": scope.get("name")},
                )
                run.succeed(coverage={"protocol": "network", "observed": summary["observed"]})
                yield stored

        with _durable_run() as stored:
            pass

        return {
            "status": "OBSERVED",
            "run_id": stored.get("run_id"),
            "scan_id": stored.get("job_id"),
            "scope_name": scope.get("name"),
            "observed": summary["observed"],
            "not_observed": summary["not_observed"],
            "summary": summary,
        }
