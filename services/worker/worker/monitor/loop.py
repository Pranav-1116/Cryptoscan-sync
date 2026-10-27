"""The 24/7 daemon loop: tick, sleep, never die.

Every iteration opens a fresh database session so a dropped connection
recovers on the next tick. Any exception is logged and swallowed — monitoring
that exits on the first bad night is not monitoring. Stop cleanly on SIGTERM
(banks patch on weekends, not reboots).
"""

from __future__ import annotations

import logging
import signal
import time
from typing import Any, Callable

logger = logging.getLogger(__name__)


class MonitorLoop:
    def __init__(
        self,
        engine_factory: Callable[[Any], Any],
        *,
        session_factory: Callable[[], Any],
        tick_seconds: float = 30.0,
        sleep: Callable[[float], None] = time.sleep,
        lease: Any = None,
    ):
        self.engine_factory = engine_factory
        self.session_factory = session_factory
        self.tick_seconds = tick_seconds
        self._sleep = sleep
        self.lease = lease  # optional LeaderLease — multi-AZ: only the leader ticks
        self._stop = False
        self.ticks = 0
        self.standby_cycles = 0

    def request_stop(self, *_args) -> None:
        self._stop = True

    def run_forever(self) -> int:
        while not self._stop:
            if self.lease is not None and not self._heartbeat():
                self._sleep(self.tick_seconds)
                continue
            session = None
            try:
                session = self.session_factory()
                outcome = self.engine_factory(session).tick()
                session.commit()
                if outcome.get("ran"):
                    logger.info("monitor_tick", extra={"ran": outcome["ran"]})
            except Exception:
                if session is not None:
                    try:
                        session.rollback()
                    except Exception:
                        logger.exception("monitor_rollback_failed")
                logger.exception("monitor_tick_failed")  # keep running
            finally:
                if session is not None:
                    try:
                        session.close()
                    except Exception as _handler_exc:
                        logger.warning(
                            "exception_suppressed",
                            extra={"error_type": type(_handler_exc).__name__},
                        )
                        pass
            self.ticks += 1
            if self._stop:
                break
            self._sleep(self.tick_seconds)
        if self.lease is not None and self.lease.is_leader:
            try:
                self.lease.release()  # graceful shutdown -> instant failover, no TTL wait
            except Exception:
                logger.exception("lease_release_failed")
        logger.info("monitor_stopped", extra={"ticks": self.ticks})
        return 0

    def _heartbeat(self) -> bool:
        """Renew (or step down from) the leader lease. Never kills the loop."""
        try:
            return self.lease.heartbeat()
        except Exception:
            logger.exception("lease_heartbeat_failed")  # DB gone: standby until it's back
            return False

    def run_once(self) -> dict:
        """Single tick — also the cron mode (`run_monitor.py --once`)."""
        session = self.session_factory()
        try:
            outcome = self.engine_factory(session).tick()
            session.commit()
            return outcome
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()


def install_signal_handlers(loop: MonitorLoop) -> None:
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, loop.request_stop)
        except ValueError:  # not on the main thread (tests)
            pass
