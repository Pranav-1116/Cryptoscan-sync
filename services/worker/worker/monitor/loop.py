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
    ):
        self.engine_factory = engine_factory
        self.session_factory = session_factory
        self.tick_seconds = tick_seconds
        self._sleep = sleep
        self._stop = False
        self.ticks = 0

    def request_stop(self, *_args) -> None:
        self._stop = True

    def run_forever(self) -> int:
        while not self._stop:
            session = None
            try:
                session = self.session_factory()
                outcome = self.engine_factory(session).tick()
                if outcome.get("ran"):
                    logger.info("monitor_tick", extra={"ran": outcome["ran"]})
            except Exception:
                logger.exception("monitor_tick_failed")  # keep running
            finally:
                if session is not None:
                    try:
                        session.commit()
                    except Exception:
                        logger.exception("monitor_commit_failed")
                    try:
                        session.close()
                    except Exception:
                        pass
            self.ticks += 1
            if self._stop:
                break
            self._sleep(self.tick_seconds)
        logger.info("monitor_stopped", extra={"ticks": self.ticks})
        return 0

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
