#!/usr/bin/env python3
"""24/7 continuous monitor daemon.

Watches every enabled monitor target (network endpoints, cloud accounts,
repositories, container images) and re-scans each on its interval through the
same live scanners the manual flows use. Runs until stopped; --once runs a
single sweep (cron mode). API: see /api/v1/monitor/* and the dashboard's
"Live monitor" view.
"""

from __future__ import annotations
from _bootstrap import bootstrap  # noqa: E402

bootstrap()

import argparse
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true", help="run one sweep and exit (cron mode)")
    parser.add_argument("--tick-seconds", type=float, default=30.0, help="daemon tick cadence (default 30s)")
    parser.add_argument("--lease-ttl", type=float, default=60.0,
                        help="leader-lease TTL seconds (default 60) — run N daemons, exactly one scans")
    parser.add_argument("--no-lease", action="store_true",
                        help="run without the leader lease (single-instance legacy mode)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    from db.connection.session import SessionLocal, configure_session
    from worker.monitor.alerting import AlertRouter
    from worker.monitor.engine import MonitorEngine
    from worker.monitor.lease import LeaderLease, ensure_lease_table
    from worker.monitor.loop import MonitorLoop, install_signal_handlers

    configure_session()  # bind SessionLocal to the configured database engine
    router = AlertRouter()
    factory = lambda session: MonitorEngine(session, on_alert=router.dispatch)  # noqa: E731
    lease = None
    if not args.no_lease:
        bootstrap = SessionLocal()
        try:
            ensure_lease_table(bootstrap)  # idempotent; migration 0031 does this properly
        finally:
            bootstrap.close()
        lease = LeaderLease(SessionLocal, ttl_seconds=args.lease_ttl)
    loop = MonitorLoop(
        factory,
        session_factory=SessionLocal,
        tick_seconds=args.tick_seconds,
        lease=lease,
    )
    if args.once:
        outcome = loop.run_once()
        print(f"monitor sweep: {outcome.get('ran', 0)} target(s) run")
        return 0
    install_signal_handlers(loop)
    mode = f"leader-lease ttl={args.lease_ttl}s" if lease else "no-lease (single instance)"
    print(f"cryptoscan monitor running (tick={args.tick_seconds}s, {mode}) — Ctrl+C to stop", file=sys.stderr)
    return loop.run_forever()


if __name__ == "__main__":
    raise SystemExit(main())
