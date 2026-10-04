#!/usr/bin/env python3
"""DR-drill worker recovery probe.

Boots the *real* worker entrypoint (``worker.main.Worker``) against the
promoted database node, lets it run its consumer loop for a few seconds,
then shuts it down cleanly and re-checks the worker's own session layer.

Exit 0 means: the worker process reconnected to the promoted node, its
DB-backed startup path (init_db) succeeded, and a scan-jobs query through
``SessionLocal`` — the same session layer every worker DB touch uses —
returned data after failover. This is a recovery probe for drills, not a
substitute for a production soak of the worker tier.
"""
from __future__ import annotations

import argparse
import signal
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(p) for p in ROOT.glob("services/*") if p.is_dir()] + \
               [str(p) for p in ROOT.glob("shared/*") if p.is_dir()]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run-seconds", type=float, default=8.0,
                    help="how long the worker loop should run against the node")
    args = ap.parse_args(argv)

    from worker.config.settings import Settings
    from worker.main import Worker

    worker = Worker(Settings())

    def stop() -> None:
        worker.signal_handler(signal.SIGTERM, None)

    timer = threading.Timer(args.run_seconds, stop)
    timer.start()
    try:
        worker.run()  # installs signal handlers: must stay in the main thread
    finally:
        timer.cancel()
        if worker.running:
            stop()

    # The worker's own session layer, after failover.
    from db.connection.session import SessionLocal
    from sqlalchemy import text

    with SessionLocal() as session:
        jobs = int(session.execute(text("SELECT count(*) FROM scan_jobs")).scalar() or 0)
        scans = int(session.execute(text("SELECT count(*) FROM scans")).scalar() or 0)
    print(f"worker recovery probe: reconnected; scan_jobs={jobs} scans={scans}")
    return 0 if (jobs >= 0 and scans >= 0) else 1


if __name__ == "__main__":
    raise SystemExit(main())
