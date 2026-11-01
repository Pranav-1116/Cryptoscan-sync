#!/usr/bin/env python3
"""Run the twin's retention sweep once: archive, then prune.

    # what it would delete, deleting nothing
    python scripts/apply_retention.py --dry-run

    # the real thing, with the archive on a mounted volume
    python scripts/apply_retention.py --archive-dir /var/lib/cryptoscan/archive

The window comes from ``ESTATE_HISTORY_RETENTION_DAYS`` /
``ESTATE_EVIDENCE_RETENTION_DAYS`` (default 2555 = seven years), and the sweep
refuses to run at all while ``ESTATE_RETENTION_LEGAL_HOLD`` is set. Nothing is
deleted until the archive file has been written, flushed and fsynced, and the
receipt names the SHA-256 of exactly what left the database — which is what an
auditor needs to check the box, and what an operator needs to ask for it back.

On PostgreSQL the sweep also **drops whole months** instead of deleting their
rows: a monthly partition of ``estate_observations`` that is entirely past the
window is archived to its own NDJSON file and then dropped, which is a catalogue
operation rather than a table rewrite. The same run creates the next months'
partitions (``db.partitions.ensure``), so a sweep that stops running is the only
way a month can be missing — and a missing month fails the insert loudly instead
of hiding in a DEFAULT.

Intended cadence: daily, from a CronJob or systemd timer, with the archive
directory on durable storage. It is idempotent — a second run in the same hour
finds nothing to do.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for relative in ("services/api", "services/database", "shared/shared_models",
                 "shared/shared_config", "services/runtime", "services/evidence",
                 "services/worker", "services/observability"):
    candidate = str(ROOT / relative)
    if candidate not in sys.path:
        sys.path.insert(0, candidate)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--archive-dir", help="where the pruned rows are written first")
    parser.add_argument("--dry-run", action="store_true", help="report, delete nothing")
    parser.add_argument("--force", action="store_true",
                        help="override the minimum-window floor")
    parser.add_argument("--json", help="write the receipt here")
    args = parser.parse_args(argv)

    from api.config.settings import get_settings
    from db.connection.session import SessionLocal
    from db.retention import apply

    settings = get_settings()
    if not args.dry_run and not args.archive_dir:
        parser.error("--archive-dir is required unless --dry-run: nothing is deleted "
                     "before it has been written somewhere durable")

    session = SessionLocal()
    try:
        receipt = apply(session, dry_run=args.dry_run, archive_dir=args.archive_dir,
                        settings=settings, force=args.force)
    finally:
        session.close()

    payload = receipt.as_dict()
    if args.json:
        Path(args.json).write_text(json.dumps(payload, indent=2) + "\n")
    print(json.dumps(payload, indent=2))
    partitions = payload.get("partitions") or {}
    if partitions.get("supported"):
        print(
            f"\npartitions: {len(partitions.get('created') or [])} created, "
            f"{len(partitions.get('dropped') or [])} dropped, "
            f"{partitions.get('rows_dropped', 0)} rows archived from dropped months",
            file=sys.stderr,
        )
    if payload["refused"]:
        print(f"\nrefused: {payload['refused']}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
