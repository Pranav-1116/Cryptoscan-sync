#!/usr/bin/env python3
"""Approve a completed scan as the active baseline."""

from __future__ import annotations
from _bootstrap import bootstrap  # noqa: E402

bootstrap()

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_id")
    parser.add_argument("--by", default="admin")
    parser.add_argument("--notes", default="Approved from CLI")
    args = parser.parse_args()

    from db.connection.session import SessionLocal, init_db
    from db.repositories.baseline_repository import BaselineRepository
    from db.repositories.scan_repository import ScanRepository

    init_db()
    session = SessionLocal()
    try:
        scan = ScanRepository(session).get_by_id(args.scan_id)
        if scan is None:
            raise SystemExit(f"scan not found: {args.scan_id}")
        baseline = BaselineRepository(session).approve(
            system_identifier=scan.target_location,
            scan_id=scan.id,
            approved_by=args.by,
            notes=args.notes,
        )
        session.commit()
        print(json.dumps({"baseline_id": baseline.id, "target": baseline.system_identifier}, indent=2))
    finally:
        session.close()


if __name__ == "__main__":
    main()
