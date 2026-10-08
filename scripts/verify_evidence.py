#!/usr/bin/env python3
"""Re-verify content hashes stored for a scan."""

from __future__ import annotations
from _bootstrap import bootstrap  # noqa: E402

bootstrap()

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_id")
    args = parser.parse_args()

    from db.connection.session import SessionLocal, init_db
    from db.models.scan import Scan
    from db.repositories.evidence_repository import EvidenceRepository
    from db.tenancy import filtered_get
    from evidence.verification.stored_scan import verify_stored_scan

    init_db()
    session = SessionLocal()
    try:
        scan = filtered_get(session, Scan, args.scan_id)
        if scan is None:
            print(f"{args.scan_id} NOT_FOUND")
            raise SystemExit(1)
        verdict = verify_stored_scan(
            scan, EvidenceRepository(session).get_all_for_scan(args.scan_id)
        )
        print(f"{args.scan_id} {verdict['result']} records={verdict['records']}")
        for error in verdict["errors"]:
            print(f"  {error}")
        raise SystemExit(0 if verdict["result"] in {"PASS", "EMPTY"} else 1)
    finally:
        session.close()


if __name__ == "__main__":
    main()
