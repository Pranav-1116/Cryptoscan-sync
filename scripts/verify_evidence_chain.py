#!/usr/bin/env python3
"""Print VALID, INVALID, or BROKEN_AT_SEQUENCE for a stored scan chain."""

from __future__ import annotations
from _bootstrap import bootstrap  # noqa: E402

bootstrap()

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="zelnx verify-evidence-chain")
    parser.add_argument("--scan-id", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    from db.connection.session import SessionLocal, init_db
    from db.repositories.evidence_repository import EvidenceRepository
    from evidence.verification.chain_verdict import verdict_for_records

    init_db()
    session = SessionLocal()
    try:
        rows = EvidenceRepository(session).get_all_for_scan(args.scan_id)
        verdict = verdict_for_records(rows, args.scan_id)
    finally:
        session.close()
    if args.json:
        print(json.dumps(verdict))
    else:
        extra = f" BROKEN_AT={verdict['broken_at']}" if verdict["broken_at"] is not None else ""
        print(f"{verdict['result']} records={verdict['records']}{extra}")
        print(verdict["message"])
    return 0 if verdict["result"] == "VALID" else 1


if __name__ == "__main__":
    raise SystemExit(main())
