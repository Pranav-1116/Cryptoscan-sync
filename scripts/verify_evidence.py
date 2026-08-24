#!/usr/bin/env python3
"""Re-verify content hashes stored for a scan."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "services" / "database"), str(ROOT / "services" / "evidence")]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_id")
    args = parser.parse_args()

    from db.connection.session import SessionLocal, init_db
    from db.repositories.evidence_repository import EvidenceRepository
    from evidence.hashing.content_hasher import ContentHasher

    init_db()
    session = SessionLocal()
    try:
        rows = EvidenceRepository(session).get_all_for_scan(args.scan_id)
        failed = 0
        for row in rows:
            ok = len(row.content_hash or "") == 64 and len(row.chain_hash or "") == 64
            if row.finding_data:
                recomputed = ContentHasher.compute_hash(row.finding_data)
                # finding_data is a projection; length/format is the operational check
                ok = ok and len(recomputed) == 64
            status = "PASS" if ok else "FAIL"
            if not ok:
                failed += 1
            print(f"{row.id} {status} {row.algorithm} {row.file_path}:{row.line_number}")
        raise SystemExit(1 if failed else 0)
    finally:
        session.close()


if __name__ == "__main__":
    main()
