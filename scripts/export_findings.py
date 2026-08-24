#!/usr/bin/env python3
"""Export findings for a scan as JSON."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "database"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("scan_id")
    args = parser.parse_args()

    from db.connection.session import SessionLocal, init_db
    from db.repositories.evidence_repository import EvidenceRepository

    init_db()
    session = SessionLocal()
    try:
        rows = EvidenceRepository(session).get_all_for_scan(args.scan_id)
        print(json.dumps([r.to_dict() for r in rows], indent=2))
    finally:
        session.close()


if __name__ == "__main__":
    main()
