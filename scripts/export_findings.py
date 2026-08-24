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
    parser.add_argument("--format", choices=("json", "csv"), default="json")
    args = parser.parse_args()

    from db.connection.session import SessionLocal, init_db
    from db.repositories.evidence_repository import EvidenceRepository

    init_db()
    session = SessionLocal()
    try:
        rows = EvidenceRepository(session).get_all_for_scan(args.scan_id)
        if args.format == "csv":
            import csv

            writer = csv.DictWriter(
                sys.stdout,
                fieldnames=["id", "algorithm", "mode", "key_size", "purpose", "file_path", "line_number", "compliance_status"],
            )
            writer.writeheader()
            for row in rows:
                writer.writerow(
                    {
                        "id": row.id,
                        "algorithm": row.algorithm,
                        "mode": row.mode,
                        "key_size": row.key_size,
                        "purpose": row.purpose,
                        "file_path": row.file_path,
                        "line_number": row.line_number,
                        "compliance_status": row.compliance_status,
                    }
                )
        else:
            print(json.dumps([r.to_dict() for r in rows], indent=2))
    finally:
        session.close()


if __name__ == "__main__":
    main()
