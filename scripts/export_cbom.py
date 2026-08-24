#!/usr/bin/env python3
"""Export a CycloneDX 1.5 CBOM for a scan or system."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "database"))
sys.path.insert(0, str(ROOT / "services" / "cbom"))
sys.path.insert(0, str(ROOT / "shared" / "shared_config"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Export a CryptoScan CBOM")
    parser.add_argument("target_id", help="scan_id or system_id")
    parser.add_argument("--kind", choices=("scan", "system"), default="scan")
    parser.add_argument("--format", choices=("json", "xml"), default="json")
    parser.add_argument("--signed", action="store_true")
    parser.add_argument("-o", "--output")
    args = parser.parse_args()

    from cbom.generator import CbomGenerator
    from db.connection.session import SessionLocal, init_db

    init_db()
    session = SessionLocal()
    try:
        generator = CbomGenerator()
        if args.kind == "scan":
            from db.models.scan import Scan
            from db.repositories.evidence_repository import EvidenceRepository

            scan = session.get(Scan, args.target_id)
            if scan is None:
                raise SystemExit(f"scan not found: {args.target_id}")
            records = EvidenceRepository(session).get_all_for_scan(args.target_id)
            bom = generator.from_records(
                records,
                name=scan.target_location,
                version=scan.target_commit or scan.target_branch or "unknown",
                tool_version=scan.scanner_version,
            )
        else:
            from db.repositories.system_repository import SystemRepository

            repo = SystemRepository(session)
            system = repo.get_by_id(args.target_id)
            if system is None:
                raise SystemExit(f"system not found: {args.target_id}")
            bom = generator.from_records(
                repo.assets_for(args.target_id),
                name=system.name,
                version=system.environment or "unknown",
            )
        if args.signed:
            bom = generator.sign(bom, "cryptoscan-dev")
        text = generator.to_xml(bom) if args.format == "xml" else generator.to_json(bom)
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
        else:
            print(text)
    finally:
        session.close()


if __name__ == "__main__":
    main()
