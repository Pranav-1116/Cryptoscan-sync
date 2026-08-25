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
    parser.add_argument("target_id", nargs="?", default="", help="scan_id or system_id (omit for portfolio)")
    parser.add_argument("--kind", choices=("scan", "system", "portfolio"), default="scan")
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
        if args.kind == "portfolio":
            from db.repositories.asset_repository import AssetRepository
            from db.repositories.system_repository import SystemRepository

            sys_repo = SystemRepository(session)
            systems, _ = sys_repo.list_systems(page=1, page_size=1000)
            records = []
            seen: set[str] = set()
            for system in systems:
                for asset in sys_repo.assets_for(system.id):
                    seen.add(asset.id)
                    data = asset.to_dict()
                    data["system_id"] = system.id
                    data["system_name"] = system.name
                    records.append(data)
            assets, _ = AssetRepository(session).list_assets(page=1, page_size=5000)
            for asset in assets:
                if asset.id in seen:
                    continue
                data = asset.to_dict()
                data["system_name"] = "unassigned"
                records.append(data)
            bom = generator.from_records(
                records,
                name="cryptoscan-portfolio",
                version="aggregate",
                metadata_properties=[{"name": "cryptoscan:scope", "value": "estate"}],
            )
        elif args.kind == "scan":
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
