#!/usr/bin/env python3
"""Upsert TLS probe targets from config/network-scan-targets.yaml."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "database"))
sys.path.insert(0, str(ROOT / "services" / "network_scanner"))
sys.path.insert(0, str(ROOT / "shared" / "shared_config"))

DEFAULT = ROOT / "config" / "network-scan-targets.yaml"


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed network scan targets")
    parser.add_argument("--file", type=Path, default=DEFAULT)
    args = parser.parse_args()
    try:
        import yaml
    except ImportError as exc:
        raise SystemExit("PyYAML is required") from exc

    payload = yaml.safe_load(args.file.read_text(encoding="utf-8")) or {}
    targets = payload.get("targets") or []
    if not targets:
        raise SystemExit(f"no targets in {args.file}")

    from db.connection.session import SessionLocal, init_db
    from db.repositories.intelligence_repository import IntelligenceRepository
    from network_scanner.core.scheduler import next_scan_time

    init_db()
    session = SessionLocal()
    try:
        repo = IntelligenceRepository(session)
        for item in targets:
            endpoint = item.get("endpoint")
            if not endpoint:
                continue
            repo.upsert_target(
                endpoint,
                system_id=item.get("system_id"),
                scan_frequency=item.get("scan_frequency") or "daily",
                enabled=bool(item.get("enabled", True)),
                next_scan_time=next_scan_time(None, item.get("scan_frequency") or "daily"),
            )
            print(f"seeded {endpoint}")
        session.commit()
    finally:
        session.close()


if __name__ == "__main__":
    main()
