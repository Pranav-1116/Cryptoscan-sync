#!/usr/bin/env python3
"""Create, list, and inspect CryptoScan systems."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "database"))
sys.path.insert(0, str(ROOT / "shared" / "shared_config"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage CryptoScan systems")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    create = sub.add_parser("create")
    create.add_argument("name")
    create.add_argument("--owner")
    create.add_argument("--environment", default="prod")
    create.add_argument("--scopes", default="", help="Comma-separated compliance scopes")
    show = sub.add_parser("show")
    show.add_argument("name")
    args = parser.parse_args()

    from db.connection.session import SessionLocal, init_db
    from db.models.system import System
    from db.repositories.system_repository import SystemRepository

    init_db()
    session = SessionLocal()
    try:
        repo = SystemRepository(session)
        if args.command == "list":
            rows, total = repo.list_systems(page=1, page_size=200)
            print(json.dumps({"total": total, "systems": [row.to_dict() for row in rows]}, indent=2))
            return
        if args.command == "create":
            scopes = [item.strip() for item in args.scopes.split(",") if item.strip()]
            existing = repo.get_by_name(args.name)
            if existing:
                raise SystemExit(f"system already exists: {args.name}")
            row = repo.create(
                System(
                    name=args.name,
                    owner=args.owner,
                    environment=args.environment,
                    compliance_scopes=scopes,
                )
            )
            session.commit()
            print(json.dumps(row.to_dict(), indent=2))
            return
        row = repo.get_by_name(args.name)
        if row is None:
            raise SystemExit(f"system not found: {args.name}")
        payload = row.to_dict()
        payload["assets"] = [asset.to_dict() for asset in repo.assets_for(row.id)]
        print(json.dumps(payload, indent=2))
    finally:
        session.close()


if __name__ == "__main__":
    main()
