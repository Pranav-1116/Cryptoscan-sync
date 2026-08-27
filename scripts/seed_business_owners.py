#!/usr/bin/env python3
"""Seed business owners used by stakeholder alerting."""

from __future__ import annotations
from _bootstrap import bootstrap  # noqa: E402

bootstrap()

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

DEFAULT = ROOT / "config" / "business-owners.yaml"


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed business owners")
    parser.add_argument("--file", type=Path, default=DEFAULT)
    parser.add_argument("--name", default=None)
    parser.add_argument("--email", default=None)
    parser.add_argument("--role", default=None)
    args = parser.parse_args()

    owners = []
    if args.name:
        owners.append({"name": args.name, "email": args.email, "role": args.role})
    elif args.file.is_file():
        try:
            import yaml
        except ImportError as exc:
            raise SystemExit("PyYAML is required") from exc
        payload = yaml.safe_load(args.file.read_text(encoding="utf-8")) or {}
        owners = payload.get("owners") or []
    if not owners:
        raise SystemExit("no owners provided")

    from sqlalchemy import select

    from db.connection.session import SessionLocal, init_db
    from db.models.business_owner import BusinessOwner
    from db.repositories.intelligence_repository import IntelligenceRepository

    init_db()
    session = SessionLocal()
    try:
        repo = IntelligenceRepository(session)
        for item in owners:
            name = item.get("name")
            if not name:
                continue
            existing = session.execute(select(BusinessOwner).where(BusinessOwner.name == name)).scalar_one_or_none()
            fields = {
                "email": item.get("email"),
                "role": item.get("role"),
                "department": item.get("department"),
                "escalation_contact": item.get("escalation_contact"),
            }
            if existing:
                for key, value in fields.items():
                    if value is not None:
                        setattr(existing, key, value)
                print(f"updated {name}")
            else:
                repo.create_owner(name=name, **{k: v for k, v in fields.items() if v is not None})
                print(f"seeded {name}")
        session.commit()
    finally:
        session.close()


if __name__ == "__main__":
    main()
