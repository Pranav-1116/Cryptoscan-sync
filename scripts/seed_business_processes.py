#!/usr/bin/env python3
"""Seed business processes used by impact scoring."""

from __future__ import annotations
from _bootstrap import bootstrap  # noqa: E402

bootstrap()

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

DEFAULT = ROOT / "config" / "business-processes.yaml"


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed business processes")
    parser.add_argument("--file", type=Path, default=DEFAULT)
    args = parser.parse_args()
    try:
        import yaml
    except ImportError as exc:
        raise SystemExit("PyYAML is required") from exc

    payload = yaml.safe_load(args.file.read_text(encoding="utf-8")) or {}
    processes = payload.get("processes") or []
    if not processes:
        raise SystemExit(f"no processes in {args.file}")

    from sqlalchemy import select

    from db.connection.session import SessionLocal, init_db
    from db.models.business_process import BusinessProcess
    from db.repositories.intelligence_repository import IntelligenceRepository

    init_db()
    session = SessionLocal()
    try:
        repo = IntelligenceRepository(session)
        for item in processes:
            name = item.get("name")
            if not name:
                continue
            existing = session.execute(select(BusinessProcess).where(BusinessProcess.name == name)).scalar_one_or_none()
            fields = {
                "description": item.get("description"),
                "process_type": item.get("process_type"),
                "revenue_daily": float(item.get("revenue_daily") or 0),
                "customer_count": int(item.get("customer_count") or 0),
                "sla_uptime": item.get("sla_uptime"),
                "executive_sponsor": item.get("executive_sponsor"),
                "data_classifications": item.get("data_classifications"),
            }
            if existing:
                for key, value in fields.items():
                    if value is not None:
                        setattr(existing, key, value)
                print(f"updated {name}")
            else:
                repo.create_process(name=name, **{k: v for k, v in fields.items() if v is not None})
                print(f"seeded {name}")
        session.commit()
    finally:
        session.close()


if __name__ == "__main__":
    main()
