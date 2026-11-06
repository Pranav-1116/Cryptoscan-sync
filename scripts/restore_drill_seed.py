#!/usr/bin/env python3
"""Seed distinguishable rows only in the disposable CI restore-drill database.

This is not a bank-estate seeder. It refuses every URL except the explicitly
marked localhost GitHub service, and never stores a usable login credential.
"""
from __future__ import annotations

import os
from sqlalchemy import create_engine, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session


def seed(engine) -> None:
    from db.models.tenant import Tenant
    from db.models.user import User

    with Session(engine) as session:
        if session.scalar(select(Tenant.id).where(Tenant.slug == "restore-drill-ci-only")):
            raise RuntimeError("Disposable restore drill source was already seeded")
        session.add(Tenant(name="CI restore drill only", slug="restore-drill-ci-only"))
        session.add(User(username="restore_drill_ci_only",
                         password_hash="INVALID_TEST_ONLY_NEVER_AUTHENTICATES",
                         roles="viewer", is_active=False))
        session.commit()


def main() -> int:
    if os.environ.get("CRYPTOSCAN_CI_DISPOSABLE_DB") != "1":
        raise RuntimeError("Refused outside an explicitly disposable CI database")
    port_text = os.environ.get("CRYPTOSCAN_CI_POSTGRES_PORT", "5432")
    if not port_text.isdigit() or not 1024 <= int(port_text) <= 65535:
        raise RuntimeError("Refused: invalid disposable CI PostgreSQL port")
    url = make_url(os.environ.get("DATABASE_URL", ""))
    if (url.get_backend_name() != "postgresql" or url.host not in {"localhost", "127.0.0.1"}
            or url.port != int(port_text) or url.database != "cryptoscan" or url.username != "drill"):
        raise RuntimeError("Refused: expected the localhost restore-drill CI service")
    target = make_url(os.environ.get("CRYPTOSCAN_RESTORE_TARGET_DB", ""))
    if (target.get_backend_name() != "postgresql" or target.host != url.host
            or target.port != url.port or target.database != "restore_drill"):
        raise RuntimeError("Refused: expected a separate disposable recovery database")
    engine = create_engine(url)
    try:
        seed(engine)
    finally:
        engine.dispose()
    print("Disposable restore-drill source seeded with one disabled user and one tenant")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
