#!/usr/bin/env python3
"""Prove production RLS on a separately provisioned role in a disposable CI DB.

Never run against a customer database. The caller must opt in and supply the
exact CI service URL; this creates and removes only its own named test database
and role. No password, token or tenant data is written to the receipt.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if os.getenv("CRYPTOSCAN_CI_DISPOSABLE_DB") != "1":
        raise RuntimeError("Refused outside an explicitly disposable CI database")
    base = make_url(os.environ.get("CRYPTOSCAN_TEST_DATABASE_URL", ""))
    port_text = os.getenv("CRYPTOSCAN_CI_POSTGRES_PORT", "5432")
    if not port_text.isdigit() or not 1024 <= int(port_text) <= 65535:
        raise RuntimeError("Refused: invalid disposable CI PostgreSQL port")
    if (base.get_backend_name() != "postgresql" or base.host != "127.0.0.1" or base.port != int(port_text)
            or base.username != "cryptoscan" or base.database != "cs_ci_parity"):
        raise RuntimeError("Refused: expected the disposable PostgreSQL CI service at cs_ci_parity")
    target = ROOT / "services" / "database" / "migrations"
    name = "cs_ci_rls_" + secrets.token_hex(5)
    role = "cs_ci_runtime_" + secrets.token_hex(5)
    runtime_secret = secrets.token_urlsafe(36)
    admin = create_engine(base, pool_pre_ping=True)
    test_engine = None
    app_engine = None
    created_db = created_role = False
    output = Path(args.output)
    if output.exists():
        raise RuntimeError("Refused: the CI RLS receipt already exists")
    try:
        with admin.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            assert conn.scalar(text("SELECT count(*) FROM pg_database WHERE datname=:name"), {"name": name}) == 0
            conn.exec_driver_sql('CREATE DATABASE "' + name + '"')
            created_db = True
        url = base.set(database=name)
        env = {**os.environ, "DATABASE_URL": url.render_as_string(hide_password=False), "ENVIRONMENT": "test"}
        env["PYTHONPATH"] = os.pathsep.join(str(path) for area in ("services", "shared")
                                             for path in (ROOT / area).iterdir() if path.is_dir())
        upgrade = subprocess.run(
            [sys.executable, "-m", "alembic", "-c", "alembic.ini", "upgrade", "head"],
            cwd=target, env=env, capture_output=True, text=True, timeout=300,
        )
        if upgrade.returncode:
            raise RuntimeError("Alembic failed on disposable DB: " + (upgrade.stderr or upgrade.stdout)[-400:])
        test_engine = create_engine(url, pool_pre_ping=True)
        from db.connection.session import init_db
        from db.models.estate_schedule import EstateSchedule
        from db.rls import enforcement

        previous_env = os.environ.get("ENVIRONMENT")
        os.environ["ENVIRONMENT"] = "production"
        try:
            try:
                init_db(test_engine)
            except RuntimeError as exc:
                if "non-superuser, NOBYPASSRLS" not in str(exc):
                    raise
            else:
                raise RuntimeError("Production startup accepted the migration superuser")
        finally:
            if previous_env is None:
                os.environ.pop("ENVIRONMENT", None)
            else:
                os.environ["ENVIRONMENT"] = previous_env

        with admin.begin() as conn:
            # The role and secret exist only in this disposable service. Bind the
            # password as a SQL value rather than echoing it into a shell command.
            conn.execute(text('CREATE ROLE "' + role + '" LOGIN NOSUPERUSER NOBYPASSRLS '
                              'NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD :secret'),
                         {"secret": runtime_secret})
            created_role = True
        with test_engine.begin() as conn:
            conn.exec_driver_sql(f'GRANT CONNECT ON DATABASE "{name}" TO "{role}"')
            conn.exec_driver_sql(f'GRANT USAGE ON SCHEMA public TO "{role}"')
            conn.exec_driver_sql(f'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO "{role}"')
            conn.exec_driver_sql(f'GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO "{role}"')
        app_engine = create_engine(url.set(username=role, password=runtime_secret), pool_pre_ping=True)
        previous_env = os.environ.get("ENVIRONMENT")
        os.environ["ENVIRONMENT"] = "production"
        try:
            init_db(app_engine)
        finally:
            if previous_env is None:
                os.environ.pop("ENVIRONMENT", None)
            else:
                os.environ["ENVIRONMENT"] = previous_env
        with app_engine.connect() as conn:
            report = enforcement(conn)
            total = report["tenant_tables"]
            if (not report["binds_this_role"] or report["superuser"] or report["bypassrls"]
                    or total < 100 or report["tables_with_rls_forced"] != total
                    or report["tables_with_rls_enabled"] != total):
                raise RuntimeError("Production runtime role does not bind every tenant table")
        a = "11111111-1111-1111-1111-111111111111"
        b = "22222222-2222-2222-2222-222222222222"
        with Session(test_engine) as session:
            when = datetime.now(timezone.utc) + timedelta(hours=1)
            session.add_all([
                EstateSchedule(name="tenant-a", tenant_id=a, planes='["STATIC"]',
                               interval_minutes=60, next_run_at=when),
                EstateSchedule(name="tenant-b", tenant_id=b, planes='["STATIC"]',
                               interval_minutes=60, next_run_at=when),
            ])
            session.commit()
        with app_engine.connect() as conn:
            unbound = conn.scalar(text("SELECT count(*) FROM estate_schedules WHERE tenant_id IS NOT NULL"))
            conn.execute(text("SELECT set_config('cryptoscan.tenant_id', :tenant, true)"), {"tenant": a})
            visible = conn.execute(text("SELECT name FROM estate_schedules WHERE tenant_id IS NOT NULL")).scalars().all()
        if unbound != 0 or visible != ["tenant-a"]:
            raise RuntimeError("Runtime RLS leaked a tenant row or refused the selected tenant")
        with test_engine.connect() as conn:
            head = conn.scalar(text("SELECT version_num FROM alembic_version"))
        with admin.connect() as conn:
            major = int(conn.scalar(text("SHOW server_version_num"))) // 10000
        receipt = {"schema": "cryptoscan.ci-runtime-rls/1", "postgres_major": major,
                   "migration_head": head, "superuser_runtime_refused": True,
                   "non_superuser_runtime_accepted": True, "tenant_tables_forced": total,
                   "unbound_tenant_rows": unbound, "selected_tenant_rows": len(visible),
                   "site_qualified": False, "scope": "DISPOSABLE_CI_SERVICE_ONLY"}
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8") as handle:
            json.dump(receipt, handle, sort_keys=True)
            handle.write("\n")
        print(f"CI runtime RLS: PASS — PostgreSQL {receipt['postgres_major']}, migration {head}, {total} forced tables")
        return 0
    finally:
        if app_engine is not None:
            app_engine.dispose()
        if test_engine is not None:
            test_engine.dispose()
        if created_db:
            with admin.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
                conn.exec_driver_sql('DROP DATABASE IF EXISTS "' + name + '"')
        if created_role:
            with admin.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
                conn.exec_driver_sql('DROP ROLE IF EXISTS "' + role + '"')
        admin.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
