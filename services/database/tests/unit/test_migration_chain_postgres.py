"""The Alembic chain applies on a real PostgreSQL, and matches the models.

This is the test that was missing: dev and unit tests build the schema with
``create_all`` from the models, so a migration that only works on SQLite (or
only works when the previous migrations had already been patched by hand)
was never noticed until the first real Postgres install.

Runs only when a PostgreSQL is reachable (``CRYPTOSCAN_TEST_PG_URL`` or the
staging server on 127.0.0.1:55432); skipped otherwise. deploy/staging/
staging-up.sh starts one.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
import sqlalchemy as sa

DB_DIR = Path(__file__).resolve().parents[2]  # services/database
ROOT = DB_DIR.parents[1]

PG_URL = os.environ.get("CRYPTOSCAN_TEST_PG_URL") or \
    "postgresql://cryptoscan:staging-only-pw@127.0.0.1:55432/cryptoscan_migration_test"

pytestmark = pytest.mark.live  # needs a real server; excluded from the hermetic gate


def _pg_available() -> bool:
    try:
        admin = PG_URL.rsplit("/", 1)[0] + "/postgres"
        eng = sa.create_engine(admin, isolation_level="AUTOCOMMIT")
        with eng.connect() as conn:
            name = PG_URL.rsplit("/", 1)[1]
            conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{name}"'))
            conn.execute(sa.text(f'CREATE DATABASE "{name}"'))
        return True
    except Exception:
        return False


def _alembic(*args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, DATABASE_URL=PG_URL)
    return subprocess.run([sys.executable, "-m", "alembic", "-c", "migrations/alembic.ini", *args],
                          cwd=DB_DIR, env=env, capture_output=True, text=True, timeout=600)


@pytest.fixture(scope="module")
def migrated():
    if not _pg_available():
        pytest.skip("no PostgreSQL reachable (start deploy/staging/staging-up.sh)")
    result = _alembic("upgrade", "head")
    assert result.returncode == 0, result.stderr[-3000:]
    yield sa.create_engine(PG_URL)


def test_chain_applies_on_fresh_postgres(migrated):
    with migrated.connect() as conn:
        head = conn.execute(sa.text("select version_num from alembic_version")).scalar()
    assert head, "alembic_version is empty"


def test_no_uuid_columns_remain_where_models_say_string(migrated):
    with migrated.connect() as conn:
        rows = conn.execute(sa.text(
            "select table_name, column_name from information_schema.columns "
            "where table_schema='public' and data_type='uuid'")).fetchall()
    assert rows == [], f"uuid-typed columns the ORM reads as str: {rows}"


def test_migrated_schema_matches_the_models(migrated):
    import db.models  # noqa: F401 — register every table
    from db.connection.session import Base

    insp = sa.inspect(migrated)
    db_tables = set(insp.get_table_names()) - {"alembic_version"}
    model_tables = set(Base.metadata.tables)
    assert model_tables - db_tables == set(), "tables in models but not created by migrations"
    missing_columns = []
    for name, table in Base.metadata.tables.items():
        cols = {c["name"] for c in insp.get_columns(name)}
        for col in table.columns:
            if col.name not in cols:
                missing_columns.append(f"{name}.{col.name}")
    assert missing_columns == [], missing_columns


def test_downgrade_one_and_back(migrated):
    down = _alembic("downgrade", "-1")
    assert down.returncode == 0, down.stderr[-2000:]
    up = _alembic("upgrade", "head")
    assert up.returncode == 0, up.stderr[-2000:]
