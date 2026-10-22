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



def _resolve_pg_url() -> str:
    """Explicit CRYPTOSCAN_TEST_PG_URL → embedded/CI server from db.testing → the staging compose default."""
    explicit = os.environ.get("CRYPTOSCAN_TEST_PG_URL")
    if explicit:
        return explicit
    try:
        from db.testing import postgres_url

        base = postgres_url()
    except Exception:
        base = None
    if base:
        from sqlalchemy.engine import make_url

        return make_url(base).set(database="cryptoscan_migration_test").render_as_string(hide_password=False)
    return "postgresql://cryptoscan:staging-only-pw@127.0.0.1:55432/cryptoscan_migration_test"


PG_URL = _resolve_pg_url()

pytestmark = pytest.mark.live  # needs a real server; excluded from the hermetic gate


def _pg_available() -> bool:
    try:
        from sqlalchemy.engine import make_url

        url = make_url(PG_URL)
        name = url.database
        eng = sa.create_engine(url.set(database="postgres"), isolation_level="AUTOCOMMIT")
        with eng.connect() as conn:
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


@pytest.mark.live
def test_fact_identity_is_tenant_local_and_null_safe_on_postgres(migrated):
    """All inserted rows are rolled back; only the fresh migration schema is exercised."""
    columns = {col["name"]: col for col in sa.inspect(migrated).get_columns("cryptographic_facts")}
    assert columns["tenant_id"]["nullable"] is True
    indexes = sa.inspect(migrated).get_indexes("cryptographic_facts")
    assert any(index["name"] == "uq_fact_identity" and index["unique"] for index in indexes)

    insert = sa.text("""
        INSERT INTO cryptographic_facts
            (id, tenant_id, algorithm, purpose, file_path, key_size, mode)
        VALUES (:id, :tenant_id, 'RSA', 'ENCRYPTION', 'src/Keys.java', NULL, '')
    """)
    with migrated.connect() as conn, conn.begin():
        for ident, tenant in (("fact-pg-platform", None), ("fact-pg-one", "one"),
                              ("fact-pg-two", "two")):
            conn.execute(insert, {"id": ident, "tenant_id": tenant})
        for ident, tenant in (("fact-pg-duplicate-platform", None),
                              ("fact-pg-duplicate-one", "one")):
            with pytest.raises(sa.exc.IntegrityError), conn.begin_nested():
                conn.execute(insert, {"id": ident, "tenant_id": tenant})
        # The transaction is deliberately not committed, including on success.
        conn.rollback()


def test_migrated_monitor_events_accepts_long_platform_types(migrated):
    """Exercise the real VARCHAR, not SQLite's unenforced declared length."""
    from sqlalchemy.orm import Session

    from db.models.monitor import MonitorEvent
    from db.repositories.monitor_repository import MonitorRepository

    column = next(col for col in sa.inspect(migrated).get_columns("monitor_events")
                  if col["name"] == "event_type")
    assert column["type"].length == MonitorEvent.__table__.c.event_type.type.length == 120

    with migrated.connect() as connection:
        transaction = connection.begin()
        try:
            with Session(connection) as session:
                row = MonitorRepository(session).add_event(
                    target=None,
                    event_type="remediation.drift_tasks_created",
                    detail="Drift acknowledgement opened remediation tasks",
                )
                assert connection.execute(sa.text(
                    "SELECT event_type FROM monitor_events WHERE id = :id"
                ), {"id": row.id}).scalar_one() == "remediation.drift_tasks_created"
                MonitorRepository(session).add_event(
                    target=None, event_type="cascade.operational_conditions_changed"
                )
        finally:
            transaction.rollback()


def test_downgrade_one_and_back(migrated):
    down = _alembic("downgrade", "-1")
    assert down.returncode == 0, down.stderr[-2000:]
    up = _alembic("upgrade", "head")
    assert up.returncode == 0, up.stderr[-2000:]
