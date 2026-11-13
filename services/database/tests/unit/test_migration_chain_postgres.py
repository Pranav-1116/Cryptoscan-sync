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
    # The child runs from services/database, not the pytest invocation's cwd.
    # Give it absolute package roots so migration backfills can import shared
    # models and service packages even when the parent used relative PYTHONPATH.
    packages = [str(path) for base in (ROOT / "services", ROOT / "shared")
                for path in base.iterdir() if path.is_dir()]
    env = dict(os.environ, DATABASE_URL=PG_URL,
               PYTHONPATH=os.pathsep.join(packages))
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


def test_os_runtime_orm_matches_migrated_schema(migrated):
    """0146 must let the actual repository insert UUID runtime rows."""
    from sqlalchemy.orm import Session
    from db.models.os_intelligence import (OSAssetCertificate, OSRuntimeEvent,
                                           OSRuntimeSession)

    inspector = sa.inspect(migrated)
    for table in ("os_certificates", "os_runtime_sessions", "os_runtime_events"):
        cols = {c["name"]: c for c in inspector.get_columns(table)}
        assert isinstance(cols["id"]["type"], sa.String)
        assert "updated_at" in cols and not cols["updated_at"]["nullable"]
        assert cols["tenant_id"]["nullable"], "platform-estate rows remain possible"
    indexes = inspector.get_indexes("os_assets")
    assert any(i["name"] == "ix_os_assets_tenant_asset" and not i["unique"]
               for i in indexes)

    with migrated.connect() as conn:
        trans = conn.begin()
        try:
            with Session(conn) as session:
                session.add(OSAssetCertificate(
                    tenant_id="migration-test", certificate_id="cert-migration-test",
                    collection_id="collection-test", asset_id="host-test",
                    subject="test", issuer="test", evidence_class="observed",
                    collected_at=sa.func.now()))
                session.add(OSRuntimeSession(
                    tenant_id="migration-test", session_id="runtime-migration-test",
                    asset_id="host-test", collection_profile="test",
                    collected_at=sa.func.now()))
                session.add(OSRuntimeSession(
                    tenant_id=None, session_id="runtime-platform-test",
                    asset_id="host-test", collection_profile="test",
                    collected_at=sa.func.now()))
                session.add(OSRuntimeEvent(
                    tenant_id="migration-test", session_id="runtime-migration-test",
                    asset_id="host-test", event_id="runtime-event-test",
                    operation_category="hash_operation",
                    collected_at=sa.func.now()))
                session.flush()
                assert session.query(OSAssetCertificate).count() == 1
                assert session.query(OSRuntimeSession).count() == 2
                assert session.query(OSRuntimeEvent).count() == 1
        finally:
            trans.rollback()


def test_upgrade_legacy_os_rows_preserves_evidence(migrated):
    """An already-applied 0145 may have numeric OS IDs and recorded rows."""
    down = _alembic("downgrade", "0145")
    assert down.returncode == 0, down.stderr[-2000:]
    with migrated.begin() as conn:
        conn.execute(sa.text(
            "INSERT INTO os_certificates (created_at, tenant_id, certificate_id, "
            "collection_id, asset_id, subject, issuer, evidence_class, collected_at) "
            "VALUES (now(), 'migration-test', 'legacy-cert', 'legacy-collection', "
            "'host-test', 'test', 'test', 'observed', now())"))
        conn.execute(sa.text(
            "INSERT INTO os_runtime_sessions (created_at, tenant_id, session_id, "
            "asset_id, collection_profile, collected_at) VALUES "
            "(now(), 'migration-test', 'legacy-session', 'host-test', 'test', now())"))
        conn.execute(sa.text(
            "INSERT INTO os_runtime_events (created_at, tenant_id, session_id, "
            "asset_id, event_id, operation_category, collected_at) VALUES "
            "(now(), 'migration-test', 'legacy-session', 'host-test', "
            "'legacy-event', 'hash_operation', now())"))
    up = _alembic("upgrade", "head")
    assert up.returncode == 0, up.stderr[-2000:]
    with migrated.begin() as conn:
        for table in ("os_certificates", "os_runtime_sessions", "os_runtime_events"):
            row = conn.execute(sa.text(
                f"SELECT id, updated_at FROM {table} WHERE tenant_id='migration-test'"
            )).one()
            assert str(row.id).isdigit() and row.updated_at is not None
            conn.execute(sa.text(
                f"DELETE FROM {table} WHERE tenant_id='migration-test'"))


def test_downgrade_one_and_back(migrated):
    down = _alembic("downgrade", "-1")
    assert down.returncode == 0, down.stderr[-2000:]
    up = _alembic("upgrade", "head")
    assert up.returncode == 0, up.stderr[-2000:]


def test_new_tables_have_forced_rls_and_tenants_cannot_write_platform_rows(migrated):
    """Direct SQL as the non-bypass tenant role tests the database boundary."""
    from db.rls import enforcement

    with migrated.connect() as conn:
        report = enforcement(conn)
        assert report["tables_with_rls_enabled"] == report["tenant_tables"]
        assert report["tables_with_rls_forced"] == report["tenant_tables"]
        assert report["policies"] >= report["tenant_tables"] * 4
        conn.rollback()  # catalog reads began an implicit transaction

        transaction = conn.begin()
        insert = sa.text(
            "INSERT INTO os_runtime_sessions "
            "(id, tenant_id, session_id, asset_id, collection_profile, "
            "created_at, updated_at, collected_at) "
            "VALUES (:id, :tenant, :id, 'host-rls', 'test', now(), now(), now())")
        try:
            for ident, tenant in (("rls-alpha", "alpha"),
                                  ("rls-beta", "beta"),
                                  ("rls-platform", None)):
                conn.execute(insert, {"id": ident, "tenant": tenant})
            conn.exec_driver_sql("SET LOCAL ROLE cryptoscan_tenant")
            conn.exec_driver_sql(
                "SELECT set_config('cryptoscan.tenant_id', 'alpha', true)")
            visible = conn.execute(sa.text(
                "SELECT id FROM os_runtime_sessions "
                "WHERE id LIKE :prefix ORDER BY id"),
                {"prefix": "rls-%"}).scalars().all()
            assert visible == ["rls-alpha", "rls-platform"]
            for ident, tenant in (("rls-foreign", "beta"),
                                  ("rls-unowned", None)):
                with pytest.raises(sa.exc.DBAPIError), conn.begin_nested():
                    conn.execute(insert, {"id": ident, "tenant": tenant})
            assert conn.exec_driver_sql(
                "UPDATE os_runtime_sessions SET notes='[]' "
                "WHERE id='rls-platform'").rowcount == 0
            assert conn.exec_driver_sql(
                "DELETE FROM os_runtime_sessions "
                "WHERE id='rls-platform'").rowcount == 0
        finally:
            transaction.rollback()


def test_performance_metric_identity_is_tenant_local_and_downgrade_refuses_collision(migrated):
    indexes = {row["name"]: row for row in sa.inspect(migrated).get_indexes("performance_metrics")}
    assert indexes["uq_performance_metrics_tenant_metric_id"]["unique"]
    assert indexes["uq_performance_metrics_platform_metric_id"]["unique"]
    insert = sa.text("""INSERT INTO performance_metrics
        (id, tenant_id, metric_id, asset_id, metric_name, metric_type,
         metric_value, unit, source_id, observed_at, quality_status,
         created_at, updated_at)
        VALUES (:id, :tenant, 'shared-source-id', 'app:pay',
                'crypto.tls_handshake_ms', 'gauge', 20, 'ms', 'bank-exporter',
                now(), 'valid', now(), now())""")
    try:
        with migrated.begin() as conn:
            for ident, tenant in (("metric-scope-a", "bank-a"),
                                  ("metric-scope-b", "bank-b"),
                                  ("metric-scope-platform", None)):
                conn.execute(insert, {"id": ident, "tenant": tenant})
            for ident, tenant in (("metric-scope-duplicate-a", "bank-a"),
                                  ("metric-scope-duplicate-platform", None)):
                with pytest.raises(sa.exc.IntegrityError), conn.begin_nested():
                    conn.execute(insert, {"id": ident, "tenant": tenant})
        down = _alembic("downgrade", "0148")
        assert down.returncode != 0 and "downgrade blocked" in down.stderr
        with migrated.connect() as conn:
            from alembic.config import Config
            from alembic.script import ScriptDirectory
            head = ScriptDirectory.from_config(
                Config(str(DB_DIR / "migrations/alembic.ini"))).get_current_head()
            assert conn.scalar(sa.text("SELECT version_num FROM alembic_version")) == head
            assert conn.scalar(sa.text(
                "SELECT count(*) FROM performance_metrics "
                "WHERE metric_id='shared-source-id'")) == 3
    finally:
        with migrated.begin() as conn:
            conn.execute(sa.text(
                "DELETE FROM performance_metrics WHERE id LIKE 'metric-scope-%'"))


def test_capture_receipts_are_tenant_scoped_and_protected_from_downgrade(migrated):
    table = "performance_capture_receipts"
    indexes = {row["name"]: row for row in sa.inspect(migrated).get_indexes(table)}
    assert indexes["uq_performance_capture_tenant_receipt"]["unique"]
    assert indexes["uq_performance_capture_platform_receipt"]["unique"]
    insert = sa.text(f"""INSERT INTO {table}
        (id, tenant_id, receipt_id, asset_ref, source_id, source_type,
         observed_at, payload_sha256, authorization_ref, provenance_state,
         accepted_count, duplicate_count, rejected_count, created_at, updated_at)
        VALUES (:id, :tenant, :receipt, 'app:pay', 'node-1', 'node_exporter',
                now(), :digest, 'fixture-change', 'UNVERIFIED_CAPTURE_ORIGIN',
                1, 0, 0, now(), now())""")
    try:
        with migrated.begin() as conn:
            for ident, tenant in (("receipt-a", "bank-a"),
                                  ("receipt-b", "bank-b"),
                                  ("receipt-platform", None)):
                conn.execute(insert, {"id": ident, "tenant": tenant,
                                      "receipt": "a" * 64, "digest": "b" * 64})
            for ident, tenant in (("receipt-duplicate-a", "bank-a"),
                                  ("receipt-duplicate-platform", None)):
                with pytest.raises(sa.exc.IntegrityError), conn.begin_nested():
                    conn.execute(insert, {"id": ident, "tenant": tenant,
                                          "receipt": "a" * 64, "digest": "b" * 64})
        down = _alembic("downgrade", "0149")
        assert down.returncode != 0 and "downgrade blocked" in down.stderr
        with migrated.connect() as conn:
            assert conn.scalar(sa.text("SELECT version_num FROM alembic_version")) == "0150"
            assert conn.scalar(sa.text(f"SELECT count(*) FROM {table}")) == 3
    finally:
        with migrated.begin() as conn:
            conn.execute(sa.text(f"DELETE FROM {table} WHERE id LIKE 'receipt-%'"))


def test_system_names_are_estate_local_including_platform_null(migrated):
    statement = sa.text("""INSERT INTO systems (id, name, tenant_id, created_at, updated_at)
        VALUES (:id, 'Shared business name', :tenant, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)""")
    with migrated.connect() as connection, connection.begin():
        for ident, tenant in (("name-platform", None), ("name-a", "a"), ("name-b", "b")):
            connection.execute(statement, {"id":ident, "tenant":tenant})
        for ident, tenant in (("duplicate-platform", None), ("duplicate-a", "a")):
            with pytest.raises(sa.exc.IntegrityError), connection.begin_nested():
                connection.execute(statement, {"id":ident, "tenant":tenant})
        connection.rollback()


def test_0107_downgrade_refuses_duplicate_names_without_changing_data(migrated):
    ids = ("downgrade-owned-a", "downgrade-owned-b")
    try:
        with migrated.begin() as connection:
            for ident in ids:
                connection.execute(sa.text("""INSERT INTO systems (id, name, tenant_id, created_at, updated_at)
                    VALUES (:id, '0107 duplicate downgrade fixture', :id, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"""), {"id":ident})
        result = _alembic("downgrade", "0106")
        assert result.returncode != 0 and "downgrade blocked" in result.stderr
        with migrated.connect() as connection:
            # The entire multi-revision downgrade is transactional on PG:
            # refusing at 0107 leaves the original head, not a half-migrated DB.
            from alembic.config import Config
            from alembic.script import ScriptDirectory
            config = Config(str(DB_DIR / "migrations/alembic.ini"))
            assert connection.execute(sa.text(
                "select version_num from alembic_version")).scalar_one() == \
                ScriptDirectory.from_config(config).get_current_head()
            assert connection.execute(sa.text("select count(*) from systems where id in ('downgrade-owned-a','downgrade-owned-b')")).scalar_one() == 2
        indexes = {index["name"] for index in sa.inspect(migrated).get_indexes("systems")}
        assert {"uq_systems_platform_name", "uq_systems_tenant_name"} <= indexes
    finally:
        with migrated.begin() as connection:
            connection.execute(sa.text("DELETE FROM systems WHERE id in ('downgrade-owned-a','downgrade-owned-b')"))


def test_0107_upgrade_preserves_an_existing_system_and_its_metadata(migrated):
    down = _alembic("downgrade", "0106")
    assert down.returncode == 0, down.stderr[-1500:]
    try:
        with migrated.begin() as connection:
            connection.execute(sa.text("""INSERT INTO systems (id, name, tenant_id, owner, extra, created_at, updated_at)
                VALUES ('upgrade-owned-a', '0107 preexisting service', 'a', 'preserve-owner',
                        '{"preserve":"metadata"}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"""))
        up = _alembic("upgrade", "head")
        assert up.returncode == 0, up.stderr[-1500:]
        with migrated.begin() as connection:
            row = connection.execute(sa.text("SELECT owner, extra FROM systems WHERE id='upgrade-owned-a'")).one()
            assert row.owner == "preserve-owner" and row.extra == {"preserve":"metadata"}
            connection.execute(sa.text("""INSERT INTO systems (id, name, tenant_id, created_at, updated_at)
                VALUES ('upgrade-owned-b', '0107 preexisting service', 'b', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"""))
    finally:
        with migrated.begin() as connection:
            connection.execute(sa.text("DELETE FROM systems WHERE id in ('upgrade-owned-a','upgrade-owned-b')"))
        restored = _alembic("upgrade", "head")
        assert restored.returncode == 0, restored.stderr[-1500:]


def test_0107_busy_database_fails_transactionally_and_can_be_retried(migrated):
    down = _alembic("downgrade", "0106")
    assert down.returncode == 0, down.stderr[-1500:]
    try:
        with migrated.begin() as connection:
            connection.execute(sa.text("""INSERT INTO systems (id, name, created_at, updated_at)
                VALUES ('lock-owned', '0107 busy database fixture', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"""))
        with migrated.connect() as holder, holder.begin():
            holder.execute(sa.text("SELECT id FROM systems WHERE id='lock-owned' FOR UPDATE"))
            up = _alembic("upgrade", "head")
            assert up.returncode != 0 and "lock timeout" in up.stderr
            holder.rollback()
        with migrated.connect() as connection:
            assert connection.execute(sa.text("SELECT version_num FROM alembic_version")).scalar_one() == "0106"
        indexes = {index["name"] for index in sa.inspect(migrated).get_indexes("systems")}
        assert "uq_systems_tenant_name" not in indexes and "uq_systems_platform_name" not in indexes
        assert any(constraint["name"] == "uq_systems_name" for constraint in sa.inspect(migrated).get_unique_constraints("systems"))
    finally:
        with migrated.begin() as connection:
            connection.execute(sa.text("DELETE FROM systems WHERE id='lock-owned'"))
        restored = _alembic("upgrade", "head")
        assert restored.returncode == 0, restored.stderr[-1500:]
