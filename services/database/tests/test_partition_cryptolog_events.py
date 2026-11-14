"""Partitioned cryptolog_events: the conversion loses nothing, the months
land where they belong, and the uniqueness semantics change is the one
0130 already taught the models to declare."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
for extra in ("services/database", "shared/shared_models", "shared/shared_config",
              "shared/shared_logging", "services/api"):
    if str(ROOT / extra) not in sys.path:
        sys.path.insert(0, str(ROOT / extra))

pgserver = pytest.importorskip("pgserver",
                               reason="pgserver is not installed: no PostgreSQL to partition")
MIGRATIONS = ROOT / "services" / "database" / "migrations"


class Harness:
    def __init__(self, engine, env):
        self.engine = engine
        self.env = env

    def alembic(self, revision: str) -> None:
        proc = subprocess.run(
            [sys.executable, "-m", "alembic", "-c", "alembic.ini",
             "upgrade", revision],
            cwd=str(MIGRATIONS), env=self.env, capture_output=True, text=True)
        if proc.returncode != 0:
            pytest.fail(f"alembic upgrade {revision} failed:\n{proc.stderr[-3000:]}")


@pytest.fixture(scope="module")
def harness():
    from sqlalchemy import create_engine

    work = tempfile.mkdtemp(prefix="pg-cryptolog-part-")
    server = pgserver.get_server(work)
    uri = server.get_uri()
    server.psql("CREATE DATABASE cryptoscan;")
    host = uri.split("host=")[1]
    url = f"postgresql+psycopg2://postgres:@/cryptoscan?host={host}"
    env = dict(os.environ)
    env["DATABASE_URL"] = url
    env["PYTHONPATH"] = ":".join(
        [str(ROOT / extra) for extra in
         ("services/database", "shared/shared_models", "shared/shared_config",
          "shared/shared_logging", "services/api")] + [env.get("PYTHONPATH", "")])
    engine = create_engine(url, future=True)
    harness = Harness(engine, env)
    # Stop one migration BEFORE the conversion so the test can seed the flat
    # table and prove 0156 moves the rows, not just the schema.
    harness.alembic("0155")
    try:
        yield harness
    finally:
        engine.dispose()
        server.cleanup()


def _seed_flat(engine, rows):
    from sqlalchemy import text

    with engine.begin() as conn:
        for event_id, created in rows:
            conn.execute(text(
                "INSERT INTO cryptolog_events (id, created_at, updated_at,"
                " tenant_id, event_id, partition_id, event_hash, event_type,"
                " category, logging_kind, severity, investigation_status, telemetry_mode,"
                " asset_id, source, cryptographic_context, observation,"
                " evidence, relationships, processing, attributes)"
                " VALUES (md5(random()::text || :e), :c, :c, 't1', :e,"
                " 'p1', 'h', 'TLS_HANDSHAKE', 'NETWORK', 'ACTIVITY', 'INFO',"
                " 'OPEN', 'EVENT', 'a1', '{}', '{}', '{}', '{}', '{}', '{}', '{}')"),
                {"e": event_id, "c": created})


def _count(engine, table="cryptolog_events"):
    from sqlalchemy import text

    with engine.connect() as conn:
        return conn.execute(text(f"SELECT count(*) FROM {table}")).scalar()


class TestConversion:

    def test_the_conversion_moves_every_row_into_a_partition(self, harness):
        from sqlalchemy import text

        _seed_flat(harness.engine, [
            ("evt-a", "2026-08-14T10:00:00+00:00"),
            ("evt-b", "2026-09-02T10:00:00+00:00"),
            ("evt-c", "2026-10-01T10:00:00+00:00"),
            ("evt-d", "2026-10-15T10:00:00+00:00"),
        ])
        assert _count(harness.engine) == 4
        harness.alembic("head")
        assert _count(harness.engine) == 4, (
            "partitioning that loses rows is an outage, not a migration")

        with harness.engine.connect() as conn:
            relkind = conn.execute(text(
                "SELECT relkind FROM pg_class WHERE oid ="
                " to_regclass('cryptolog_events')")).scalar()
            assert relkind == "p", "the parent is a partitioned table"
            placed = conn.execute(text(
                "SELECT tableoid::regclass::text, event_id FROM cryptolog_events"
                " ORDER BY event_id")).all()
        by_event = {row[1]: row[0] for row in placed}
        assert by_event["evt-a"].startswith("cryptolog_events_y2026m08")
        assert by_event["evt-b"].startswith("cryptolog_events_y2026m09")
        assert by_event["evt-c"].startswith("cryptolog_events_y2026m10")
        assert by_event["evt-d"].startswith("cryptolog_events_y2026m10"), (
            "same month, same partition — the month is the unit of disposal")


class TestRunningSystem:

    def test_new_events_land_in_this_months_partition(self, harness):
        _seed_flat(harness.engine, [("evt-now", "2026-10-20T10:00:00+00:00")])
        from sqlalchemy import text

        with harness.engine.connect() as conn:
            partition = conn.execute(text(
                "SELECT tableoid::regclass::text FROM cryptolog_events"
                " WHERE event_id = 'evt-now'")).scalar()
        assert partition.startswith("cryptolog_events_y2026m10")

    def test_ensure_creates_future_months_and_is_idempotent(self, harness):
        from datetime import datetime, timezone

        from db import partitions

        future = datetime(2028, 3, 15, tzinfo=timezone.utc)
        with harness.engine.begin() as conn:
            created = partitions.ensure(conn, now=future,
                                        table="cryptolog_events")
            assert any("y2028m03" in name for name in created), (
                "the maintenance path provisions the stream table's months")
            again = partitions.ensure(conn, now=future,
                                      table="cryptolog_events")
            assert again == [], "ensure is idempotent"

    def test_no_default_partition_rejects_an_unprovisioned_month(self, harness):
        from sqlalchemy import text
        from sqlalchemy.exc import IntegrityError, ProgrammingError

        with pytest.raises((ProgrammingError, IntegrityError)):
            with harness.engine.begin() as conn:
                conn.execute(text(
                    "INSERT INTO cryptolog_events (id, created_at, updated_at,"
                    " tenant_id, event_id, partition_id, event_hash, event_type,"
                    " category, logging_kind, severity, investigation_status, telemetry_mode,"
                    " asset_id, source, cryptographic_context, observation,"
                    " evidence, relationships, processing, attributes)"
                    " VALUES (md5(random()::text), '2030-01-15T10:00:00+00:00',"
                    " now(), 't1', 'evt-future', 'p1', 'h', 'X', 'NETWORK',"
                    " 'ACTIVITY', 'INFO', 'OPEN', 'EVENT', 'a1', '{}', '{}', '{}',"
                    " '{}', '{}', '{}', '{}')"))

    def test_event_id_uniqueness_is_per_month_and_named_honestly(self, harness):
        from sqlalchemy import text
        from sqlalchemy.exc import IntegrityError

        _seed_flat(harness.engine, [
            ("evt-dup", "2026-10-21T10:00:00+00:00"),
            ("evt-dup", "2026-09-21T10:00:00+00:00"),  # other month: allowed
        ])
        with pytest.raises(IntegrityError):
            with harness.engine.begin() as conn:
                conn.execute(text(
                    "INSERT INTO cryptolog_events (id, created_at, updated_at,"
                    " tenant_id, event_id, partition_id, event_hash, event_type,"
                    " category, logging_kind, severity, investigation_status, telemetry_mode,"
                    " asset_id, source, cryptographic_context, observation,"
                    " evidence, relationships, processing, attributes)"
                    " VALUES (md5(random()::text), '2026-10-21T10:00:00+00:00',"
                    " now(), 't1', 'evt-dup', 'p1', 'h', 'X', 'NETWORK',"
                    " 'ACTIVITY', 'INFO', 'OPEN', 'EVENT', 'a1', '{}', '{}', '{}', '{}',"
                    " '{}', '{}', '{}')"))
