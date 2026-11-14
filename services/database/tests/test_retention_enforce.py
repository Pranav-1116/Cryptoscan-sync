"""Retention enforcement: dry-run performs nothing, execute archives
first and verifies, and every deletion joins the audit chain."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
for extra in ("services/database", "shared/shared_models", "shared/shared_config",
              "shared/shared_logging", "services/api"):
    if str(ROOT / extra) not in sys.path:
        sys.path.insert(0, str(ROOT / extra))

pgserver = pytest.importorskip("pgserver",
                               reason="pgserver is not installed: no PostgreSQL to enforce on")
MIGRATIONS = ROOT / "services" / "database" / "migrations"


@pytest.fixture(scope="module")
def engine():
    from sqlalchemy import create_engine

    work = tempfile.mkdtemp(prefix="pg-retention-")
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
    proc = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", "alembic.ini", "upgrade", "head"],
        cwd=str(MIGRATIONS), env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        server.cleanup()
        pytest.fail("migration chain does not reach head:\n" + proc.stderr[-3000:])
    engine = create_engine(url, future=True)
    try:
        yield engine
    finally:
        engine.dispose()
        server.cleanup()


def _seed(engine, rows):
    from sqlalchemy import text
    from sqlalchemy.orm import sessionmaker

    from db import partitions as partitioning

    # The empty-store conversion provisioned months around today; the
    # fixtures seed historical ones. Provision them (the maintenance path
    # every deployment runs) — the no-DEFAULT contract rejects months that
    # nobody provisioned, which is exactly right and not this test's fight.
    session = sessionmaker(bind=engine)()
    try:
        partitioning.ensure(session, now=NOW, ahead=2, behind=6,
                            table="cryptolog_events")
        session.commit()
    finally:
        session.close()

    with engine.begin() as conn:
        for event_id, created in rows:
            conn.execute(text(
                "INSERT INTO cryptolog_events (id, created_at, updated_at,"
                " tenant_id, event_id, partition_id, event_hash, event_type,"
                " category, logging_kind, severity, investigation_status,"
                " telemetry_mode, asset_id, source, cryptographic_context,"
                " observation, evidence, relationships, processing, attributes)"
                " VALUES (md5(random()::text || :e), :c, :c, 't1', :e, 'p1',"
                " 'h', 'X', 'NETWORK', 'ACTIVITY', 'INFO', 'OPEN', 'EVENT',"
                " 'a1', '{}', '{}', '{}', '{}', '{}', '{}', '{}')"),
                {"e": event_id, "c": created})


NOW = datetime(2026, 11, 15, tzinfo=timezone.utc)


class TestPartitionRetention:

    def test_a_dry_run_performs_nothing(self, engine, tmp_path):
        from sqlalchemy.orm import sessionmaker

        from db.retention_enforce import enforce_partition_retention

        _seed(engine, [
            ("old-a", "2026-08-14T10:00:00+00:00"),
            ("old-b", "2026-09-02T10:00:00+00:00"),
            ("fresh", "2026-11-01T10:00:00+00:00"),
        ])
        session = sessionmaker(bind=engine)()
        report = enforce_partition_retention(
            session, table="cryptolog_events", key="created_at",
            window_days=30, archive_dir=tmp_path / "archive",
            actor="retention-sweep", dry_run=True, now=NOW)
        session.close()
        assert report["dry_run"] is True
        # Every wholly-expired month is a candidate (including the empty
        # provisioned ones); the seeded months are the ones with rows.
        assert {"cryptolog_events_y2026m08",
                "cryptolog_events_y2026m09"} <= set(report["candidates"])
        assert "cryptolog_events_y2026m11" not in report["candidates"]
        assert report["dropped"] == []
        assert not (tmp_path / "archive").exists(), (
            "a plan performs nothing — the cryptolog contract, enforced")
        from sqlalchemy import text

        with engine.connect() as conn:
            assert conn.execute(text(
                "SELECT count(*) FROM cryptolog_events")).scalar() == 3

    def test_execute_archives_verifies_drops_and_audits(self, engine, tmp_path):
        from sqlalchemy import text
        from sqlalchemy.orm import sessionmaker

        from db.retention_enforce import enforce_partition_retention

        session = sessionmaker(bind=engine)()
        report = enforce_partition_retention(
            session, table="cryptolog_events", key="created_at",
            window_days=30, archive_dir=tmp_path / "archive",
            actor="retention-sweep", dry_run=False, now=NOW)
        session.close()
        assert {"cryptolog_events_y2026m08",
                "cryptolog_events_y2026m09"} <= set(report["dropped"])
        assert report["archived_rows"] == 2, (
            "the seeded rows were archived before the drop")

        for month in ("y2026m08", "y2026m09"):
            archive = tmp_path / "archive" / f"cryptolog_events_{month}.ndjson"
            lines = [json.loads(line) for line in
                     archive.open("r", encoding="utf-8")]
            assert len(lines) == 1 and lines[0]["event_id"].startswith("old-")

        with engine.connect() as conn:
            left = conn.execute(text(
                "SELECT event_id FROM cryptolog_events")).fetchall()
            assert [row[0] for row in left] == ["fresh"], (
                "the in-window month keeps every row")

        with engine.connect() as conn:
            entries = conn.execute(text(
                "SELECT actor, action, target_id FROM audit_log"
                " WHERE action = 'RETENTION_DROP_PARTITION'"
                " ORDER BY chain_sequence")).fetchall()
        assert {"cryptolog_events_y2026m08",
                "cryptolog_events_y2026m09"} <= {row[2] for row in entries}
        assert all(row[0] == "retention-sweep" for row in entries), (
            "every deletion is recorded — nobody's cleanup is anonymous")


class TestBlobCollection:

    def test_only_unreferenced_blobs_are_collected(self, engine, tmp_path):
        from sqlalchemy import text
        from sqlalchemy.orm import sessionmaker

        from db.retention_enforce import collect_unreferenced_blobs

        with engine.begin() as conn:
            conn.execute(text(
                "INSERT INTO binary_artifact_blobs (id, created_at,"
                " updated_at, tenant_id, sha256, ciphertext, bytes_size,"
                " ref_count) VALUES"
                " (md5(random()::text), now(), now(), 't1', 'deadbeef',"
                " '\\x00', 4, 0),"
                " (md5(random()::text), now(), now(), 't1', 'cafebabe',"
                " '\\x00', 4, 2)"))
        session = sessionmaker(bind=engine)()
        dry = collect_unreferenced_blobs(session, actor="retention-sweep")
        assert dry["candidates"] == 1 and dry["dropped"] == 0

        report = collect_unreferenced_blobs(session, actor="retention-sweep",
                                            dry_run=False)
        session.close()
        assert report["dropped"] == 1 and report["bytes_freed"] == 4
        with engine.connect() as conn:
            left = conn.execute(text(
                "SELECT sha256 FROM binary_artifact_blobs")).fetchall()
        assert [row[0] for row in left] == ["cafebabe"], (
            "a blob one job still names is kept whatever its age")
