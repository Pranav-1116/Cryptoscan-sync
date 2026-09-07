"""Worker tick integration: the 24/7 monitor engine runs due encrypted backups
(Postgres/Neo4j) + retention alongside the report sweep. Deterministic; the
dump runner and storage are injected (no real DB server, no network)."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register all tables
from db.connection.session import Base
from db.repositories.settings_repository import SettingsRepository
from worker.monitor.engine import MonitorEngine

from governance import backup_jobs as bj, backup_schedule as bsched

T0 = datetime(2026, 9, 7, 12, 0, 0, tzinfo=timezone.utc)


def _session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


class _Runner:
    def __call__(self, argv, stdin=None):
        tool = argv[0].split("/")[-1]
        if "dump" in tool or "backup" in argv:
            return bj.CommandResult(0, b"WORKER-DUMP", b"")
        return bj.CommandResult(0, b"", b"")


def _backend_for(engine_name: str):
    runner = _Runner()
    return bj.Neo4jBackend(runner=runner) if engine_name == "neo4j" else bj.PgDumpBackend(runner=runner)


def _engine(session, storage, monkeypatch=None):
    if monkeypatch is not None:
        monkeypatch.setenv("SECRET_KEY", "worker-tick-master")
    return MonitorEngine(
        session, runners={}, clock=lambda: T0, watch_enabled=False,
        run_reports=False, run_backups=True,
        backup_backend_for=_backend_for, backup_storage=storage)


def test_tick_runs_due_backups_and_reports_in_summary(monkeypatch):
    session = _session()
    repo = SettingsRepository(session)
    bsched.save_configs(repo, [
        bj.BackupConfig(database_id="proddb", engine="postgres", interval_hours=24),
        bj.BackupConfig(database_id="graphdb", engine="neo4j", interval_hours=24),
    ], by="test")
    session.commit()

    storage = bj.InMemoryBackupStorage()
    eng = _engine(session, storage, monkeypatch)
    out = eng.tick()

    bk = out["backups"]
    assert bk["backed_up"] == 2 and bk["failed"] == 0
    assert len(storage.list_manifests()) == 2
    # schedule state persisted (second tick skips)
    out2 = eng.tick()
    assert all(o["status"] == "SKIPPED_NOT_DUE" for o in out2["backups"]["outcomes"])


def test_tick_without_backup_wiring_leaves_backups_empty(monkeypatch):
    session = _session()
    eng = MonitorEngine(session, runners={}, clock=lambda: T0, watch_enabled=False,
                        run_reports=False, run_backups=True)  # no backend/storage wired
    out = eng.tick()
    assert out["backups"] == {}
