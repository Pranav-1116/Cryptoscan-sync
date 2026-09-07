"""Tests for backup jobs/scheduling/retention execution, air-gap read-only
enforcement, and offline feed normalization. All deterministic, no network."""
import datetime as dt

import pytest

from governance import backup as bk, backup_jobs as bj
from governance import airgap, feed_store


# ------------------------------------------------------- backup jobs ------- #
class FakeRunner:
    def __init__(self, engine):
        self.engine = engine
        self.commands = []

    def __call__(self, argv, stdin: bytes | None = None):
        self.commands.append((argv, stdin))
        tool = argv[0].split("/")[-1]
        if tool in ("pg_dump",):
            return bj.CommandResult(0, b"PG-CUSTOM-ARCHIVE-BYTES", b"")
        if "backup" in argv:  # neo4j-admin database backup
            return bj.CommandResult(0, b"NEO4J-BACKUP-BYTES", b"")
        # restore tools
        return bj.CommandResult(0, b"", b"")


def test_pgdump_backend_invokes_pg_dump_and_pg_restore():
    runner = FakeRunner("postgres")
    be = bj.PgDumpBackend(runner=runner, host="db.internal", user="svc")
    data = be.dump("proddb")
    assert data == b"PG-CUSTOM-ARCHIVE-BYTES"
    argv = runner.commands[0][0]
    assert argv[0].endswith("pg_dump") and "proddb" in argv and "-Fc" in argv
    out = be.restore("proddb", data)
    assert out["tool"] == "pg_restore"


def test_unsafe_db_name_rejected():
    be = bj.PgDumpBackend(runner=FakeRunner("x"))
    with pytest.raises(bk.BackupError):
        be.dump("db; rm -rf /")


def test_pgdump_failure_raises_backup_error():
    def fail(argv, stdin=None):
        return bj.CommandResult(1, b"", b"connection refused")
    be = bj.PgDumpBackend(runner=fail)
    with pytest.raises(bk.BackupError):
        be.dump("proddb")


def test_scheduled_backup_cycle_persists_and_restores_from_storage():
    storage = bj.InMemoryBackupStorage()
    runner = FakeRunner("postgres")
    be = bj.PgDumpBackend(runner=runner)
    key = bk.generate_encryption_key()
    cfg = bj.BackupConfig(database_id="proddb", engine="postgres", interval_hours=24)
    now = dt.datetime(2026, 9, 7, tzinfo=dt.timezone.utc)

    r1 = bj.run_backup_job(backend=be, storage=storage, config=cfg,
                           encryption_key=key, signing_secret="s", now=now)
    assert r1["ok"] and len(storage.list_manifests()) == 1
    assert cfg.sequence == 1 and cfg.last_run_at == now

    # not due yet (1h later, interval 24h) -> skipped
    results = bj.run_due_backups(configs=[cfg], backend_for=lambda e: be, storage=storage,
                                 encryption_key=key, signing_secret="s",
                                 now=now + dt.timedelta(hours=1))
    assert results[0].get("skipped") is True

    # due after 25h -> second backup
    bj.run_due_backups(configs=[cfg], backend_for=lambda e: be, storage=storage,
                       encryption_key=key, signing_secret="s", now=now + dt.timedelta(hours=25))
    assert len(storage.list_manifests()) == 2

    # restore newest from storage
    out = bj.restore_from_storage(backend=be, storage=storage, database_id="proddb",
                                  encryption_key=key, signing_secret="s")
    assert out["restored"] is True and out["engine"] == "postgres"


def test_retention_execution_deletes_old_backups():
    storage = bj.InMemoryBackupStorage()
    key = bk.generate_encryption_key()
    be = bj.PgDumpBackend(runner=FakeRunner("postgres"))
    # one old (30d) and one fresh
    for age_days in (30, 1):
        cfg = bj.BackupConfig(database_id="d", engine="postgres")
        bj.run_backup_job(backend=be, storage=storage, config=cfg, encryption_key=key,
                          signing_secret="s", now=dt.datetime(2026, 9, 7, tzinfo=dt.timezone.utc)
                          - dt.timedelta(days=age_days))
    assert len(storage.list_manifests()) == 2
    out = bj.execute_retention(storage=storage, signing_secret="s",
                               now=dt.datetime(2026, 9, 7, tzinfo=dt.timezone.utc))
    assert out["plan"]["purged"] == 1
    assert len(out["deleted_keys"]) == 1
    assert len(storage.list_manifests()) == 1


def test_restore_missing_database_raises():
    storage = bj.InMemoryBackupStorage()
    be = bj.PgDumpBackend(runner=FakeRunner("postgres"))
    with pytest.raises(bk.BackupError):
        bj.restore_from_storage(backend=be, storage=storage, database_id="ghost",
                                encryption_key=bk.generate_encryption_key(), signing_secret="s")


# --------------------------------------------------- airgap read-only ----- #
def test_airgap_blocks_mutating_allows_reads_and_feed_import():
    pol = airgap.AirgapPolicy(airgap=True)
    for op in ("scan.trigger", "connector.deliver", "siem.push", "bus.publish"):
        with pytest.raises(airgap.AirgapReadOnlyError):
            airgap.enforce_operation(op, pol)
    # reads + offline feed import permitted
    assert airgap.enforce_operation("feed.import", pol)["action"] == "ALLOW_READONLY"
    assert airgap.enforce_operation("ot.decode", pol)["allowed"] is True
    # unknown op fails closed
    with pytest.raises(airgap.AirgapReadOnlyError):
        airgap.enforce_operation("mystery.op", pol)
    # not airgapped: everything allowed
    off = airgap.AirgapPolicy(airgap=False)
    assert airgap.enforce_operation("scan.trigger", off)["allowed"] is True


# --------------------------------------------------- feed normalization ---- #
def test_feed_normalize_nvd_and_osv():
    nvd = feed_store.normalize_entry("nvd", "CVE-2026-1", {"cvss": 9.8, "package": "openssl",
                                                           "version": "3.0.1", "desc": "rce"})
    assert nvd["severity"] == "CRITICAL" and nvd["package"] == "openssl"
    osv = feed_store.normalize_entry("osv", "GHSA-x", {"package": "lodash", "cvss": 5.5})
    assert osv["severity"] == "MEDIUM"


def test_inmemory_feed_sink_idempotent():
    sink = feed_store.InMemoryFeedSink()
    n1 = sink.upsert_feed("nvd", "CVE-1", {"package": "x", "cvss": 7.5})
    n2 = sink.upsert_feed("nvd", "CVE-1", {"package": "x", "cvss": 7.5, "version": None})
    assert n1 == 1 and n2 == 0
    sink.finalize(1)
    assert sink.applied == 1


def test_offline_bundle_flows_into_feed_sink():
    from governance import airgap as ag

    secret = "fs"
    bundle = ag.build_bundle([
        {"feed": "nvd", "id": "CVE-2026-9", "payload": {"package": "openssl", "cvss": 9.1, "version": "3.0.2"}},
    ], secret=secret)
    sink = feed_store.InMemoryFeedSink()
    out = ag.import_bundle(bundle, secret=secret, sink=sink)
    assert out["imported"] == 1
    assert sink.feeds["nvd"], "feed entry should be normalized and stored"
