"""PostgreSQL operations invariants: WAL, PITR, autovacuum, backups.

The HA compose once claimed 'WAL-archived' with no WAL config behind it.
These tests read deploy/ha exactly as shipped and pin the promises:
archiving is ON with a REAL archive_command (not the /bin/true rehearsal
stub the replication overlay documents as a stub), autovacuum is tuned for
continuous ingest, the backup script retains, and the restore drill is a
PITR drill (target time + WAL replay), not a plain untar.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONF = ROOT / "deploy" / "ha" / "pg-primary" / "postgresql.conf"
BACKUP = ROOT / "deploy" / "ha" / "pg-backup" / "pgbackup.sh"
RESTORE = ROOT / "deploy" / "ha" / "pg-backup" / "restore-drill.sh"
COMPOSE = ROOT / "deploy" / "ha" / "docker-compose.yml"


def _settings() -> dict[str, str]:
    out = {}
    for line in CONF.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if "=" in line:
            key, value = line.split("=", 1)
            out[key.strip()] = value.strip().strip("'\"")
    return out


class TestWalManagement:

    def test_wal_level_supports_replicas_and_archiving(self):
        assert _settings()["wal_level"] == "replica", (
            "minimal WAL breaks both streaming replicas and PITR")

    def test_wal_sizing_is_bounded_not_default_tiny(self):
        settings = _settings()
        assert settings["max_wal_size"] == "2GB"
        assert settings["min_wal_size"] == "1GB"
        assert settings["checkpoint_timeout"] == "15min"


class TestPointInTimeRecovery:

    def test_archiving_is_on_with_a_real_command(self):
        settings = _settings()
        assert settings["archive_mode"] == "on"
        command = settings["archive_command"]
        assert "/pgbackup/archive" in command, (
            "WAL segments must land in the backup volume — off the data "
            "directory, so losing the data volume never loses the archive")
        assert command.strip() not in ("", "/bin/true"), (
            "the /bin/true stub is the overlay's rehearsal placeholder; the "
            "shipped config must actually archive")

    def test_the_restore_drill_is_a_pitr_drill(self):
        text = RESTORE.read_text()
        assert "recovery_target_time" in text, "restore TO A SPECIFIC TIME"
        assert "restore_command" in text, "WAL replay, not a plain untar"
        assert "recovery.signal" in text
        assert "/pgrestore" in text, (
            "the drill restores into a throwaway directory — it never "
            "touches the live data")


class TestVacuumAutovacuum:

    def test_autovacuum_is_on_and_tuned_for_continuous_ingest(self):
        settings = _settings()
        assert settings["autovacuum"] == "on"
        assert settings["autovacuum_vacuum_scale_factor"] == "0.02", (
            "continuous evidence churn needs aggressive vacuuming, not "
            "PostgreSQL's 20% default")
        assert settings["autovacuum_analyze_scale_factor"] == "0.01"
        assert settings["autovacuum_max_workers"] == "4"

    def test_slow_queries_are_visible(self):
        assert _settings()["log_min_duration_statement"] == "1000", (
            "the EXPLAIN audit's production half: a query slow enough to "
            "matter shows up in the log with its duration")


class TestDatabaseAuditing:

    def test_the_server_logs_privileged_statements(self):
        settings = _settings()
        assert settings["log_statement"] == "ddl", (
            "every schema change is logged whatever client issued it — the "
            "audit trail does not depend on the application's cooperation")
        assert "%u" in settings["log_line_prefix"], (
            "the log names the ROLE that ran the statement")


class TestAutomatedBackups:

    def test_the_backup_script_retains(self):
        text = BACKUP.read_text()
        assert "pg_basebackup" in text
        assert "BASE_BACKUP_KEEP_DAYS" in text, "retention is a named policy"
        assert "rm -rf" in text and "mtime" in text, (
            "old base backups are actually removed — unbounded backups are "
            "how a backup volume becomes the outage")

    def test_the_compose_runs_backups_on_a_schedule(self):
        text = COMPOSE.read_text()
        assert "pgbackup" in text
        assert "sleep 86400" in text, "the nightly loop is in the wiring"
        assert "pgbackup:/pgbackup" in text, (
            "primary and backup share the volume that holds base+WAL")

    def test_the_primary_mounts_the_shipped_config(self):
        text = COMPOSE.read_text()
        assert "postgresql.conf" in text
        assert "config_file=" in text
