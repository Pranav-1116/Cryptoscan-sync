"""The restore drill is refused more often than it runs, and each refusal is tested.

An automated drill earns trust in two ways: it actually restores, and it refuses the ways a
drill can quietly destroy the thing it is meant to prove recoverable. The second half is what
this file pins down, because it is the half that never shows up in a demo.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]


def _script():
    spec = importlib.util.spec_from_file_location(
        "restore_drill", ROOT / "scripts" / "restore_drill.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


drill = _script()

SOURCE = "postgresql://cryptoscan_app:source-password@db.internal:5432/cryptoscan"
TARGET = "postgresql://drill:target-password@recovery.internal:5432/cryptoscan_drill"

MANIFEST = {"backup_id": "bk-abc-1-20261103T000000Z", "database_id": "cryptoscan",
            "engine": "postgres", "created_at": "2026-11-03T00:00:00+00:00", "sequence": 1,
            "size_bytes": 4096, "plaintext_sha256": "a" * 64, "ciphertext_sha256": "b" * 64,
            "has_wal_tail": False, "format": "cryptoscan-backup-v1", "storage_key": "postgres/x"}


# --------------------------------------------------------------------------- #
# refusals
# --------------------------------------------------------------------------- #

def test_a_drill_without_a_target_refuses_to_guess_one():
    with pytest.raises(drill.DrillRefused, match="CRYPTOSCAN_RESTORE_TARGET_DB is unset"):
        drill.plan(source_dsn=SOURCE, target_dsn="", manifests=[MANIFEST])


def test_a_drill_will_not_restore_over_the_source_database():
    with pytest.raises(drill.DrillRefused, match="the recovery target is the source"):
        drill.plan(source_dsn=SOURCE, target_dsn=SOURCE, manifests=[MANIFEST])


def test_a_drill_refuses_an_engine_it_cannot_measure():
    with pytest.raises(drill.DrillRefused, match="defined for PostgreSQL"):
        drill.plan(source_dsn="sqlite:///x.db", target_dsn=TARGET, manifests=[MANIFEST])


def test_a_drill_refuses_when_there_is_nothing_to_restore():
    with pytest.raises(drill.DrillRefused, match="no backup manifests"):
        drill.plan(source_dsn=SOURCE, target_dsn=TARGET, manifests=[])


def test_point_in_time_on_a_logical_dump_is_refused_rather_than_faked():
    with pytest.raises(drill.DrillRefused, match="logical pg_dump with no WAL"):
        drill.plan(source_dsn=SOURCE, target_dsn=TARGET, manifests=[MANIFEST],
                   point_in_time="2026-11-01T00:00:00Z")


def test_a_named_backup_that_does_not_exist_is_a_refusal_not_the_newest_backup():
    with pytest.raises(drill.DrillRefused, match="is not in the store"):
        drill.plan(source_dsn=SOURCE, target_dsn=TARGET, manifests=[MANIFEST],
                   storage_key="postgres/missing")


# --------------------------------------------------------------------------- #
# the plan itself
# --------------------------------------------------------------------------- #

def test_pg_restore_uses_connection_flags_not_a_password_bearing_dsn(monkeypatch):
    from governance import backup_jobs

    captured = []

    def runner(*, env):
        def run(argv, *, stdin=None):
            captured.append((argv, stdin))
            return backup_jobs.CommandResult(0, b"", b"")
        return run

    monkeypatch.setattr(backup_jobs, "subprocess_runner", runner)
    backend = drill._pg_backend(SOURCE, TARGET)
    backend.restore("cryptoscan_drill", b"test-only-archive")
    argv, _ = captured[0]
    assert "target-password" not in " ".join(argv)
    assert argv[argv.index("-d") + 1] == "cryptoscan_drill"
    assert argv[argv.index("-U") + 1] == "drill"


def test_ci_key_is_passed_to_fernet_in_its_encoded_form():
    from cryptography.fernet import Fernet
    from scripts.pending_workflows import CI_ONLY_ENCRYPTION_KEY

    key = drill._encryption_key(CI_ONLY_ENCRYPTION_KEY)
    Fernet(key)
    assert key.decode() == CI_ONLY_ENCRYPTION_KEY


def test_the_plan_picks_the_newest_backup_and_never_carries_a_password():
    older = dict(MANIFEST, created_at="2026-10-01T00:00:00+00:00", backup_id="older")
    decision = drill.plan(source_dsn=SOURCE, target_dsn=TARGET, manifests=[older, MANIFEST])
    assert decision["backup"]["backup_id"] == "bk-abc-1-20261103T000000Z"
    assert decision["may_run"] is True
    rendered = json.dumps(decision)
    assert "source-password" not in rendered and "target-password" not in rendered
    assert decision["target"] == {"driver": "postgresql", "host": "recovery.internal",
                                 "port": 5432, "database": "cryptoscan_drill",
                                 "username": "drill", "has_password": True}


def test_run_uses_the_real_backup_storage_restore_path(monkeypatch):
    from governance import backup_jobs

    class Store:
        def list_manifests(self):
            return [MANIFEST]

    restored = []

    def restore_from_storage(**kwargs):
        restored.append(kwargs["database_id"])
        return {"restored": True}

    monkeypatch.setattr(backup_jobs, "restore_from_storage", restore_from_storage)
    monkeypatch.setattr(drill, "measure", lambda dsn, connect=None: {
        "revision": "0133", "verdict": "RESTORED_AND_MEASURED",
        "tables": {"users": 1, "tenants": 1},
    })
    outcome = drill.run(source_dsn=SOURCE, target_dsn=TARGET, storage=Store(),
                        database_id="cryptoscan", encryption_key=b"test-only",
                        signing_secret="test-only", backend=object())
    assert restored == ["cryptoscan"]
    assert outcome["result"] == "RESTORED_AND_MEASURED"
    assert outcome["measurement"]["source_comparison"]["verdict"] == "MATCH"


# --------------------------------------------------------------------------- #
# what a receipt may claim
# --------------------------------------------------------------------------- #

def _decision():
    return drill.plan(source_dsn=SOURCE, target_dsn=TARGET, manifests=[MANIFEST])


def test_a_receipt_that_restored_and_measured_says_so_and_says_what_it_does_not_prove():
    measurement = drill.measure.__wrapped__ if hasattr(drill.measure, "__wrapped__") else None
    assert measurement is None or callable(measurement)
    facts = {"measured": True, "table_count": 120, "missing_tables": [],
             "tables": {"users": 4}, "rls": {}, "verdict": "RESTORED_AND_MEASURED"}
    record = drill.receipt(decision=_decision(), restored={"restored": True},
                           measurement=facts, duration_seconds=1.25)
    assert record["result"] == "RESTORED_AND_MEASURED"
    assert record["claims"]["backup_restores"] is True
    assert record["claims"]["proves_pitr"] is False
    assert record["claims"]["restore_is_disaster_recovery"] is False
    assert record["receipt_sha256"] and len(record["receipt_sha256"]) == 64


def test_an_empty_restore_is_not_a_pass():
    facts = {"measured": True, "table_count": 0, "missing_tables": [], "tables": {},
             "verdict": "RESTORED_EMPTY"}
    record = drill.receipt(decision=_decision(), restored={"restored": True},
                           measurement=facts, duration_seconds=0.5)
    assert record["result"] == "RESTORED_EMPTY"
    assert record["claims"]["backup_restores"] is False


def test_a_receipt_never_contains_the_dsn_or_a_password():
    facts = {"measured": True, "table_count": 10, "missing_tables": [], "tables": {},
             "verdict": "RESTORED_AND_MEASURED"}
    rendered = json.dumps(drill.receipt(decision=_decision(), restored={}, measurement=facts,
                                         duration_seconds=0.1))
    assert "source-password" not in rendered
    assert "target-password" not in rendered
    assert "postgresql://" not in rendered


def test_the_history_chain_names_the_receipt_before_it(tmp_path):
    path = tmp_path / "history.jsonl"
    first = drill.append_history(path, {"result": "NOT_RUN", "receipt_sha256": "a" * 64})
    second = drill.append_history(path, {"result": "NOT_RUN", "receipt_sha256": "b" * 64})
    assert first["previous_receipt_sha256"] is None
    assert second["previous_receipt_sha256"] == "a" * 64
    lines = path.read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["receipt_sha256"] for line in lines] == ["a" * 64, "b" * 64]


# --------------------------------------------------------------------------- #
# measurement
# --------------------------------------------------------------------------- #

def test_measurement_reports_an_absent_table_as_a_fact_and_never_raises():
    from types import SimpleNamespace

    class Scalar:
        def __init__(self, value=None, error=None):
            self._value, self._error = value, error

        def scalar(self):
            if self._error:
                raise self._error
            return self._value

    class Connection:
        dialect = SimpleNamespace(name="sqlite")   # db.rls.enforcement answers without querying

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def scalar(self, statement):
            text = str(statement)
            if "information_schema" in text:
                return 120
            if "current_schema" in text:
                return "public"
            if "version_num" in text:
                return "0133"
            raise AssertionError(f"unexpected scalar query: {text}")

        def execute(self, statement):
            text = str(statement)
            if '"users"' in text:
                return Scalar(7)
            return Scalar(error=RuntimeError("relation does not exist"))

    class Engine:
        def connect(self):
            return Connection()

        def dispose(self):
            pass

    facts = drill.measure(TARGET, connect=lambda dsn: Engine())
    assert facts["verdict"] == "RESTORED_PARTIALLY_MEASURED"
    assert facts["revision"] == "0133"
    assert facts["tables"]["users"] == 7
    assert "tenants" in facts["missing_tables"]
    assert facts["rls"]["supported"] is False


def test_a_schema_without_seeded_rows_is_not_a_successful_restore():
    facts = {"measured": True, "table_count": 172, "missing_tables": [], "errors": [],
             "tables": {table: 0 for table in drill.MEASURED_TABLES}}
    assert drill._verdict(facts) == "RESTORED_EMPTY"


def test_a_restore_with_missing_rows_or_a_different_revision_does_not_match():
    source = {"revision": "0133", "tables": {"users": 1, "tenants": 1}}
    target = {"revision": "0132", "tables": {"users": 0, "tenants": 1}}
    result = drill.compare_measurements(source, target)
    assert result["verdict"] == "MISMATCH"
    assert result["mismatches"] == ["schema_revision", "users"]
    assert drill.compare_measurements(source, source)["verdict"] == "MATCH"


def test_cleanup_failure_cannot_be_reported_as_a_fully_measured_restore():
    from types import SimpleNamespace

    class Connection:
        dialect = SimpleNamespace(name="sqlite")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def scalar(self, statement):
            sql = str(statement)
            if "information_schema" in sql:
                return 8
            if "current_schema" in sql:
                return "public"
            return "0133"

        def execute(self, statement):
            return SimpleNamespace(scalar=lambda: 1)

    class Engine:
        def connect(self):
            return Connection()

        def dispose(self):
            raise OSError("test-only close failure")

    measured = drill.measure(TARGET, connect=lambda _: Engine())
    assert measured["verdict"] == "RESTORED_PARTIALLY_MEASURED"
    assert "cleanup failed: OSError" in measured["errors"][0]


def test_a_database_with_no_application_tables_is_not_reported_as_recovered():
    facts = {"measured": True, "table_count": 3,
             "missing_tables": list(drill.MEASURED_TABLES), "tables": {},
             "verdict": "RESTORED_WITHOUT_APPLICATION_TABLES"}
    record = drill.receipt(decision=_decision(), restored={}, measurement=facts,
                           duration_seconds=0.2)
    assert record["claims"]["backup_restores"] is False
