"""The point-in-time-recovery drill, and the three ways it silently stops working.

The drill spawns real PostgreSQL binaries, so the end-to-end case skips when
none are installed. The cheap cases always run: they guard the properties that
made the drill fail while it was being written, each of which is a real restore
bug rather than a test inconvenience:

* a non-atomic ``archive_command`` publishes a half-written WAL segment under
  its final name, and the restore that reads it dies with
  ``archive file ... has wrong size``;
* the restored cluster inherits the primary's port and socket directory, so it
  either refuses to start or attaches to the live cluster's socket;
* a report with no checks at all must not be reported as a pass.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import pitr_drill  # noqa: E402


def test_the_archive_command_is_atomic():
    """Copy-under-a-temporary-name, then rename."""
    source = (ROOT / "scripts" / "pitr_drill.py").read_text(encoding="utf-8")
    assert ".partial" in source
    assert "&& mv " in source
    # `cp %p %f` straight to the final name is the bug this drill reproduces.
    assert "cp %p {archive}/%f\"" not in source


def test_recovery_settings_inherit_no_primary_port():
    source = (ROOT / "scripts" / "pitr_drill.py").read_text(encoding="utf-8")
    restored_block = source.split("restored = Cluster(", 1)[1]
    assert "restored.write_settings()" in restored_block, (
        "the restored cluster must get its own port and socket directory"
    )
    assert "recovery_target_action" in source and "promote" in source


def test_an_empty_report_is_not_a_pass():
    report = pitr_drill.Report()
    assert report.passed is False, "no checks must never read as success"
    report.check("only_check", True, "ok")
    assert report.passed is True
    report.check("regression", False, "nope")
    assert report.passed is False


def test_missing_binaries_are_refused_with_an_actionable_message(monkeypatch):
    """Never fall back to "assume PostgreSQL is somewhere"."""
    monkeypatch.setenv("PG_BIN", "/nonexistent/postgres/bin")
    monkeypatch.setattr(shutil, "which", lambda name: None)
    monkeypatch.setitem(sys.modules, "pgserver", None)
    with pytest.raises(pitr_drill.DrillError) as excinfo:
        pitr_drill.find_binaries("/nonexistent/postgres/bin")
    message = str(excinfo.value)
    assert "PG_BIN" in message and "initdb" in message


def _binaries_available() -> bool:
    try:
        pitr_drill.find_binaries()
    except pitr_drill.DrillError:
        return False
    return True


@pytest.mark.skipif(not _binaries_available(), reason="no PostgreSQL binaries on this host")
def test_the_drill_proves_a_point_in_time_restore(tmp_path):
    evidence = tmp_path / "pitr.json"
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "pitr_drill.py"), "--evidence", str(evidence)],
        capture_output=True, text=True, timeout=300,
    )
    assert evidence.exists(), result.stderr
    document = json.loads(evidence.read_text(encoding="utf-8"))
    assert document["schema"] == pitr_drill.SCHEMA
    passed = {check["check"]: check["passed"] for check in document["checks"]}
    assert document["verdict"] == "PASS", [c for c in document["checks"] if not c["passed"]]
    for required in (
        "base_backup_verified",
        "target_wal_archived",
        "archived_segment_complete",
        "pre_target_data_recovered",
        "post_target_data_excluded",
        "restored_instance_promoted",
        "new_timeline_created",
        "restored_cluster_writable",
    ):
        assert passed.get(required) is True, f"{required} missing from the drill"
    assert document["measurements"]["rto_seconds"] > 0
    assert result.returncode == 0
    assert evidence.stat().st_mode & 0o777 == 0o600
