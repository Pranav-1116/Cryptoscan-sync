"""Actual psql SQL-error behavior; disposable opt-in databases only."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
import pytest
from sqlalchemy import text
from test_workflow_postgres import quality_cluster as quality_cluster, pgdb as pgdb

pytestmark = pytest.mark.live
ROOT = Path(__file__).resolve().parents[4]


def test_real_psql_error_is_not_reported_as_success(pgdb, tmp_path):
    backup = tmp_path / "invalid.sql"
    backup.write_text("CREATE TABLE recovery_sql_guard (id integer); INSERT INTO recovery_sql_guard VALUES (1); SELECT invalid_sql_failure;\n")
    backup.with_suffix(".sql.manifest.json").write_text(json.dumps({"sha256": hashlib.sha256(backup.read_bytes()).hexdigest()}))
    url = pgdb.url.set(drivername="postgresql").render_as_string(hide_password=False)
    result = subprocess.run([sys.executable, str(ROOT / "scripts/restore_evidence.py"), str(backup), "--db", url],
                            capture_output=True, text=True, timeout=20, env=os.environ.copy())
    assert result.returncode != 0, "SQL errors must not become a successful restore CLI exit"
    with pgdb.connect() as connection:
        assert connection.scalar(text("SELECT to_regclass('public.recovery_sql_guard')")) is None
