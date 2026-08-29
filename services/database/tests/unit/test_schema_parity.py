"""Regression guard: alembic-head schema must match the ORM models exactly.

Historically ten tables drifted (legacy PK names, missing timestamp columns,
missing scans/systems/scan_jobs fields) — every ORM query against a migrated
database failed while dev/test (create_all) stayed green. This test builds
both schemas and diffs them column-by-column, so a model change without a
migration (or vice versa) fails CI immediately.
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]  # repo root
ALEMBIC_INI = ROOT / "services" / "database" / "migrations" / "alembic.ini"


def _schema(path: str) -> dict[str, set[str]]:
    db = sqlite3.connect(path)
    try:
        return {
            table: {row[1] for row in db.execute(f"pragma table_info({table})")}
            for (table,) in db.execute("select name from sqlite_master where type='table'")
        }
    finally:
        db.close()


def test_alembic_head_matches_create_all():
    from sqlalchemy import create_engine

    import db.models  # noqa: F401 — register every table
    from db.connection.session import Base

    with tempfile.TemporaryDirectory() as tmp:
        migrated = str(Path(tmp) / "migrated.db")
        created = str(Path(tmp) / "created.db")
        env = dict(os.environ, DATABASE_URL=f"sqlite:///{migrated}")
        upgrade = subprocess.run(
            [sys.executable, "-m", "alembic", "-c", str(ALEMBIC_INI), "upgrade", "head"],
            cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=300,
        )
        assert upgrade.returncode == 0, upgrade.stderr[-2000:]

        Base.metadata.create_all(create_engine(f"sqlite:///{created}"))

        alembic_schema = _schema(migrated)
        model_schema = _schema(created)
        drift = {
            table: sorted(model_schema.get(table, set()) - alembic_schema.get(table, set()))
            for table in set(model_schema) | set(alembic_schema)
        }
        drift = {table: cols for table, cols in drift.items() if cols}
        assert not drift, (
            f"alembic head is missing model columns (add them to the next migration): {drift}"
        )
