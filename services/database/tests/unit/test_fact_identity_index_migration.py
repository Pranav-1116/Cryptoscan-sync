"""Migration 0127 restores the identity index that 0123 dropped.

`cryptographic_facts` carries a unique *expression* index, `uq_fact_identity`,
created by migration 0087 so that two facts spelling "no tenant" differently
(NULL vs '') still collide. Migration 0123 rebuilt the table in batch mode to
make its columns NOT NULL, and on SQLite a batch rebuild recreates the table
without its expression indexes — so on every SQLite database (which includes
every test's `create_all` schema) duplicate identities were accepted, while
PostgreSQL kept the constraint. The index is invisible to column-based
inspection because SQLite reports NULL column names for expression indexes,
which is why the gap survived earlier parity tests.

These tests hold the repair in place: the index exists at head, it rejects the
duplicate identities it was built to reject, and running the migration twice is
harmless.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[4]
MIGRATION = ROOT / "services" / "database" / "migrations" / "versions" / (
    "0127_restore_fact_identity_index.py")


def _config(db_path: Path):
    from alembic.config import Config

    cfg = Config(str(ROOT / "services" / "database" / "migrations" / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "services" / "database" / "migrations"))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    return cfg


def _index_sql(db_path: Path, name: str = "uq_fact_identity") -> str | None:
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='index' AND name=?", (name,)
        ).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def test_migration_file_names_the_same_identity_as_0087():
    """The expression tuple must match 0087 and the model, not a rewrite of it."""
    source = MIGRATION.read_text()
    assert "uq_fact_identity" in source
    for fragment in ("coalesce(tenant_id", "coalesce(purpose", "coalesce(file_path",
                     "coalesce(key_size", "coalesce(mode", "tenant_id IS NULL",
                     "key_size IS NULL"):
        assert fragment in source, fragment


@pytest.mark.timeout(600)
def test_index_exists_at_head(tmp_path):
    from alembic import command

    db_path = tmp_path / "head.db"
    command.upgrade(_config(db_path), "head")
    sql = _index_sql(db_path)
    assert sql is not None, "uq_fact_identity is missing at head"
    assert "UNIQUE INDEX" in sql.upper() or "unique index" in sql.lower()


@pytest.mark.timeout(600)
def test_the_index_is_absent_at_0126_and_present_at_0127(tmp_path):
    """The negative control: the defect is real, and 0127 is what closes it."""
    from alembic import command

    db_path = tmp_path / "defect.db"
    command.upgrade(_config(db_path), "0126")
    assert _index_sql(db_path) is None, (
        "0126 was expected to be missing the identity index — if this fails the "
        "premise of migration 0127 has changed and the migration should be re-read"
    )
    command.upgrade(_config(db_path), "0127")
    assert _index_sql(db_path) is not None


@pytest.mark.timeout(600)
def test_duplicate_identities_are_rejected_at_head(tmp_path):
    """The behaviour the index exists for: one identity, one row."""
    from alembic import command

    db_path = tmp_path / "dup.db"
    command.upgrade(_config(db_path), "head")
    conn = sqlite3.connect(db_path)
    try:
        columns = [row[1] for row in conn.execute("PRAGMA table_info(cryptographic_facts)")]
        assert "algorithm" in columns

        def insert(tenant_id, purpose, file_path, key_size, mode, label):
            values = {
                "algorithm": "RSA",
                "tenant_id": tenant_id,
                "purpose": purpose,
                "file_path": file_path,
                "key_size": key_size,
                "mode": mode,
                "id": label,
            }
            present = [c for c in values if c in columns]
            conn.execute(
                "INSERT INTO cryptographic_facts (%s) VALUES (%s)"
                % (", ".join(present), ", ".join("?" for _ in present)),
                [values[c] for c in present],
            )

        # the same identity twice: NOT NULL, nullable columns left NULL
        insert(None, None, "/etc/key.pem", 2048, None, "fact-a")
        with pytest.raises(sqlite3.IntegrityError):
            insert(None, None, "/etc/key.pem", 2048, None, "fact-b")

        # `(tenant_id IS NULL)` and `(key_size IS NULL)` are part of the key on
        # purpose: "absent" is not the same fact as "explicitly empty", so those
        # two rows are allowed to coexist. That is the design 0087 chose, and the
        # restored index must keep it rather than collapse the pair.
        insert("", "", "/etc/key.pem", 0, "", "fact-c")
        conn.rollback()
    finally:
        conn.close()


@pytest.mark.timeout(600)
def test_re_running_the_migration_is_harmless(tmp_path):
    """Idempotence: the guard is `if not exists`, so a second run must not raise."""
    from alembic import command

    db_path = tmp_path / "twice.db"
    cfg = _config(db_path)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "0126")
    command.upgrade(cfg, "head")
    assert _index_sql(db_path) is not None
