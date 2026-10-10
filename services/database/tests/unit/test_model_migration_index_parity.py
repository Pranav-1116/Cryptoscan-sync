"""Model/migration index parity (report 04 — round 21).

The models declare indexes the migration chain historically never created:
`create_all` deployments had them, alembic deployments silently lacked them
(migration 0078 closed a 24-index gap). This test runs the REAL chain to
head on a scratch SQLite database and compares, prefix-aware, against the
ORM metadata so the two can never drift apart again.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
from pathlib import Path

import pytest
from sqlalchemy import create_engine

# repo-root cwd (this suite is run from the repo root)
ROOT = Path(__file__).resolve().parents[4]


def _upgrade_head(db_path: str) -> None:
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(ROOT / "services" / "database" / "migrations" / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "services" / "database" / "migrations"))
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    command.upgrade(cfg, "head")


def _orm_indexes() -> dict[str, set[tuple[str, ...]]]:
    import db.models  # noqa: F401 — register every table
    from db.connection.session import Base

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    out: dict[str, set[tuple[str, ...]]] = {}
    for table in Base.metadata.sorted_tables:
        out[table.name] = {tuple(ix.columns.keys()) for ix in table.indexes}
    return out


def _chain_indexes(db_path: str) -> dict[str, list[tuple[str, ...]]]:
    conn = sqlite3.connect(db_path)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    out: dict[str, list[tuple[str, ...]]] = {}
    for table in tables:
        if table.startswith("sqlite_") or table == "alembic_version":
            continue
        cols: list[tuple[str, ...]] = []
        for row in conn.execute(f"PRAGMA index_list('{table}')"):
            cols.append(
                tuple(c[2] for c in conn.execute(f"PRAGMA index_info('{row[1]}')"))
            )
        out[table] = cols
    return out


def _prefix_covered(existing: list[tuple[str, ...]], wanted: tuple[str, ...]) -> bool:
    return any(list(idx[: len(wanted)]) == list(wanted) for idx in existing)


def test_model_indexes_exist_in_migration_chain():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = str(Path(tmp) / "parity.db")
        _upgrade_head(db_path)
        orm = _orm_indexes()
        chain = _chain_indexes(db_path)

        missing: list[tuple[str, tuple[str, ...]]] = []
        for table, wanted_set in sorted(orm.items()):
            existing = chain.get(table, [])
            for wanted in sorted(wanted_set):
                if not _prefix_covered(existing, wanted):
                    missing.append((table, wanted))
        assert not missing, (
            "model-declared indexes missing from the alembic chain "
            f"(create_all deployments have them, migrated ones do not): {missing}"
        )


def test_migration_0078_indexes_are_prefix_minimal():
    """Nothing in 0078 duplicates coverage that already existed."""
    import re

    src = (ROOT / "services" / "database" / "migrations" / "versions" /
           "0078_model_chain_index_parity.py").read_text()
    created = re.findall(r'\("([a-z0-9_]+)", "[a-z0-9_]+", \(([^)]*)\)\)', src)
    assert len(created) == 24
    with tempfile.TemporaryDirectory() as tmp:
        db_path = str(Path(tmp) / "parity.db")
        # upgrade to 0077 (before the parity migration)
        from alembic import command
        from alembic.config import Config

        cfg = Config(str(ROOT / "services" / "database" / "migrations" / "alembic.ini"))
        cfg.set_main_option("script_location", str(ROOT / "services" / "database" / "migrations"))
        os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
        command.upgrade(cfg, "0077")
        chain = _chain_indexes(db_path)
        redundant = []
        for table, cols in created:
            wanted = tuple(c.strip().strip('"') for c in cols.split(","))
            if _prefix_covered(chain.get(table, []), wanted):
                redundant.append((table, wanted))
        assert not redundant, f"0078 creates indexes that were already covered: {redundant}"


def _chain_head() -> str:
    """The head revision: the one no other migration lists as down_revision."""
    import re

    versions = ROOT / "services" / "database" / "migrations" / "versions"
    revisions: dict[str, str] = {}
    downs: set[str] = set()
    for path in sorted(versions.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        rev = re.search(r'^revision\s*=\s*["\']([\w-]+)["\']', text, re.M)
        down = re.search(r'^down_revision\s*=\s*["\']([\w-]+)["\']', text, re.M)
        if rev:
            revisions[rev.group(1)] = path.name
            if down:
                downs.add(down.group(1))
    heads = [rev for rev in revisions if rev not in downs]
    assert len(heads) == 1, f"chain must have exactly one head, found {heads}"
    return heads[0]


@pytest.mark.parametrize("steps", [1, 3])
def test_recent_downgrades_roundtrip(steps):
    """upgrade head -> downgrade N -> upgrade head must succeed (report 04:
    'no rollback testing'). Runs the real chain on SQLite."""
    from alembic import command
    from alembic.config import Config

    with tempfile.TemporaryDirectory() as tmp:
        db_path = str(Path(tmp) / "roundtrip.db")
        cfg = Config(str(ROOT / "services" / "database" / "migrations" / "alembic.ini"))
        cfg.set_main_option("script_location", str(ROOT / "services" / "database" / "migrations"))
        os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
        command.upgrade(cfg, "head")
        command.downgrade(cfg, f"-{steps}")
        command.upgrade(cfg, "head")
        conn = sqlite3.connect(db_path)
        version = conn.execute("SELECT version_num FROM alembic_version").fetchone()[0]
        # head is discovered from the chain, not hardcoded, so new migrations
        # do not break this test
        head = _chain_head()
        assert version == head
        # the 0078 indexes exist again after the roundtrip
        indexes = {r[1] for r in conn.execute("PRAGMA index_list('vulnerabilities')")}
        assert "ix_vulnerabilities_scan_id" in indexes
