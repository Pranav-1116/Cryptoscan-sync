"""The alembic chain must run to head on SQLite AND Postgres-compatible types.

Guards the postgres-only DDL that silently broke `alembic upgrade head`
on SQLite for the entire chain's life (JSONB/ARRAY types, COMMENT ON,
GIN/partial indexes, CHECK constraints).
"""

from __future__ import annotations

import os


from sqlalchemy import create_engine, inspect


def test_alembic_chain_runs_to_head_on_sqlite(tmp_path):
    from alembic import command
    from alembic.config import Config

    db_path = tmp_path / "migrations.db"
    ini = os.path.join(os.path.dirname(__file__), "..", "..", "migrations", "alembic.ini")
    cfg = Config(ini)
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    command.upgrade(cfg, "head")

    engine = create_engine(f"sqlite:///{db_path}")
    tables = set(inspect(engine).get_table_names())
    assert "scans" in tables
    assert "runtime_findings" in tables
    assert "users" in tables
    indexes = {i["name"] for i in inspect(engine).get_indexes("runtime_findings")}
    assert "ix_runtime_findings_dedup_key" in indexes


def test_migration_chain_matches_models_table_set(tmp_path):
    from alembic import command
    from alembic.config import Config

    from db.connection.session import Base
    from db import models  # noqa: F401

    db_path = tmp_path / "migrations.db"
    ini = os.path.join(os.path.dirname(__file__), "..", "..", "migrations", "alembic.ini")
    cfg = Config(ini)
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    command.upgrade(cfg, "head")

    engine = create_engine(f"sqlite:///{db_path}")
    migrated = set(inspect(engine).get_table_names()) - {"alembic_version"}
    model_tables = set(Base.metadata.tables)
    assert migrated == model_tables, (
        f"migrations and models disagree: only-migrations={sorted(migrated - model_tables)} "
        f"only-models={sorted(model_tables - migrated)}"
    )


def test_explicit_ini_url_wins_over_ambient_env(tmp_path, monkeypatch):
    """A leaked ambient DATABASE_URL must not redirect an explicit target.

    Regression: api integration fixtures set os.environ["DATABASE_URL"]
    without restoring it; env.py resolved env-before-ini, so a later
    alembic run with an explicit sqlalchemy.url silently migrated the
    leaked database instead (tmp file stayed empty).
    """
    from alembic import command
    from alembic.config import Config

    db_path = tmp_path / "explicit.db"
    stray = tmp_path / "stray.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{stray}")

    ini = os.path.join(os.path.dirname(__file__), "..", "..", "migrations", "alembic.ini")
    cfg = Config(ini)
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    command.upgrade(cfg, "head")

    engine = create_engine(f"sqlite:///{db_path}")
    assert "scans" in set(inspect(engine).get_table_names())
    # the stray target was never touched
    assert not stray.exists()
