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
    # Alembic bookkeeping is intentionally outside the application ORM.
    migrated = set(inspect(engine).get_table_names()) - {
        "alembic_version",
        "_alembic_0078_indexes",
    }
    model_tables = set(Base.metadata.tables)
    assert migrated == model_tables, (
        f"migrations and models disagree: only-migrations={sorted(migrated - model_tables)} "
        f"only-models={sorted(model_tables - migrated)}"
    )


def test_upgrade_does_not_disable_other_loggers(tmp_path):
    """fileConfig(alembic.ini) must not poison the process's other loggers.

    Regression: env.py used fileConfig() with the default
    ``disable_existing_loggers=True``, which sets ``disabled = True`` on every
    existing logger not named in alembic.ini. Any module imported before an
    in-process ``alembic upgrade`` (worker, api, this test suite) had its
    logging silently killed for the rest of the process — e.g.
    worker.test_quantum_stage caplog assertions started failing after the
    database tests ran.
    """
    import logging

    from alembic import command
    from alembic.config import Config

    victim = logging.getLogger("cryptoscan.migration_chain_probe")
    assert victim.disabled is False  # fresh logger, enabled
    before = victim.level

    db_path = tmp_path / "migrations.db"
    ini = os.path.join(os.path.dirname(__file__), "..", "..", "migrations", "alembic.ini")
    cfg = Config(ini)
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    command.upgrade(cfg, "head")

    assert victim.disabled is False, (
        "alembic upgrade disabled an unrelated pre-existing logger; "
        "env.py must call fileConfig(disable_existing_loggers=False)"
    )
    assert victim.level == before


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
