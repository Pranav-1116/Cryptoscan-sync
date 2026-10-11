"""
Alembic migration environment configuration.

Configures the migration context for both offline (SQL generation)
and online (direct DB connection) migration modes.
"""
from __future__ import annotations

import logging
import os
from logging.config import fileConfig
from urllib.parse import quote_plus

from alembic import context
from sqlalchemy import engine_from_config, pool

# Import all models to register them with the metadata
from db.models.base import Base
from db.models.scan import Scan  # noqa: F401
from db.models.evidence_record import EvidenceRecord  # noqa: F401
from db.models.verification_log import VerificationLog  # noqa: F401
from db.models.baseline import Baseline  # noqa: F401
from db.models.drift_event import DriftEvent  # noqa: F401
from db.models.scan_job import ScanJob  # noqa: F401
from db.models.repo_configuration import RepoConfiguration  # noqa: F401

# Alembic Config object
config = context.config

# Configure Python logging from the alembic.ini file.
#
# disable_existing_loggers=False is load-bearing: with the default (True),
# fileConfig sets ``disabled = True`` on every logger that already exists and
# is not named in alembic.ini's [loggers] section. When alembic runs inside a
# live process (tests, a worker that migrates at boot, ops tooling), that
# permanently silences every other module's stdlib logging for the rest of
# the process — records are dropped before any handler runs.
if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

# Use our ORM models' metadata for autogenerate
target_metadata = Base.metadata


def get_database_url() -> str:
    """
    Build database URL from environment variables.

    Environment variables:
        DATABASE_URL: Full connection URL (takes precedence)
        DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD: Components

    Returns:
        PostgreSQL connection URL.

    Raises:
        ValueError: If required config is missing.
    """
    # Precedence: an explicit -c ini URL wins (that is what "alembic -c
    # <file>" means), then the ambient DATABASE_URL (the deployment path —
    # alembic.ini ships an empty sqlalchemy.url), then DB_* components.
    # Env-first previously let a leaked DATABASE_URL silently redirect an
    # explicitly-targeted migration to another database.
    url = (config.get_main_option("sqlalchemy.url") or "").strip()
    url = url or os.environ.get("DATABASE_URL")

    if url:
        # Normalize scheme for psycopg2
        if url.startswith("postgres://"):
            url = "postgresql+psycopg2://" + url[len("postgres://"):]
        elif url.startswith("postgresql://") and "+psycopg2" not in url:
            url = "postgresql+psycopg2://" + url[len("postgresql://"):]
        return url

    # Build from components
    host = os.environ.get("DB_HOST", "localhost")
    port = os.environ.get("DB_PORT", "5432")
    name = os.environ.get("DB_NAME", "cryptoscan")
    user = os.environ.get("DB_USER", "cryptoscan")
    password = quote_plus(os.environ.get("DB_PASSWORD", ""))

    return f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{name}"


def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode.

    Generates SQL scripts without connecting to the database.
    Useful for reviewing migrations before applying.
    """
    url = get_database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        # Include all schema changes
        compare_type=True,
        compare_server_default=True,
        include_schemas=True,
        render_as_batch=False,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """
    Run migrations in 'online' mode.

    Directly connects to the database and applies migrations.
    """
    # Override sqlalchemy.url with our computed URL
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = get_database_url()

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,  # Use NullPool for migrations
    )

    def _current_version(connection) -> str | None:
        """Current alembic version, or None before the version table exists."""
        from sqlalchemy import inspect

        try:
            if not inspect(connection).has_table("alembic_version"):
                return None
            row = connection.exec_driver_sql("SELECT version_num FROM alembic_version").first()
            return str(row[0]) if row else None
        except Exception:
            return None

    def _mode() -> str:
        cmd_opts = getattr(config, "cmd_opts", None)
        return getattr(cmd_opts, "prog", "upgrade") or "upgrade"

    with connectable.connect() as connection:
        version_before = _current_version(connection)
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            # Enable type comparison for detecting column type changes
            compare_type=True,
            # Enable server default comparison
            compare_server_default=True,
            # Include schemas
            include_schemas=True,
            # Transaction per migration (not per batch)
            transaction_per_migration=True,
            # PostgreSQL-specific: lock the table during migration
            render_as_batch=False,
        )

        with context.begin_transaction():
            context.run_migrations()

        # Schema-migration auditing (audit 78): one hash-chained audit row
        # per applied revision. Best-effort — bootstrap revisions that ran
        # before audit_log existed are not back-filled, and an audit-write
        # failure never fails an already-committed migration.
        version_after = _current_version(connection)
        if version_after != version_before:
            try:
                from alembic.script import ScriptDirectory

                from db.migration_audit import audit_applied_migrations

                audit_applied_migrations(
                    connection,
                    before=version_before,
                    after=version_after,
                    script_dir=ScriptDirectory.from_config(config),
                    mode=_mode(),
                )
            except Exception:
                logging.getLogger(__name__).warning(
                    "migration_audit_hook_failed: %s -> %s",
                    version_before, version_after, exc_info=True,
                )


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()