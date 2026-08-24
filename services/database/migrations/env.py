"""
Alembic migration environment configuration.

Configures the migration context for both offline (SQL generation)
and online (direct DB connection) migration modes.
"""
from __future__ import annotations

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

# Configure Python logging from the alembic.ini file
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

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
    # Check for direct URL first
    url = os.environ.get("DATABASE_URL") or config.get_main_option("sqlalchemy.url")

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

    with connectable.connect() as connection:
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


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()