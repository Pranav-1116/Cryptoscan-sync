"""
SQLAlchemy engine factory for CryptoScan database connections.

Provides connection pooling, SSL support, and health checking
for production PostgreSQL connections.
"""
from __future__ import annotations

import logging
import os
from typing import Any
from urllib.parse import quote_plus

from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.pool import QueuePool

logger = logging.getLogger(__name__)


def build_database_url(
    host: str,
    port: int,
    database: str,
    username: str,
    password: str,
    ssl_mode: str = "prefer",
) -> str:
    """
    Build a PostgreSQL connection URL with proper encoding.

    Args:
        host: Database host.
        port: Database port.
        database: Database name.
        username: Database user.
        password: Database password (will be URL-encoded).
        ssl_mode: PostgreSQL SSL mode.

    Returns:
        Fully formed PostgreSQL connection URL.
    """
    encoded_password = quote_plus(password)
    return (
        f"postgresql+psycopg2://{username}:{encoded_password}"
        f"@{host}:{port}/{database}"
        f"?sslmode={ssl_mode}"
    )


def create_db_engine(
    database_url: str | None = None,
    *,
    pool_size: int = 10,
    max_overflow: int = 20,
    pool_timeout: int = 30,
    pool_recycle: int = 3600,
    pool_pre_ping: bool = True,
    echo: bool = False,
    echo_pool: bool = False,
    application_name: str = "cryptoscan",
    connect_timeout: int = 10,
    statement_timeout_ms: int = 30000,
) -> Engine:
    """
    Create a production-grade SQLAlchemy engine.

    Uses connection pooling with health checking. All parameters
    can be overridden; defaults are production-appropriate.

    Args:
        database_url: Full PostgreSQL URL. Falls back to env vars.
        pool_size: Number of connections in the pool.
        max_overflow: Extra connections beyond pool_size.
        pool_timeout: Seconds to wait for a connection.
        pool_recycle: Seconds before recycling a connection.
        pool_pre_ping: Test connections before use.
        echo: Log all SQL statements.
        echo_pool: Log pool events.
        application_name: PostgreSQL application_name parameter.
        connect_timeout: TCP connection timeout in seconds.
        statement_timeout_ms: Max statement execution time in ms.

    Returns:
        Configured SQLAlchemy Engine.

    Raises:
        ValueError: If database URL cannot be determined.
    """
    if database_url is None:
        database_url = _build_url_from_env()

    if not database_url:
        raise ValueError(
            "Database URL is required. Set DATABASE_URL environment variable "
            "or provide database_url parameter."
        )

    connect_args: dict[str, Any] = {
        "connect_timeout": connect_timeout,
        "application_name": application_name,
        "options": f"-c statement_timeout={statement_timeout_ms}",
    }

    engine = create_engine(
        database_url,
        poolclass=QueuePool,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_timeout=pool_timeout,
        pool_recycle=pool_recycle,
        pool_pre_ping=pool_pre_ping,
        echo=echo,
        echo_pool=echo_pool,
        connect_args=connect_args,
        # Ensure JSON columns are handled correctly
        json_serializer=_json_serializer,
        json_deserializer=_json_deserializer,
    )

    # Register event listeners
    _register_engine_events(engine)

    logger.info(
        "Database engine created",
        extra={
            "pool_size": pool_size,
            "max_overflow": max_overflow,
            "pool_pre_ping": pool_pre_ping,
        },
    )

    return engine


def _build_url_from_env() -> str | None:
    """Build database URL from environment variables."""
    # First check for direct URL
    direct_url = os.environ.get("DATABASE_URL")
    if direct_url:
        # Convert postgres:// to postgresql+psycopg2://
        if direct_url.startswith("postgres://"):
            direct_url = "postgresql+psycopg2://" + direct_url[len("postgres://"):]
        elif direct_url.startswith("postgresql://"):
            direct_url = "postgresql+psycopg2://" + direct_url[len("postgresql://"):]
        return direct_url

    # Build from components
    host = os.environ.get("DB_HOST")
    port = os.environ.get("DB_PORT", "5432")
    database = os.environ.get("DB_NAME")
    username = os.environ.get("DB_USER")
    password = os.environ.get("DB_PASSWORD", "")

    if not all([host, database, username]):
        return None

    return build_database_url(
        host=host,
        port=int(port),
        database=database,
        username=username,
        password=password,
        ssl_mode=os.environ.get("DB_SSL_MODE", "prefer"),
    )


def _register_engine_events(engine: Engine) -> None:
    """Register SQLAlchemy engine event handlers."""

    @event.listens_for(engine, "connect")
    def set_pg_settings(dbapi_connection, connection_record):
        """Set per-connection PostgreSQL settings."""
        cursor = dbapi_connection.cursor()
        # Set timezone to UTC for consistent timestamp handling
        cursor.execute("SET TIME ZONE 'UTC'")
        cursor.close()

    @event.listens_for(engine, "checkout")
    def receive_checkout(dbapi_connection, connection_record, connection_proxy):
        """Log connection checkouts for monitoring."""
        logger.debug("DB connection checked out from pool")

    @event.listens_for(engine, "checkin")
    def receive_checkin(dbapi_connection, connection_record):
        """Log connection returns to pool."""
        logger.debug("DB connection returned to pool")


def _json_serializer(obj: Any) -> str:
    """Custom JSON serializer for SQLAlchemy."""
    import json
    return json.dumps(obj, default=str)


def _json_deserializer(s: str) -> Any:
    """Custom JSON deserializer for SQLAlchemy."""
    import json
    return json.loads(s)


def check_db_health(engine: Engine) -> dict[str, Any]:
    """
    Check database connectivity and basic health.

    Args:
        engine: SQLAlchemy engine to check.

    Returns:
        Dict with health status information.

    Raises:
        OperationalError: If database is unreachable.
    """
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("SELECT version(), current_database(), NOW() AT TIME ZONE 'UTC' as now")
            )
            row = result.fetchone()

            return {
                "status": "healthy",
                "database": row.current_database,
                "server_time": row.now.isoformat() if row.now else None,
                "pg_version": row.version,
                "pool_size": engine.pool.size(),
                "checked_in": engine.pool.checkedin(),
                "checked_out": engine.pool.checkedout(),
                "overflow": engine.pool.overflow(),
            }
    except OperationalError as e:
        logger.error("Database health check failed", exc_info=True)
        return {
            "status": "unhealthy",
            "error": str(e),
        }