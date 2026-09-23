"""SQLAlchemy engine factory — PostgreSQL in production, SQLite locally."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus

from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.pool import QueuePool, StaticPool

logger = logging.getLogger(__name__)

_ENGINE: Engine | None = None


def build_database_url(
    host: str,
    port: int,
    database: str,
    username: str,
    password: str,
    ssl_mode: str = "prefer",
) -> str:
    encoded_password = quote_plus(password)
    return (
        f"postgresql+psycopg2://{username}:{encoded_password}"
        f"@{host}:{port}/{database}?sslmode={ssl_mode}"
    )


def _normalize_url(database_url: str) -> str:
    if database_url.startswith("postgres://"):
        return "postgresql+psycopg2://" + database_url[len("postgres://") :]
    if database_url.startswith("postgresql://") and "+psycopg2" not in database_url:
        return "postgresql+psycopg2://" + database_url[len("postgresql://") :]
    return database_url


def create_db_engine(
    database_url: str | None = None,
    *,
    echo: bool = False,
    application_name: str = "cryptoscan",
) -> Engine:
    if database_url is None:
        database_url = os.environ.get("DATABASE_URL", "sqlite:///./data/cryptoscan.db")
    database_url = _normalize_url(database_url)

    if database_url.startswith("sqlite"):
        # Ensure parent dir exists for file-backed sqlite
        if database_url.startswith("sqlite:///") and ":memory:" not in database_url:
            raw_path = database_url.replace("sqlite:///", "", 1)
            if raw_path.startswith("./"):
                db_path = Path(raw_path)
            else:
                db_path = Path(raw_path)
            db_path.parent.mkdir(parents=True, exist_ok=True)
        in_memory = ":memory:" in database_url
        engine = create_engine(
            database_url,
            echo=echo,
            connect_args={"check_same_thread": False},
            # File-backed SQLite + multi-threaded workers: reuse connections
            # from a small pool (WAL allows concurrent readers; the single
            # writer is serialized by SQLite with busy_timeout below).
            # NullPool measured 2ms+ of connect+PRAGMA overhead per request.
            # :memory: must share one connection.
            poolclass=StaticPool if in_memory else QueuePool,
            pool_size=10,
            max_overflow=0,
        )

        @event.listens_for(engine, "connect")
        def _sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.close()

        return engine

    connect_args: dict[str, Any] = {
        "connect_timeout": 10,
        "application_name": application_name,
        "options": "-c statement_timeout=30000",
    }
    engine = create_engine(
        database_url,
        poolclass=QueuePool,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,
        pool_recycle=3600,
        echo=echo,
        connect_args=connect_args,
    )

    @event.listens_for(engine, "connect")
    def _pg_settings(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("SET TIME ZONE 'UTC'")
        cursor.close()

    logger.info("database_engine_created", extra={"dialect": engine.dialect.name})
    return engine


_ENGINE_URL: str | None = None


def _configured_url() -> str:
    return _normalize_url(os.environ.get("DATABASE_URL", "sqlite:///./data/cryptoscan.db"))


def get_engine() -> Engine:
    """The process engine for the *currently configured* ``DATABASE_URL``.

    The singleton follows the environment: if ``DATABASE_URL`` changed since
    the engine was built (a test module pointing at its own file, a process
    reconfigured between runs), the stale engine is disposed and a new one is
    created for the new URL. An engine installed explicitly with
    :func:`set_engine` is pinned and never swapped by this check.
    """
    global _ENGINE, _ENGINE_URL
    url = _configured_url()
    if _ENGINE is None:
        _ENGINE = create_db_engine(url)
        _ENGINE_URL = url
    elif _ENGINE_URL is not None and _ENGINE_URL != url:
        stale = _ENGINE
        _ENGINE = create_db_engine(url)
        _ENGINE_URL = url
        try:
            stale.dispose()
        except Exception:  # noqa: BLE001
            pass
        try:
            from db.connection.session import configure_session

            configure_session(_ENGINE)
        except Exception:  # noqa: BLE001
            pass
    return _ENGINE


def set_engine(engine: Engine) -> None:
    """Pin an explicit engine (tests, one-off scripts); env changes won't swap it."""
    global _ENGINE, _ENGINE_URL
    _ENGINE = engine
    _ENGINE_URL = None


def check_db_health(engine: Engine | None = None) -> dict[str, Any]:
    engine = engine or get_engine()
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"status": "healthy", "dialect": engine.dialect.name}
    except Exception as exc:
        logger.exception("database_health_failed")
        return {"status": "unhealthy", "error": str(exc)}
