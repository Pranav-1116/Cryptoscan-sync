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


def _pool_settings() -> dict[str, int]:
    """Pool sizing from the environment (DB_POOL_SIZE / DB_MAX_OVERFLOW /
    DB_POOL_TIMEOUT / DB_POOL_RECYCLE), validated, with the measured
    defaults unchanged for every deployment that sets none of them."""

    def _int(name: str, default: int, minimum: int = 1) -> int:
        raw = os.environ.get(name, "").strip()
        if not raw:
            return default
        try:
            value = int(raw)
        except ValueError:
            raise ValueError(f"{name} must be an integer, got {raw!r}")
        if value < minimum:
            raise ValueError(f"{name} must be >= {minimum}, got {value}")
        return value

    return {
        "pool_size": _int("DB_POOL_SIZE", 10),
        "max_overflow": _int("DB_MAX_OVERFLOW", 20, minimum=0),
        "pool_timeout": _int("DB_POOL_TIMEOUT", 10),
        "pool_recycle": _int("DB_POOL_RECYCLE", 3600),
    }


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
            # Bursts above pool_size (a dashboard with 20 open tabs, a load test) must
            # not queue for the pool timeout; WAL readers are cheap, so allow
            # overflow connections that are closed again when the burst passes.
            **_pool_settings(),
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
    pool = _pool_settings()
    engine = create_engine(
        database_url,
        poolclass=QueuePool,
        pool_size=pool["pool_size"],
        max_overflow=pool["max_overflow"],
        pool_timeout=pool["pool_timeout"],
        pool_pre_ping=True,
        pool_recycle=pool["pool_recycle"],
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
        except Exception as dispose_exc:  # noqa: BLE001
            logger.warning(
                "stale_database_engine_dispose_failed",
                extra={"error_type": type(dispose_exc).__name__},
            )
        try:
            from db.connection.session import configure_session

            configure_session(_ENGINE)
        except Exception as configure_exc:  # noqa: BLE001
            logger.exception(
                "database_session_reconfigure_failed",
                extra={"error_type": type(configure_exc).__name__},
            )
    return _ENGINE


def set_engine(engine: Engine) -> None:
    """Pin an explicit engine (tests, one-off scripts); env changes won't swap it."""
    global _ENGINE, _ENGINE_URL
    _ENGINE = engine
    _ENGINE_URL = None


def check_db_health(engine: Engine | None = None) -> dict[str, Any]:
    try:
        engine = engine or get_engine()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"status": "healthy", "dialect": engine.dialect.name}
    except Exception as exc:
        # Health surfaces are public; driver messages/tracebacks can expose
        # connection credentials and SQL. Keep failure visible, not its payload.
        logger.error("database_health_failed", extra={"error_type": type(exc).__name__})
        return {"status": "unhealthy", "error": "Database health probe failed", "error_type": type(exc).__name__}


def pool_status(engine: Engine | None = None) -> dict[str, Any]:
    """Connection-pool observability: the numbers an operator needs before
    a pool shortage becomes an outage (checked-out, overflow in use,
    configured ceilings), and nothing the pool cannot honestly know.

    ``pool.dbapi_connections`` exists only on QueuePool-style pools; a
    StaticPool (SQLite ``:memory:``) reports its single connection. A pool
    under pressure (>= 90% of ``pool_size + max_overflow`` checked out)
    reports ``pressure: true`` — the health layer turns that into a
    DEGRADED signal, never silence.
    """
    engine = engine or get_engine()
    pool = engine.pool
    size = getattr(pool, "size", lambda: 1)()
    max_overflow = getattr(pool, "_max_overflow", 0)
    checkedout = getattr(pool, "checkedout", lambda: 0)()
    overflow = getattr(pool, "overflow", lambda: 0)()
    capacity = size + max_overflow
    return {
        "dialect": engine.dialect.name,
        "pool_class": type(pool).__name__,
        "pool_size": size,
        "max_overflow": max_overflow,
        "pool_timeout": getattr(pool, "_timeout", None),
        "pool_recycle": getattr(pool, "_recycle", None),
        "checkedout": checkedout,
        "overflow": overflow,
        "capacity": capacity,
        "pressure": bool(capacity and checkedout >= 0.9 * capacity),
    }
