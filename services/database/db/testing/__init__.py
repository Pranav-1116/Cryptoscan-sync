"""Test-only database backends: SQLite in memory, or a real PostgreSQL.

`estate_engine(backend)` gives the end-to-end estate tests (worker pipeline, API read-back) a second, PostgreSQL
backend so JSON columns, timestamps, transactions and `text` searches are exercised against the engine banks
actually deploy. PostgreSQL comes from, in order:

1. ``CRYPTOSCAN_TEST_DATABASE_URL`` — an existing server (CI service container, a developer's docker compose);
2. ``pgserver`` (embedded PostgreSQL 16 wheel, ``pip install pgserver``) — started once per process in a temp dir;
3. otherwise the test is *skipped*, never silently downgraded to SQLite.

Not imported by production code.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


import atexit
import os
import tempfile
import uuid
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.pool import StaticPool

_EMBEDDED: dict[str, Any] = {}


def _cleanup_embedded_server() -> None:
    """Stop pgserver without writing into pytest's closed capture stream.

    The embedded server is cleaned up by ``atexit`` after pytest has closed its
    capture handlers. pgserver logs normal shutdown at INFO, but the closed
    handler turns those harmless messages into logging tracebacks. Suppress
    logging only for this final cleanup operation; the server is still stopped
    and test-time failures are not hidden.
    """
    server = _EMBEDDED.get("server")
    if server is None:
        return
    previous_disable = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    try:
        server.cleanup()
    finally:
        logging.disable(previous_disable)


def postgres_url() -> str | None:
    """A PostgreSQL URL for tests, or None when no server can be had."""
    url = os.environ.get("CRYPTOSCAN_TEST_DATABASE_URL")
    if url:
        return url
    if "url" in _EMBEDDED:
        return _EMBEDDED["url"]
    try:
        import pgserver  # type: ignore
    except Exception as _handler_exc:
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        return None
    try:
        pgdata = tempfile.mkdtemp(prefix="cryptoscan-pg-")
        server = pgserver.get_server(pgdata)
        url = server.get_uri()
        if url.startswith("postgresql://"):
            url = "postgresql+psycopg2://" + url[len("postgresql://"):]
        _EMBEDDED["server"] = server
        _EMBEDDED["url"] = url
        atexit.register(_cleanup_embedded_server)
        return url
    except Exception as _handler_exc:
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        return None


def estate_engine(backend: str) -> Engine | None:
    """Engine for ``backend`` in {"sqlite", "postgresql"}; None when PostgreSQL is unavailable.

    Each PostgreSQL engine gets its own fresh database so tests never see each other's rows.
    """
    if backend == "sqlite":
        return create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    base = postgres_url()
    if not base:
        return None
    dbname = "cs_test_" + uuid.uuid4().hex[:12]
    admin = create_engine(base, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{dbname}"'))
    admin.dispose()
    from sqlalchemy.engine import make_url

    return create_engine(make_url(base).set(database=dbname))


def drop_engine(engine: Engine) -> None:
    """Dispose and, for PostgreSQL, drop the per-test database."""
    url = engine.url
    engine.dispose()
    if url.get_backend_name() != "postgresql":
        return
    base = postgres_url()
    if not base:
        return
    admin = create_engine(base, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{url.database}" WITH (FORCE)'))
    admin.dispose()
