"""Session factory and declarative base."""

from __future__ import annotations

import logging
import os
import time
from contextlib import contextmanager
from typing import Generator
from urllib.parse import urlparse

from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from db.connection.engine import get_engine

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


SessionLocal = sessionmaker(autocommit=False, autoflush=False, expire_on_commit=False)


def configure_session(engine=None) -> None:
    SessionLocal.configure(bind=engine or get_engine())


def init_db(engine=None) -> None:
    """Create all tables. Safe to call on every startup."""
    from db.models import (  # noqa: F401 — register models
        baseline,
        business_owner,
        business_process,
        certificate,
        certificate_usage,
        cloud_account,
        container_scan,
        crypto_asset,
        crypto_asset_evidence,
        drift_event,
        evidence_record,
        migration_project,
        network_scan_target,
        ot_device,
        policy_exception,
        repo_configuration,
        scan,
        scan_job,
        system,
        system_agility_score,
        system_asset,
        system_business_process,
        system_dependency,
        vendor,
        vendor_crypto,
        verification_log,
        vulnerability,
    )

    engine = engine or get_engine()
    configure_session(engine)
    _wait_for_database(engine)
    try:
        from db.connection.schema_ensure import ensure_schema_extensions

        ensure_schema_extensions(engine)
    except Exception:
        logger.debug("schema_extensions_skipped", exc_info=True)
    logger.info("database_schema_ready")


def _wait_for_database(engine) -> None:
    """Retry until Postgres is reachable. Compose `depends_on` is not enough on reboot."""
    deadline = time.monotonic() + int(os.environ.get("DB_WAIT_SECONDS", "90"))
    delay = 1.0
    last_error: Exception | None = None
    while True:
        try:
            Base.metadata.create_all(bind=engine)
            return
        except OperationalError as exc:
            last_error = exc
            if time.monotonic() >= deadline:
                break
            logger.warning(
                "database_unavailable_retrying host=%s sleep=%.1fs",
                _database_host(engine),
                delay,
            )
            time.sleep(delay)
            delay = min(delay * 1.5, 8.0)
    host = _database_host(engine)
    raise RuntimeError(
        f"Cannot reach database host {host!r}. Inside Docker Compose the hostname "
        "must be the service name 'postgres' on network cryptoscan-net. On the "
        "host use 127.0.0.1:55432 — never the name 'postgres'. Recreate the "
        "stack with: docker compose down && docker compose up --build. "
        f"Last error: {last_error}"
    ) from last_error


def _database_host(engine) -> str:
    try:
        url = str(engine.url)
        parsed = urlparse(url.replace("postgresql+psycopg2://", "postgresql://", 1))
        return parsed.hostname or url
    except Exception:
        return "?"


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_session() -> Generator[Session, None, None]:
    """FastAPI dependency."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
