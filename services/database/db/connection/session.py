"""Session factory and declarative base."""

from __future__ import annotations

import logging
import os
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Generator
from urllib.parse import urlparse

from sqlalchemy import inspect, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from db.connection.engine import get_engine

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


SessionLocal = sessionmaker(autocommit=False, autoflush=False, expire_on_commit=False)


def configure_session(engine=None) -> None:
    SessionLocal.configure(bind=engine or get_engine())
    # Tenant isolation is an ORM-level filter rather than a per-repository
    # argument, so that a query added later cannot forget it. Inert until a
    # request enters db.tenancy.tenant_scope().
    from db.tenancy import install_tenant_guard

    install_tenant_guard()


def init_db(engine=None) -> None:
    """Prepare sessions and verify the runtime database contract.

    Development and test environments may build a local database from
    metadata. Production is migration-owned: application processes never
    mutate a live schema with ``create_all`` and instead verify that the
    dedicated Alembic job reached the repository head.
    """
    from db.models import (  # noqa: F401 — register models
        api_key,
        app_setting,
        onboarding,
        control_plane,
        enterprise,
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
        network_inventory,
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
        user,
        vendor,
        vendor_crypto,
        vendor_profile,
        verification_log,
        vulnerability,
    )

    engine = engine or get_engine()
    configure_session(engine)
    _wait_for_database(engine)
    if _is_production():
        _assert_migrations_current(engine)
    else:
        try:
            from db.connection.schema_ensure import ensure_schema_extensions

            ensure_schema_extensions(engine)
        except Exception:
            logger.debug("schema_extensions_skipped", exc_info=True)
    logger.info("database_schema_ready", extra={"managed_by": "alembic" if _is_production() else "metadata"})


def _is_production() -> bool:
    return os.environ.get("ENVIRONMENT", "development").strip().lower() == "production"


def migration_status(engine=None) -> dict[str, object]:
    """Return the live Alembic status without changing the database.

    This is intentionally read-only so readiness probes can detect a database
    that falls behind after a rolling deployment without attempting a repair
    from an API or worker process.
    """
    engine = engine or get_engine()
    try:
        inspector = inspect(engine)
        if not inspector.has_table("alembic_version"):
            return {"status": "missing", "applied": [], "heads": []}
        with engine.connect() as connection:
            applied = sorted({
                str(row[0])
                for row in connection.execute(text("SELECT version_num FROM alembic_version"))
            })
        from alembic.config import Config
        from alembic.script import ScriptDirectory

        ini = Path(__file__).resolve().parents[2] / "migrations" / "alembic.ini"
        heads = sorted(ScriptDirectory.from_config(Config(str(ini))).get_heads())
        status = "current" if applied == heads and bool(heads) else "behind"
        return {"status": status, "applied": applied, "heads": heads}
    except Exception as exc:  # noqa: BLE001
        logger.warning("migration_status_probe_failed", extra={"error_type": type(exc).__name__})
        return {"status": "error", "applied": [], "heads": [], "error": type(exc).__name__}


def _assert_migrations_current(engine) -> None:
    """Fail closed when the durable database is absent or behind this build."""
    status = migration_status(engine)
    if status.get("status") != "current":
        raise RuntimeError(
            "Production database migrations are not at the repository head; "
            "run alembic upgrade head before starting API or worker processes"
        )


def _wait_for_database(engine) -> None:
    """Retry until the configured database is reachable without changing schema."""
    deadline = time.monotonic() + int(os.environ.get("DB_WAIT_SECONDS", "90"))
    delay = 1.0
    last_error: Exception | None = None
    while True:
        try:
            # Reachability probing must not create or mutate schema.
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
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
