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
    # The second lock, on PostgreSQL only: every transaction carries the tenant
    # setting migration 0132's policy reads, so a connection this process does not
    # own — a psql prompt, a BI tool — reads no tenant's rows at all. Inert on
    # SQLite, and inert here until the policy exists, which is the same silence
    # the ORM guard has outside a scope.
    from db.rls import install_rls_binder

    install_rls_binder()


def init_db(engine=None) -> None:
    """Prepare sessions and verify the runtime database contract.

    Only an unstamped SQLite development/test database may be built from
    metadata. Stamped databases are migration-owned; a behind or unreadable
    migration state fails before any schema reconciliation.
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
        _assert_production_rls(engine)
        managed_by = "alembic"
    else:
        from db.connection.schema_ensure import ensure_schema_extensions

        managed_by = "metadata" if ensure_schema_extensions(engine) else "alembic"
    logger.info("database_schema_ready", extra={"managed_by": managed_by})


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


def _assert_production_rls(engine) -> None:
    """Refuse a runtime connection that can bypass the tenant policies."""
    from db.rls import enforcement

    with engine.connect() as connection:
        report = enforcement(connection)
    tables = int(report.get("tenant_tables") or 0)
    if (report.get("supported") is not True or report.get("binds_this_role") is not True
            or tables < 1 or int(report.get("tables_with_rls_enabled") or 0) < tables
            or int(report.get("tables_with_rls_forced") or 0) < tables
            or int(report.get("policies") or 0) < tables):
        logger.error("production_database_rls_unavailable", extra={
            "role": report.get("role"), "superuser": report.get("superuser"),
            "bypassrls": report.get("bypassrls"), "tenant_tables": tables,
            "enabled": report.get("tables_with_rls_enabled"),
            "forced": report.get("tables_with_rls_forced"),
        })
        raise RuntimeError(
            "Production runtime database role must be non-superuser, NOBYPASSRLS, "
            "and bound by enabled and forced tenant RLS on every tenant table; "
            "provision a separate bank-owned app role after migrations"
        )


def _allow_metadata_bootstrap(engine) -> bool:
    """Only an unstamped SQLite development/test database may use model DDL."""
    if _is_production():
        raise RuntimeError("Production schema changes require alembic upgrade head")
    status = migration_status(engine)
    if status["status"] == "current":
        return False  # Alembic owns this schema; do not create future indexes.
    if status["status"] == "missing" and engine.dialect.name == "sqlite":
        return True
    raise RuntimeError(
        f"Database migration status is {status['status']} "
        f"(applied: {status['applied']}, repository heads: {status['heads']}). "
        "Set DATABASE_URL for this database and run "
        "alembic -c services/database/migrations/alembic.ini upgrade head "
        "from the repository root before starting API or workers. "
        "Metadata bootstrap is only allowed for unstamped SQLite development/test databases."
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
