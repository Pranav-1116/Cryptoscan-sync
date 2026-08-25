"""Session factory and declarative base."""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Generator

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
        cloud_account,
        container_scan,
        crypto_asset,
        crypto_asset_evidence,
        drift_event,
        evidence_record,
        migration_project,
        network_scan_target,
        repo_configuration,
        scan,
        scan_job,
        system,
        system_asset,
        system_business_process,
        system_dependency,
        vendor,
        verification_log,
        vulnerability,
    )

    engine = engine or get_engine()
    configure_session(engine)
    Base.metadata.create_all(bind=engine)
    logger.info("database_schema_ready")


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
