"""
Worker Test Fixtures
"""
import pytest
import tempfile
import shutil
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db.models.base import Base
from db.models import (  # noqa: F401 — register metadata
    baseline,
    container_scan,
    crypto_asset,
    crypto_asset_evidence,
    drift_event,
    evidence_record,
    repo_configuration,
    scan,
    scan_job,
    system,
    system_asset,
    system_dependency,
    verification_log,
    vulnerability,
)


@pytest.fixture
def temp_workspace():
    """Temporary workspace directory"""
    workspace = Path(tempfile.mkdtemp())
    yield workspace
    shutil.rmtree(workspace)


@pytest.fixture
def test_db():
    """In-memory test database (SQLite). Set CRYPTOSCAN_TEST_DB_BACKEND=postgresql to run the whole suite on PostgreSQL."""
    import os

    backend = os.environ.get("CRYPTOSCAN_TEST_DB_BACKEND", "sqlite")
    if backend == "sqlite":
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        session = sessionmaker(bind=engine)()
        yield session
        session.close()
        return
    from db.testing import drop_engine, estate_engine

    engine = estate_engine(backend)
    if engine is None:
        pytest.skip("no PostgreSQL available")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()
        drop_engine(engine)


@pytest.fixture
def mock_scan_job():
    """Mock scan job"""
    from worker.core.job_consumer import ScanJob
    
    return ScanJob(
        job_id="test-job-123",
        job_type="GITHUB_WEBHOOK",
        target_repo="https://github.com/test/repo",
        target_commit="abc123",
        target_branch="main",
        triggered_by="test-user",
        created_at="2024-01-15T10:00:00Z"
    )


@pytest.fixture
def mock_findings():
    """Mock scan findings"""
    from shared_models.finding import RawFinding
    
    return [
        RawFinding(
            algorithm="DES",
            file_path="Payment.java",
            line_number=247,
            confidence="HIGH"
        ),
        RawFinding(
            algorithm="AES",
            mode="GCM",
            file_path="Auth.java",
            line_number=89,
            confidence="HIGH"
        )
    ]

@pytest.fixture(params=["sqlite", "postgresql"])
def estate_db(request):
    """The end-to-end estate tests run twice: SQLite in memory and a real PostgreSQL (env URL or embedded pgserver).

    PostgreSQL is *skipped*, never faked, when no server is available."""
    from db.testing import drop_engine, estate_engine

    engine = estate_engine(request.param)
    if engine is None:
        pytest.skip("no PostgreSQL: set CRYPTOSCAN_TEST_DATABASE_URL or pip install pgserver")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    try:
        yield session
    finally:
        session.close()
        drop_engine(engine)
