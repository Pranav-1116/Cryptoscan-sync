"""
Worker Test Fixtures
"""
import pytest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import MagicMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database.db.models.base import Base


@pytest.fixture
def temp_workspace():
    """Temporary workspace directory"""
    workspace = Path(tempfile.mkdtemp())
    yield workspace
    shutil.rmtree(workspace)


@pytest.fixture
def test_db():
    """In-memory test database"""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


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