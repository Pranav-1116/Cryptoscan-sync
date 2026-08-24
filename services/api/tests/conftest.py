"""
pytest fixtures for API integration tests.
Provides TestClient, mock repositories, and auth fixtures.
"""
from __future__ import annotations

from typing import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from api.config.settings import get_settings
from api.main import create_app


# ---------------------------------------------------------------------------
# Settings override for tests
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def override_settings(monkeypatch):
    """Override settings for test environment."""
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "test-webhook-secret-abc123")
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test_db")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/1")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ENVIRONMENT", "test")
    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Mock repositories
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_scan_repo() -> MagicMock:
    repo = MagicMock()
    repo.list_scans = AsyncMock(return_value=([], 0))
    repo.get_by_id = AsyncMock(return_value=None)
    return repo


@pytest.fixture
def mock_evidence_repo() -> MagicMock:
    repo = MagicMock()
    repo.list_by_scan = AsyncMock(return_value=([], 0))
    repo.get_by_id = AsyncMock(return_value=None)
    return repo


@pytest.fixture
def mock_drift_repo() -> MagicMock:
    repo = MagicMock()
    repo.list_events = AsyncMock(return_value=([], 0))
    repo.get_by_id = AsyncMock(return_value=None)
    repo.acknowledge = AsyncMock(return_value=None)
    return repo


@pytest.fixture
def mock_job_repo() -> MagicMock:
    repo = MagicMock()
    repo.create = AsyncMock()
    repo.create_from_webhook = AsyncMock()
    repo.get_by_id = AsyncMock(return_value=None)
    repo.list_jobs = AsyncMock(return_value=([], 0))
    repo.update_status = AsyncMock()
    return repo


@pytest.fixture
def mock_baseline_repo() -> MagicMock:
    repo = MagicMock()
    repo.list_baselines = AsyncMock(return_value=([], 0))
    repo.get_by_id = AsyncMock(return_value=None)
    repo.create = AsyncMock()
    repo.supersede_active = AsyncMock()
    repo.set_status = AsyncMock()
    return repo


@pytest.fixture
def mock_repo_config_repo() -> MagicMock:
    repo = MagicMock()
    repo.list_configs = AsyncMock(return_value=([], 0))
    repo.get_by_id = AsyncMock(return_value=None)
    repo.get_by_url = AsyncMock(return_value=None)
    repo.create = AsyncMock()
    repo.update = AsyncMock()
    repo.delete = AsyncMock()
    return repo


@pytest.fixture
def mock_db_session() -> MagicMock:
    session = MagicMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.execute = AsyncMock()
    return session


# ---------------------------------------------------------------------------
# App + client fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def app(
    mock_scan_repo,
    mock_evidence_repo,
    mock_drift_repo,
    mock_job_repo,
    mock_baseline_repo,
    mock_repo_config_repo,
    mock_db_session,
):
    """Create FastAPI app with mocked dependencies."""
    from api import dependencies

    application = create_app()

    # Override DI providers
    application.dependency_overrides[dependencies.get_db_session] = (
        lambda: mock_db_session
    )
    application.dependency_overrides[dependencies.get_scan_repository] = (
        lambda: mock_scan_repo
    )
    application.dependency_overrides[dependencies.get_evidence_repository] = (
        lambda: mock_evidence_repo
    )
    application.dependency_overrides[dependencies.get_drift_repository] = (
        lambda: mock_drift_repo
    )
    application.dependency_overrides[dependencies.get_job_repository] = (
        lambda: mock_job_repo
    )
    application.dependency_overrides[dependencies.get_baseline_repository] = (
        lambda: mock_baseline_repo
    )
    application.dependency_overrides[dependencies.get_repo_config_repository] = (
        lambda: mock_repo_config_repo
    )

    return application


@pytest_asyncio.fixture
async def client(app) -> AsyncGenerator[AsyncClient, None]:
    """Unauthenticated async test client."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac


@pytest_asyncio.fixture
async def authenticated_client(app) -> AsyncGenerator[AsyncClient, None]:
    """Authenticated async test client (mocked auth)."""
    from api import dependencies

    # Override auth to always return test user
    app.dependency_overrides[dependencies.get_current_user] = (
        lambda: "testuser"
    )

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac