"""
pytest fixtures for API integration tests.
Provides TestClient, mock repositories, and auth fixtures.
"""
from __future__ import annotations

from typing import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock

import pytest
try:
    import pytest_asyncio
except ImportError:  # pragma: no cover
    pytest_asyncio = None
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
    # This harness mocks the repositories entirely (no real DB), so tenancy
    # resolves to the PLATFORM context: tenant-scoped routes behave like the
    # pre-SaaS estate here. Real-DB tenancy behavior is covered by
    # integration/test_saas_tenancy.py.
    from api.dependencies import TenantContext

    application.dependency_overrides[dependencies.get_tenant_context] = lambda: TenantContext(
        username="testuser", tenant_id=None, tenant_role=None, is_platform_admin=True
    )

    return application


def _async_fixture(func):
    if pytest_asyncio is not None:
        return pytest_asyncio.fixture(func)
    return pytest.fixture(func)


@_async_fixture
async def client(app) -> AsyncGenerator[AsyncClient, None]:
    """Unauthenticated async test client."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac


@_async_fixture
async def authenticated_client(app) -> AsyncGenerator[AsyncClient, None]:
    """Authenticated async test client (mocked auth)."""
    from api import dependencies

    # Override auth to always return test user
    app.dependency_overrides[dependencies.get_current_user] = (
        lambda: "testuser"
    )
    # Role-gated dependencies default to the same test user (admin powers).
    app.dependency_overrides[dependencies.require_admin] = lambda: "testuser"
    app.dependency_overrides[dependencies.require_auditor] = lambda: "testuser"

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac

@_async_fixture
async def lowpriv_client(app) -> AsyncGenerator[AsyncClient, None]:
    """Authenticated client with a read-only role (fail-closed authorization).

    get_current_user succeeds (the session is valid) but every role-gated
    dependency is forced to raise 403, so mutating endpoints that rely on
    require_roles/require_auditor/require_admin must deny the caller.
    """
    from fastapi import HTTPException

    from api import dependencies

    app.dependency_overrides[dependencies.get_current_user] = lambda: "lowpriv"

    def _deny(_request=None):
        raise HTTPException(status_code=403, detail="insufficient role")

    app.dependency_overrides[dependencies.require_admin] = _deny
    app.dependency_overrides[dependencies.require_auditor] = _deny

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac


# ---------------------------------------------------------------------------
# Environment hygiene net
#
# Several integration fixtures configure the app through raw
# ``os.environ[...] = ...`` writes (module-scoped, deliberately persistent
# for their module). Without a net those values leak into every suite
# collected later IN THE SAME PROCESS — a leaked DATABASE_URL once
# silently redirected an alembic migration run to the wrong database.
#
# Two layers make the whole api suite env-neutral, regardless of fixture
# scope, without touching the 19 files that write environ:
#
# 1. Fixture layer — every fixture (any scope) snapshots the managed keys
#    at setup and restores them at its finalizer. Module-scoped values
#    still persist for the module's tests, but die with the module.
# 2. Test layer — an autouse guard snapshots/restores around each test
#    call, catching writes made inside test bodies (e.g. _make_app()
#    helpers that set OIDC_/REPORT_SIGNING_ keys at call time).
# ---------------------------------------------------------------------------

import os as _os

import pytest as _pytest

_ENV_MANAGED_KEYS = (
    "SECRET_KEY", "ENVIRONMENT", "ADMIN_USERNAME", "ADMIN_PASSWORD",
    "ADMIN_PASSWORD_HASH", "DATABASE_URL", "REDIS_URL",
    "OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_AUTO_PROVISION", "OIDC_JWKS_FILE",
    "SMTP_HOST", "REPORT_SIGNING_KEY", "REPORT_SIGNING_KEY_ID",
)


def _env_snapshot() -> dict:
    return {key: _os.environ.get(key) for key in _ENV_MANAGED_KEYS}


def _env_restore(snapshot: dict) -> None:
    for key, value in snapshot.items():
        if value is None:
            _os.environ.pop(key, None)
        else:
            _os.environ[key] = value


@_pytest.hookimpl(wrapper=True)
def pytest_fixture_setup(fixturedef, request):
    """Remember each fixture's pre-setup env; restored at its finalizer."""
    before = _env_snapshot()
    result = yield
    fixturedef._cryptoscan_env_before = before
    return result


def pytest_fixture_post_finalizer(fixturedef) -> None:
    before = getattr(fixturedef, "_cryptoscan_env_before", None)
    if before is not None:
        _env_restore(before)
        fixturedef._cryptoscan_env_before = None


@_pytest.fixture(autouse=True)
def _restore_env_after_test():
    before = _env_snapshot()
    yield
    _env_restore(before)
