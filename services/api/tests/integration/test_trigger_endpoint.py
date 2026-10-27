"""
Integration tests for manual scan trigger endpoint.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import AsyncClient

from api.security import rbac


class TestTriggerEndpoint:
    """Tests for POST /api/scans/trigger."""

    @pytest.mark.asyncio
    async def test_trigger_scan_success(
        self,
        authenticated_client: AsyncClient,
        mock_job_repo: MagicMock,
    ):
        """Valid trigger request should create job and return 202."""
        mock_job = MagicMock()
        mock_job.job_id = "test-job-uuid-123"
        mock_job.status = "QUEUED"
        mock_job.created_at = __import__("datetime").datetime.utcnow()
        mock_job_repo.create = AsyncMock(return_value=mock_job)

        response = await authenticated_client.post(
            "/api/v1/scans/trigger",
            json={
                "repo_url": "https://github.com/org/payment-api",
                "branch": "main",
                "commit": None,
            },
        )

        assert response.status_code == 202
        body = response.json()
        assert body["job_id"] == "test-job-uuid-123"
        assert body["status"] == "QUEUED"
        assert "Poll" in body["message"]

    @pytest.mark.asyncio
    async def test_trigger_scan_commit_failure_fails_closed(
        self,
        authenticated_client: AsyncClient,
        mock_db_session: MagicMock,
        mock_job_repo: MagicMock,
    ):
        """A database failure must not return an accepted scan job."""
        mock_job = MagicMock(job_id="not-accepted", status="QUEUED", created_at=None)
        mock_job_repo.create = AsyncMock(return_value=mock_job)
        mock_job_repo.session = mock_db_session
        mock_db_session.commit = MagicMock(side_effect=RuntimeError("database unavailable"))
        mock_db_session.rollback = MagicMock()

        response = await authenticated_client.post(
            "/api/v1/scans/trigger",
            json={
                "repo_url": "https://github.com/org/payment-api",
                "branch": "main",
            },
        )

        assert response.status_code == 503
        assert "no job was accepted" in response.json()["detail"]
        mock_db_session.rollback.assert_called_once()

    @pytest.mark.parametrize(
        "role",
        ["superadmin", "ciso", "security_analyst", "developer", "scanner"],
    )
    @pytest.mark.asyncio
    async def test_every_scan_trigger_role_can_queue_a_scan(
        self,
        role: str,
        role_client: AsyncClient,
        mock_job_repo: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """The endpoint follows every role in the canonical scan.trigger matrix."""
        mock_job = MagicMock()
        mock_job.job_id = f"job-{role}"
        mock_job.status = "QUEUED"
        mock_job.created_at = __import__("datetime").datetime.utcnow()
        mock_job_repo.create = AsyncMock(return_value=mock_job)
        monkeypatch.setattr(rbac, "_caller_roles", lambda _request: (role, [role]))

        response = await role_client.post(
            "/api/v1/scans/trigger",
            json={"repo_url": "https://github.com/org/payment-api", "branch": "main"},
        )

        assert response.status_code == 202
        assert response.json()["job_id"] == f"job-{role}"

    @pytest.mark.parametrize("role", ["auditor", "business_owner", "readonly", "supervisor"])
    @pytest.mark.asyncio
    async def test_non_scan_trigger_roles_are_denied(
        self,
        role: str,
        role_client: AsyncClient,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Read/report roles cannot use the scan submission endpoint."""
        monkeypatch.setattr(rbac, "_caller_roles", lambda _request: (role, [role]))

        response = await role_client.post(
            "/api/v1/scans/trigger",
            json={"repo_url": "https://github.com/org/payment-api", "branch": "main"},
        )

        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_trigger_scan_invalid_url_returns_422(
        self,
        authenticated_client: AsyncClient,
    ):
        """Invalid repo URL should return 422."""
        response = await authenticated_client.post(
            "/api/v1/scans/trigger",
            json={
                "repo_url": "not-a-valid-url",
                "branch": "main",
            },
        )
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_trigger_scan_unauthenticated_returns_401(
        self,
        client: AsyncClient,
    ):
        """Unauthenticated trigger request should return 401."""
        response = await client.post(
            "/api/v1/scans/trigger",
            json={
                "repo_url": "https://github.com/org/payment-api",
                "branch": "main",
            },
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_get_job_status(
        self,
        authenticated_client: AsyncClient,
        mock_job_repo: MagicMock,
    ):
        """GET /api/jobs/{id} should return current job status."""
        import datetime

        mock_job = MagicMock()
        mock_job.job_id = "test-job-uuid-123"
        mock_job.status = "RUNNING"
        mock_job.job_type = "MANUAL"
        mock_job.target_repo = "https://github.com/org/payment-api.git"
        mock_job.target_branch = "main"
        mock_job.target_commit = None
        mock_job.triggered_by = "testuser"
        mock_job.created_at = datetime.datetime.utcnow()
        mock_job.started_at = datetime.datetime.utcnow()
        mock_job.completed_at = None
        mock_job.scan_id = None
        mock_job.error_message = None
        mock_job.metadata = {"current_stage": "scan", "stages_complete": 2}
        mock_job_repo.get_by_id = AsyncMock(return_value=mock_job)

        response = await authenticated_client.get("/api/v1/jobs/test-job-uuid-123")

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "RUNNING"
        assert body["progress"]["current_stage"] == "scan"
        assert body["progress"]["stages_complete"] == 2