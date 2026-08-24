"""
Integration tests for GitHub webhook endpoint.
Tests HMAC verification, payload parsing, job queuing.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient

WEBHOOK_SECRET = "test-webhook-secret-abc123"
GITHUB_PUSH_PAYLOAD = {
    "ref": "refs/heads/main",
    "deleted": False,
    "repository": {
        "full_name": "org/payment-api",
        "clone_url": "https://github.com/org/payment-api.git",
        "html_url": "https://github.com/org/payment-api",
    },
    "head_commit": {
        "id": "a1b2c3d4e5f6789012345678901234567890abcd",
        "message": "Add payment encryption",
        "author": {"name": "John Dev", "email": "john@example.com"},
        "timestamp": "2024-01-15T08:00:00Z",
    },
    "pusher": {"name": "john.developer"},
}


def _sign_payload(payload: bytes, secret: str) -> str:
    """Compute HMAC-SHA256 signature in GitHub format."""
    sig = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return f"sha256={sig}"


@pytest.fixture
def raw_payload() -> bytes:
    return json.dumps(GITHUB_PUSH_PAYLOAD).encode()


@pytest.fixture
def valid_signature(raw_payload: bytes) -> str:
    return _sign_payload(raw_payload, WEBHOOK_SECRET)


class TestWebhookEndpoint:
    """Tests for POST /webhooks/github."""

    @pytest.mark.asyncio
    async def test_valid_push_event_queues_job(
        self,
        client: AsyncClient,
        raw_payload: bytes,
        valid_signature: str,
        mock_repo_config_repo: MagicMock,
        mock_job_repo: MagicMock,
    ):
        """Valid push to configured repo should queue a scan job and return 200."""
        # Arrange: repo is configured and enabled
        mock_repo_config = MagicMock()
        mock_repo_config.enabled = True
        mock_repo_config.scan_on_push = True
        mock_repo_config_repo.get_by_url = AsyncMock(return_value=mock_repo_config)
        mock_job_repo.create_from_webhook = AsyncMock(
            return_value=MagicMock(job_id="test-job-id")
        )

        response = await client.post(
            "/api/v1/webhooks/github",
            content=raw_payload,
            headers={
                "X-GitHub-Event": "push",
                "X-Hub-Signature-256": valid_signature,
                "X-GitHub-Delivery": "test-delivery-id",
                "Content-Type": "application/json",
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert body["acknowledged"] is True
        assert body["queued"] is True
        assert "Scan queued" in body["message"]

    @pytest.mark.asyncio
    async def test_invalid_signature_returns_401(
        self,
        client: AsyncClient,
        raw_payload: bytes,
    ):
        """Invalid HMAC signature should be rejected with 401."""
        response = await client.post(
            "/api/v1/webhooks/github",
            content=raw_payload,
            headers={
                "X-GitHub-Event": "push",
                "X-Hub-Signature-256": "sha256=invalidhashvalue",
                "X-GitHub-Delivery": "test-delivery-id",
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_missing_signature_returns_401(
        self,
        client: AsyncClient,
        raw_payload: bytes,
    ):
        """Missing X-Hub-Signature-256 header should return 401."""
        response = await client.post(
            "/api/v1/webhooks/github",
            content=raw_payload,
            headers={
                "X-GitHub-Event": "push",
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_unconfigured_repo_does_not_queue(
        self,
        client: AsyncClient,
        raw_payload: bytes,
        valid_signature: str,
        mock_repo_config_repo: MagicMock,
    ):
        """Push from unconfigured repo should acknowledge but not queue."""
        mock_repo_config_repo.get_by_url = AsyncMock(return_value=None)

        response = await client.post(
            "/api/v1/webhooks/github",
            content=raw_payload,
            headers={
                "X-GitHub-Event": "push",
                "X-Hub-Signature-256": valid_signature,
                "Content-Type": "application/json",
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert body["acknowledged"] is True
        assert body["queued"] is False
        assert "not configured" in body["message"]

    @pytest.mark.asyncio
    async def test_non_push_event_ignored(
        self,
        client: AsyncClient,
        raw_payload: bytes,
        valid_signature: str,
    ):
        """Non-push events (ping, pull_request) should be acknowledged but not scanned."""
        response = await client.post(
            "/api/v1/webhooks/github",
            content=raw_payload,
            headers={
                "X-GitHub-Event": "ping",
                "X-Hub-Signature-256": valid_signature,
                "Content-Type": "application/json",
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert body["acknowledged"] is True
        assert body["queued"] is False

    @pytest.mark.asyncio
    async def test_branch_deletion_event_not_queued(
        self,
        client: AsyncClient,
        valid_signature: str,
    ):
        """Branch deletion push events should not trigger scans."""
        delete_payload = {**GITHUB_PUSH_PAYLOAD, "deleted": True}
        raw = json.dumps(delete_payload).encode()
        sig = _sign_payload(raw, WEBHOOK_SECRET)

        response = await client.post(
            "/api/v1/webhooks/github",
            content=raw,
            headers={
                "X-GitHub-Event": "push",
                "X-Hub-Signature-256": sig,
                "Content-Type": "application/json",
            },
        )

        assert response.status_code == 200
        assert response.json()["queued"] is False