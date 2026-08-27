"""Dashboard SPA smoke tests: the served UI must render and stay offline-capable."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_root_serves_spa_shell(client: AsyncClient):
    response = await client.get("/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    body = response.text
    # Core UI markers: app root, styles, and script must be present.
    assert "<title>CryptoScan" in body
    assert "<script>" in body or "<script " in body


@pytest.mark.asyncio
async def test_spa_has_no_external_cdn_dependencies(client: AsyncClient):
    """Air-gap guarantee: no third-party origins in the served HTML."""
    response = await client.get("/")
    body = response.text.lower()
    for banned in ("https://fonts.googleapis", "https://cdn.", "http://unpkg", "https://unpkg", "https://cdnjs"):
        assert banned not in body, f"external dependency found: {banned}"


@pytest.mark.asyncio
async def test_login_page_flow_exists(client: AsyncClient):
    response = await client.get("/")
    assert response.status_code == 200
    # The SPA implements its own login view calling the auth login route.
    assert "/auth/login" in response.text


@pytest.mark.asyncio
async def test_health_open_without_auth(client: AsyncClient):
    response = await client.get("/health")
    assert response.status_code == 200
