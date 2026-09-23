"""Repository-wide pytest configuration: the suite is hermetic.

No test may open a real network connection. ``pytest-socket`` refuses every
socket except loopback (the FastAPI TestClient, an in-process Redis double or a
local Postgres in CI all live there), so a test that reaches for GitHub, a
cloud API, an SMTP relay or a live TLS target fails immediately with
``SocketBlockedError`` instead of hanging on DNS / connect timeouts — the
failure mode that used to make this suite too slow to run in CI.

A test that must talk to a real endpoint opts in explicitly with
``@pytest.mark.enable_socket`` / ``@pytest.mark.allow_hosts([...])`` and is
excluded from the default gate by the ``live`` marker (see ``pytest.ini``).
"""
from __future__ import annotations

import os

import pytest


def pytest_configure(config):
    config.addinivalue_line("markers", "live: needs real network access (excluded from the hermetic gate)")


@pytest.fixture(autouse=True)
def _hermetic(request):
    """Fail fast on any non-loopback socket unless the test opted in."""
    if request.node.get_closest_marker("live") or request.node.get_closest_marker("enable_socket"):
        yield
        return
    try:
        import pytest_socket
    except ImportError:  # pragma: no cover - plugin not installed: be permissive
        yield
        return
    pytest_socket.socket_allow_hosts(["127.0.0.1", "::1", "localhost"], allow_unix_socket=True)
    try:
        yield
    finally:
        pytest_socket.enable_socket()


@pytest.fixture(autouse=True)
def _no_ambient_credentials(monkeypatch):
    """Cloud SDKs must not pick up the developer's real credentials in tests."""
    for var in ("AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
                "AZURE_CLIENT_SECRET", "GOOGLE_APPLICATION_CREDENTIALS", "GITHUB_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    # boto3 otherwise probes the EC2 metadata service (169.254.169.254) with retries
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_DEFAULT_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))


def pytest_sessionstart(session):
    """Give every xdist worker its own scratch data directory.

    Tests that never set ``DATABASE_URL`` fall back to ``sqlite:///./data/
    cryptoscan.db``; with several workers that is one file being created,
    migrated and bootstrapped concurrently — the one source of order-dependent
    flakes left in the suite. Pointing each worker at its own file (and its
    own snapshot dir) is what makes ``-n auto`` safe.
    """
    import tempfile
    from pathlib import Path

    worker = os.environ.get("PYTEST_XDIST_WORKER", "main")
    scratch = Path(tempfile.gettempdir()) / "cryptoscan-tests" / worker
    scratch.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("DATABASE_URL", f"sqlite:///{scratch / 'cryptoscan.db'}")
    os.environ.setdefault("CRYPTOSCAN_SNAPSHOT_DIR", str(scratch / "data"))
    os.environ.setdefault("SBOM_STORAGE_DIR", str(scratch / "sboms"))
    os.environ.setdefault("ALLOW_SQLITE", "1")
