"""Conditional GET: polling a JSON endpoint must be able to cost headers only.

The dashboards poll — the twin page, the scan list, the BOM catalog — and most
of those reads are unchanged between polls.  ``ConditionalGetMiddleware`` gives
every JSON GET an ``ETag`` over exactly the bytes served and answers a matching
``If-None-Match`` with ``304`` and no body.  This test pins the contract:

* a JSON GET carries ETag + ``Cache-Control: private, no-cache`` + ``Vary``;
* replaying the tag gets 304 with the same tag and an empty body;
* a wrong tag gets the full 200 body again;
* mutating requests are never conditional;
* an unauthenticated caller can never trade a stolen tag for a 304 — the auth
  layer rejects it before the middleware sees the request.
"""

from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    os.environ["SECRET_KEY"] = "test-secret-key-for-sessions-min-32-chars"
    os.environ["ENVIRONMENT"] = "development"
    os.environ["ADMIN_USERNAME"] = "admin"
    os.environ["ADMIN_PASSWORD"] = "cryptoscan"
    db_file = os.path.join(tempfile.gettempdir(), "conditional_get_test.db")
    for ext in ("", "-wal", "-shm"):
        if os.path.exists(db_file + ext):
            os.remove(db_file + ext)
    os.environ["DATABASE_URL"] = f"sqlite:///{db_file}"

    from api.config.settings import get_settings
    from api.main import create_app

    get_settings.cache_clear()
    app = create_app()
    with TestClient(app) as c:
        token = c.post("/api/v1/auth/login", json={"username": "admin", "password": "cryptoscan"}).json()["token"]
        c.headers["Authorization"] = f"Bearer {token}"
        yield c


def test_json_get_carries_a_validator_and_revalidates_with_304(client):
    first = client.get("/api/v1/digital-twin/scenarios")
    assert first.status_code == 200, first.text
    etag = first.headers.get("etag")
    assert etag and etag.startswith('"') and etag.endswith('"'), first.headers
    assert "private" in first.headers.get("cache-control", ""), first.headers
    assert "no-cache" in first.headers.get("cache-control", ""), first.headers
    assert "accept-encoding" in first.headers.get("vary", "").lower(), first.headers

    again = client.get("/api/v1/digital-twin/scenarios", headers={"If-None-Match": etag})
    assert again.status_code == 304, again.text
    assert again.content == b"", "a 304 must not carry the body it is skipping"
    assert again.headers.get("etag") == etag


def test_a_stale_tag_gets_the_full_body_again(client):
    body = client.get("/api/v1/scans", params={"page_size": 5})
    assert body.status_code == 200, body.text
    stale = client.get("/api/v1/scans", params={"page_size": 5}, headers={"If-None-Match": '"not-the-tag"'})
    assert stale.status_code == 200, stale.text
    assert stale.content == body.content, "a mismatched validator must serve the full representation"


def test_mutating_requests_are_never_conditional(client):
    login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "cryptoscan"},
                        headers={"If-None-Match": '"anything"'})
    assert login.status_code == 200, login.text
    assert "etag" not in {k.lower() for k in login.headers}, "POST responses must not be made conditional"


def test_an_unauthenticated_caller_cannot_trade_a_tag_for_a_304(client):
    first = client.get("/api/v1/digital-twin/scenarios")
    etag = first.headers["etag"]
    anonymous = client.get("/api/v1/digital-twin/scenarios",
                           headers={"If-None-Match": etag, "Authorization": "Bearer revoked-or-garbage"})
    assert anonymous.status_code in (401, 403), anonymous.text
    assert anonymous.status_code != 304
