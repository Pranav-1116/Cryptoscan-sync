"""API error contract (gap analysis §B).

Every error response carries a stable ``error_code`` and the ``request_id``
of the call; reads page at deterministic limits with a hard maximum. These
tests run against the real app factory — middleware stack included.
"""

from __future__ import annotations

import pytest


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/contract.db")
    monkeypatch.setenv("NEO4J_URI", "")
    from api.config.settings import get_settings
    get_settings.cache_clear()
    from db.connection import engine as engine_mod
    engine_mod._ENGINE = None
    from api.events.bus import reset_event_bus
    reset_event_bus()
    from api.middleware.abac_middleware import reset_abac_cache
    reset_abac_cache()
    from api.main import create_app
    from fastapi.testclient import TestClient

    with TestClient(create_app()) as c:
        yield c
    reset_abac_cache()


def _auth_headers(c):
    token = c.post("/api/v1/auth/login",
                   json={"username": "admin", "password": "cryptoscan"}).json()["token"]
    return {"Authorization": f"Bearer {token}"}


# ------------------------------------------------------------- vocabulary
def test_error_vocabulary_matches_contract_table():
    from api.errors import ERROR_CODES
    table = {
        "UNAUTHENTICATED", "FORBIDDEN", "NOT_FOUND", "CONFLICT", "RATE_LIMITED",
        "UPSTREAM_UNAVAILABLE", "INVALID_ARGUMENT", "UNSUPPORTED_COLLECTOR",
        "EVIDENCE_REQUIRED",
    }
    assert table <= ERROR_CODES, "every §B table code is stable and present"
    assert ERROR_CODES - table == {"INTERNAL_ERROR"}, "only the 500 companion is extra"


def test_unknown_code_is_refused_not_invented():
    from api.errors import error_envelope
    with pytest.raises(ValueError):
        error_envelope("MADE_UP_CODE", "nope")


def test_code_for_status_covers_documented_statuses():
    from api.errors import (code_for_status, UNAUTHENTICATED, FORBIDDEN, NOT_FOUND,
                            CONFLICT, RATE_LIMITED, INVALID_ARGUMENT,
                            UPSTREAM_UNAVAILABLE, INTERNAL_ERROR)
    assert code_for_status(401) == UNAUTHENTICATED
    assert code_for_status(403) == FORBIDDEN
    assert code_for_status(404) == NOT_FOUND
    assert code_for_status(409) == CONFLICT
    assert code_for_status(422) == INVALID_ARGUMENT
    assert code_for_status(429) == RATE_LIMITED
    assert code_for_status(503) == UPSTREAM_UNAVAILABLE
    assert code_for_status(500) == INTERNAL_ERROR


# ------------------------------------------------------- envelope + ids
def test_missing_route_returns_stable_envelope_with_request_id(client):
    resp = client.get("/api/v1/definitely-not-a-route", headers=_auth_headers(client))
    assert resp.status_code == 404
    body = resp.json()
    assert body["error_code"] == "NOT_FOUND"
    assert body["detail"], "detail keeps its historical shape"
    assert body["request_id"], "every error body carries the request id"


def test_request_id_is_echoed_from_the_caller(client):
    h = dict(_auth_headers(client))
    h["X-Request-ID"] = "contract-test-123"
    resp = client.get("/api/v1/definitely-not-a-route", headers=h)
    assert resp.headers["X-Request-ID"] == "contract-test-123"
    assert resp.json()["request_id"] == "contract-test-123"


def test_request_id_is_minted_when_the_caller_sends_none(client):
    resp = client.get("/api/v1/definitely-not-a-route", headers=_auth_headers(client))
    assert resp.headers.get("X-Request-ID"), "a correlation id is always minted"
    assert resp.json()["request_id"] == resp.headers["X-Request-ID"]


def test_validation_error_is_invalid_argument_with_field_detail(client):
    h = _auth_headers(client)
    resp = client.get("/api/v1/assets?page=not-a-number", headers=h)
    assert resp.status_code == 422
    body = resp.json()
    assert body["error_code"] == "INVALID_ARGUMENT"
    assert isinstance(body["detail"], list) and body["detail"], "field errors ride in detail"
    assert body["request_id"]


def test_page_size_has_a_hard_maximum(client):
    h = _auth_headers(client)
    over = client.get("/api/v1/assets?page_size=201", headers=h)
    assert over.status_code == 422
    assert over.json()["error_code"] == "INVALID_ARGUMENT"
    # the maximum itself is a deterministic read limit
    ok = client.get("/api/v1/assets?page_size=200", headers=h)
    assert ok.status_code == 200
    assert ok.json()["page_size"] == 200


def test_unauthenticated_error_carries_code_and_request_id(client):
    resp = client.get("/api/v1/assets")
    assert resp.status_code == 401
    body = resp.json()
    assert body["error_code"] in {
        "MISSING_AUTH_HEADER", "INVALID_TOKEN", "INVALID_API_KEY", "UNAUTHENTICATED"}
    assert body["request_id"], "auth refusals correlate too"


# ------------------------------------------------------------ rate limit
def test_rate_limited_envelope_declares_limit_and_retry(client):
    # login class: 5 requests / 60 s per identity (DEFAULT_RULES)
    statuses = []
    for _ in range(6):
        r = client.post("/api/v1/auth/login",
                        json={"username": "admin", "password": "wrong"})
        statuses.append(r.status_code)
        if r.status_code == 429:
            assert r.json()["error_code"] == "RATE_LIMITED"
            assert r.json()["request_id"]
            assert int(r.headers["Retry-After"]) >= 1
            assert r.headers["X-RateLimit-Limit"] == "5"
            assert r.headers["X-RateLimit-Remaining"] == "0"
            return
    pytest.fail(f"no 429 within 6 attempts on a 5/min limit: {statuses}")


def test_rate_limit_headers_are_declared_on_successes_too(client):
    r = client.post("/api/v1/auth/login",
                    json={"username": "admin", "password": "cryptoscan"})
    assert r.status_code == 200
    assert r.headers["X-RateLimit-Limit"] == "5"
    assert int(r.headers["X-RateLimit-Remaining"]) < 5
