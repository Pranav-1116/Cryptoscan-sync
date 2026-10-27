"""Runtime-findings server-side search (§5, round 65).

The list endpoint's ``q`` parameter searches the WHOLE store in the
database. The pin that matters: a matching row older than the recent
window (beyond ``limit`` rows of recency) is still found — the old
client-side approach (fetch the first 100 recent rows, filter in the
browser) could never see it.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from api.config.settings import get_settings


@pytest.fixture()
def sqlite_app(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/rts.db")
    monkeypatch.setenv("NEO4J_URI", "")
    get_settings.cache_clear()
    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None
    from api.main import create_app

    app = create_app()
    with TestClient(app) as client:
        yield client, f"sqlite:///{tmp_path}/rts.db"


def _login(client):
    r = client.post("/api/v1/auth/login",
                    json={"username": "admin", "password": "cryptoscan"})
    return {"Authorization": f"Bearer {r.json()['token']}"}


def _seed(db_url, filler=105):
    """`filler` fresh non-matching rows + ONE matching row that is older
    than everything else — invisible to a recent-window client filter."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import db.models  # noqa: F401
    from db.models.base import utcnow
    from db.models.runtime_finding import RuntimeFinding

    eng = create_engine(db_url)
    session = sessionmaker(bind=eng)()
    now = utcnow()
    for index in range(filler):
        session.add(RuntimeFinding(
            scanner_id="tls-tap-agent", kind="session",
            hostname=f"host-{index}.internal", process_name=f"svc-{index}",
            tls_version="TLSv1.3", cipher_suite="TLS_AES_256_GCM_SHA384",
            algorithm="AES-GCM", status="ALLOWED", weak_tls=False,
            observation_count=1, dedup_key=f"filler-{index}",
            last_seen_at=now,
        ))
    session.add(RuntimeFinding(
        scanner_id="ld-preload-agent", kind="session",
        hostname="legacy-gateway.internal", process_name="legacy-gateway",
        algorithm="3DES", status="DISALLOWED", weak_tls=True,
        observation_count=9, dedup_key="the-old-one",
        last_seen_at=now - timedelta(days=30),
    ))
    session.commit()
    session.close()
    eng.dispose()


def test_search_finds_rows_beyond_the_recent_window(sqlite_app):
    client, db_url = sqlite_app
    _seed(db_url)
    admin = _login(client)

    # without q: the 100 most-recent rows — the old client-side window.
    # The 30-day-old 3DES row is NOT among them.
    plain = client.get("/api/v1/scans/runtime-findings?limit=100", headers=admin).json()
    assert plain["total_count"] == 100
    assert not any(f["algorithm"] == "3DES" for f in plain["findings"])

    # with q: the whole store is searched in the database — the old
    # matching row IS found, and total_count counts MATCHES, not returns.
    hit = client.get("/api/v1/scans/runtime-findings?q=3DES", headers=admin).json()
    assert hit["query"] == "3DES"
    assert hit["total_count"] == 1
    assert len(hit["findings"]) == 1
    assert hit["findings"][0]["hostname"] == "legacy-gateway.internal"
    assert hit["findings"][0]["status"] == "DISALLOWED"


def test_search_matches_across_fields_and_is_case_insensitive(sqlite_app):
    client, db_url = sqlite_app
    _seed(db_url, filler=3)
    admin = _login(client)

    for term, expected_host in (
        ("legacy-gateway", "legacy-gateway.internal"),   # hostname
        ("LD-PRELOAD", "legacy-gateway.internal"),       # scanner, case-insensitive
        ("disallowed", "legacy-gateway.internal"),       # status
    ):
        body = client.get(f"/api/v1/scans/runtime-findings?q={term}", headers=admin).json()
        assert body["total_count"] == 1, term
        assert body["findings"][0]["hostname"] == expected_host

    # no match is an honest empty answer, not an error
    miss = client.get("/api/v1/scans/runtime-findings?q=quantum-unicorn", headers=admin).json()
    assert miss["total_count"] == 0 and miss["findings"] == []


def test_search_requires_auth(sqlite_app):
    client, _ = sqlite_app
    assert client.get("/api/v1/scans/runtime-findings?q=x").status_code == 401
