"""GET /api/v1/audit-export/access-review — the CC6.3 quarterly review export."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401
from api.dependencies import get_current_user, get_db_session, require_auditor
from api.main import create_app
from db.connection.session import Base
from db.models.api_key import ApiKey
from db.models.user import User, UserSession

NOW = datetime.now(timezone.utc)


def _make_app(override_auditor: bool = True, current_user: str = "auditor-1"):
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: current_user
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    if override_auditor:
        app.dependency_overrides[require_auditor] = lambda: current_user
    return app, session, engine


def _seed(session) -> None:
    session.add_all([
        User(username="super", password_hash="pbkdf2_sha256$x", display_name="Super", roles="superadmin",
             is_active=True, mfa_enabled=True, last_login_at=NOW - timedelta(days=2)),
        User(username="no-mfa", password_hash="pbkdf2_sha256$x", roles="security_analyst", is_active=True,
             mfa_enabled=False, last_login_at=NOW - timedelta(days=3)),
        User(username="stale", password_hash="pbkdf2_sha256$x", roles="readonly", is_active=True, mfa_enabled=True,
             last_login_at=NOW - timedelta(days=120)),
        User(username="never", password_hash="pbkdf2_sha256$x", roles="developer", is_active=True, mfa_enabled=True,
             last_login_at=None),
        User(username="deactivated", password_hash="pbkdf2_sha256$x", roles="viewer", is_active=False, mfa_enabled=True,
             last_login_at=NOW - timedelta(days=30)),
    ])
    session.add_all([
        ApiKey(name="expired-live", key_hash="e" * 64, key_prefix="csk_e1",
               created_by="super", roles="readonly",
               expires_at=NOW - timedelta(days=1), revoked_at=None),
        ApiKey(name="revoked-key", key_hash="r" * 64, key_prefix="csk_r1",
               created_by="super", roles="readonly", revoked_at=NOW - timedelta(days=1)),
        ApiKey(name="healthy-key", key_hash="h" * 64, key_prefix="csk_h1",
               created_by="super", roles="readonly",
               expires_at=NOW + timedelta(days=90),
               last_used_at=NOW - timedelta(hours=1)),
    ])
    session.add(UserSession(token_hash="s" * 64, username="super",
                            created_at_ts=NOW - timedelta(hours=1),
                            expires_at=NOW + timedelta(hours=23)))
    session.commit()


@pytest.mark.asyncio
async def test_access_review_content_and_signals():
    app, session, _ = _make_app()
    _seed(session)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/audit-export/access-review")
        assert res.status_code == 200, res.text
        data = res.json()

    assert data["totals"] == {"users": 5, "active_users": 4, "api_keys": 3}
    s = data["signals"]
    assert s["privileged_accounts"] == ["super"]
    assert s["active_without_mfa"] == ["no-mfa"]
    assert s["stale_accounts"] == ["never", "stale"]      # never-logged-in counts stale
    assert s["never_logged_in"] == ["never"]
    assert s["expired_keys_not_revoked"] == ["expired-live"]
    assert s["revoked_keys"] == 1
    assert s["active_sessions_total"] == 1
    assert data["active_sessions"] == {"super": 1}

    # deactivated user must not appear in active signals
    assert "deactivated" not in s["active_without_mfa"] + s["stale_accounts"]

    # key material is never exported — only the display prefix
    key_fields = {f for k in data["api_keys"] for f in k}
    assert "key_hash" not in key_fields
    assert {k["key_prefix"] for k in data["api_keys"]} == {"csk_e1", "csk_r1", "csk_h1"}

    # the signature: report_hash over the canonical data (excluding the review
    # envelope) — recomputed here exactly as the endpoint computes it
    hashed = {k: v for k, v in data.items() if k not in ("review", "report_hash")}
    expected = hashlib.sha256(
        json.dumps(hashed, indent=2, sort_keys=True, default=str).encode()).hexdigest()
    assert data["report_hash"] == expected


@pytest.mark.asyncio
async def test_access_review_markdown_and_deterministic_hash():
    app, session, _ = _make_app()
    _seed(session)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        js = await client.get("/api/v1/audit-export/access-review")
        md = await client.get("/api/v1/audit-export/access-review?format=md")
    assert md.status_code == 200
    assert md.headers["X-Report-Hash"] == js.json()["report_hash"]  # deterministic
    body = md.text
    assert "# Access review" in body
    assert "| super |" in body and "no-mfa" in body
    assert "expired-live" in body and "never" in body


@pytest.mark.asyncio
async def test_access_review_requires_auditor_role():
    # NO require_auditor override — the real dependency runs and reads the
    # seeded viewer's roles fresh from the users table
    app, session, _ = _make_app(override_auditor=False, current_user="viewer-only")
    session.add(User(username="viewer-only", password_hash="pbkdf2_sha256$x", roles="viewer", is_active=True,
                     mfa_enabled=True, last_login_at=NOW))
    session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/audit-export/access-review",
                               headers={"Authorization": "Bearer test-token"})
    assert res.status_code == 403
    assert res.json()["detail"].startswith("Requires one of roles")


# --------------------------------------------------------------------------- #
# Review records — the CC6.3 minutes (POST/GET /access-reviews)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_review_record_roundtrip():
    app, session, _ = _make_app()
    _seed(session)

    body = {"period": "2026-Q3",
            "findings": [{"signal": "stale_accounts", "subject": "stale",
                          "action": "deactivate", "due": "2026-10-01"}],
            "notes": "Quarterly review complete"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        export = await client.get("/api/v1/audit-export/access-review")
        body["report_hash"] = export.json()["report_hash"]
        res = await client.post("/api/v1/audit-export/access-reviews", json=body)
        listing = await client.get("/api/v1/audit-export/access-reviews")

    assert res.status_code == 200, res.text
    rec = res.json()
    assert rec["period"] == "2026-Q3"
    assert rec["report_hash"] == export.json()["report_hash"]
    # estate did not change between export and sign-off
    assert rec["estate_unchanged"] is True
    assert rec["current_report_hash"] == rec["report_hash"]
    assert rec["reviewer"] == "auditor-1"
    assert rec["findings"] == body["findings"]

    assert listing.status_code == 200
    data = listing.json()
    assert data["count"] == 1
    assert data["reviews"][0]["period"] == "2026-Q3"
    assert data["reviews"][0]["notes"] == "Quarterly review complete"


@pytest.mark.asyncio
async def test_review_record_flags_changed_estate():
    app, session, _ = _make_app()
    _seed(session)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        export = await client.get("/api/v1/audit-export/access-review")
        report_hash = export.json()["report_hash"]
        # the estate changes between export and sign-off (a new account appears)
        session.add(User(username="late-joiner", password_hash="pbkdf2_sha256$x",
                         roles="developer", is_active=True, mfa_enabled=True,
                         last_login_at=NOW))
        session.commit()
        res = await client.post("/api/v1/audit-export/access-reviews",
                                json={"period": "2026-Q3", "report_hash": report_hash})

    assert res.status_code == 200, res.text
    rec = res.json()
    assert rec["estate_unchanged"] is False
    assert rec["current_report_hash"] != rec["report_hash"]


@pytest.mark.asyncio
async def test_review_record_period_conflict_and_validation():
    app, session, _ = _make_app()
    _seed(session)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        export = await client.get("/api/v1/audit-export/access-review")
        h = export.json()["report_hash"]
        ok1 = await client.post("/api/v1/audit-export/access-reviews",
                                json={"period": "2026-Q3", "report_hash": h})
        ok2 = await client.post("/api/v1/audit-export/access-reviews",
                                json={"period": "2026-Q3", "report_hash": h})
        bad_period = await client.post("/api/v1/audit-export/access-reviews",
                                       json={"period": "Q3 2026", "report_hash": h})
        bad_hash = await client.post("/api/v1/audit-export/access-reviews",
                                     json={"period": "2026-Q4", "report_hash": "nothex"})
    assert ok1.status_code == 200
    assert ok2.status_code == 409                       # minutes are append-only
    assert bad_period.status_code == 400
    assert bad_hash.status_code == 400


@pytest.mark.asyncio
async def test_review_record_requires_auditor_role():
    app, session, _ = _make_app(override_auditor=False, current_user="viewer-only")
    session.add(User(username="viewer-only", password_hash="pbkdf2_sha256$x", roles="viewer",
                     is_active=True, mfa_enabled=True, last_login_at=NOW))
    session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(
            "/api/v1/audit-export/access-reviews",
            json={"period": "2026-Q3", "report_hash": "0" * 64},
            headers={"Authorization": "Bearer test-token"})
    assert res.status_code == 403
    assert res.json()["detail"].startswith("Requires one of roles")
