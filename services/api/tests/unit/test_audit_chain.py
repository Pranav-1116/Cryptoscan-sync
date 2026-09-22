"""W57-58 honest subset: hash-chained audit log (verify + immutable export)."""

from __future__ import annotations

import hashlib
import json

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register all tables
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.repositories.user_repository import UserRepository


def _make_app():
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "auditor-admin"
    from api.dependencies import require_admin

    app.dependency_overrides[require_admin] = lambda: "auditor-admin"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session, engine


def _three_events(session):
    repo = UserRepository(session)
    repo.audit("alice", "auth.login", ip="10.0.0.1")
    repo.audit("bob", "auth.login", outcome="FAILURE", ip="10.0.0.9", detail={"reason": "bad password"})
    repo.audit("admin", "user.create", target_type="user", target_id="u-3")
    session.flush()
    return repo


@pytest.mark.asyncio
async def test_chain_verifies_and_export_is_immutable():
    app, session, engine = _make_app()
    _three_events(session)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        verify = (await client.get("/api/v1/auth/audit/verify")).json()
        assert verify["status"] == "OK"
        assert verify["checked"] == 3
        assert verify["chain_head"] and verify["chain_head"] != "0" * 64

        export = await client.get("/api/v1/auth/audit/export")
        assert export.status_code == 200
        assert export.headers["X-Audit-Chain-Status"] == "OK"
        lines = export.text.strip().split("\n")
        manifest = json.loads(lines[0])
        body = "\n".join(lines[1:]) + "\n"
        assert manifest["entry_count"] == 3
        assert manifest["sha256"] == hashlib.sha256(body.encode()).hexdigest()
        assert export.headers["X-Audit-Export-Sha256"] == manifest["sha256"]
        entries = [json.loads(line) for line in lines[1:]]
        # the chain travels with the export: each entry links to the previous
        assert entries[0]["previous_hash"] == "0" * 64
        assert entries[1]["previous_hash"] == entries[0]["entry_hash"]
        assert entries[2]["previous_hash"] == entries[1]["entry_hash"]


@pytest.mark.asyncio
async def test_tampered_entry_is_detected_at_verify_time():
    app, session, engine = _make_app()
    repo = _three_events(session)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        assert (await client.get("/api/v1/auth/audit/verify")).json()["status"] == "OK"

        # A new entry lands after the anchor, then is forged in place
        # (content rewritten, stored hash kept): the next verify re-hashes
        # the suffix and must catch it. Select by chain_sequence — the
        # created_at ordering in list_audit is not a stable tiebreaker when
        # events share a timestamp.
        repo.audit("eve", "audit.forged", detail={"note": "pending edit"})
        session.flush()
        target = next(r for r in repo.list_audit(page=1, page_size=10) if r.chain_sequence == 4)
        target.detail = "innocent edit"
        session.flush()

        verify = (await client.get("/api/v1/auth/audit/verify")).json()
        assert verify["status"] == "TAMPERED"
        assert verify["break_at_sequence"] == 4
        assert verify["mode"] == "incremental"
        assert "modified" in verify["reason"]

        # A pre-anchor edit sits inside the reported full-walk window (the
        # incremental report states mode + full_verified_at); the forced full
        # walk closes it on demand.
        row2 = next(r for r in repo.list_audit(page=1, page_size=10) if r.chain_sequence == 2)
        row2.detail = "pre-anchor forgery"
        session.flush()
        verify_full = (await client.get("/api/v1/auth/audit/verify?full=true")).json()
        assert verify_full["status"] == "TAMPERED"
        assert verify_full["break_at_sequence"] == 2
        assert verify_full["mode"] == "full"


@pytest.mark.asyncio
async def test_deleted_entry_breaks_the_chain():
    app, session, engine = _make_app()
    repo = _three_events(session)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Select by chain_sequence: list_audit orders by created_at, which is
        # not a stable tiebreaker when events share a timestamp.
        rows = sorted(
            repo.list_audit(page=1, page_size=10),
            key=lambda r: r.chain_sequence,
        )
        session.delete(rows[1])  # remove the middle entry (sequence 2)
        session.flush()

        verify = (await client.get("/api/v1/auth/audit/verify")).json()
        assert verify["status"] == "TAMPERED"
        assert verify["break_at_sequence"] == 3  # entry 3 no longer follows entry 1
        assert "removed" in verify["reason"] or "mismatch" in verify["reason"]
