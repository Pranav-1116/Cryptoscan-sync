"""Per-record evidence verification (§4.2, round 42).

A scan-level PASS is not a per-record verdict. GET /findings/{id}/verify
recomputes one record's content hash and chain linkage using the same
verifier as the scan-level endpoint — the surfaces cannot disagree — and
says explicitly what it does and does not prove.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401
from api.dependencies import get_current_user, get_db_session, require_auditor
from api.main import create_app
from db.connection.session import Base
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan
from evidence.hashing.chain_hasher import ChainHasher
from evidence.hashing.content_hasher import ContentHasher

NOW = datetime(2026, 10, 13, tzinfo=timezone.utc)


def _make_app():
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "per-record-verify-" + "z" * 21)
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "aud"
    app.dependency_overrides[require_auditor] = lambda: "aud"
    app.dependency_overrides[get_db_session] = lambda: (yield factory)
    return app, factory, engine


def _commit_chain(factory, scan_id: str, payloads: list[dict]) -> list[EvidenceRecord]:
    """Persist a real chain: content hash per payload, chain hash linking
    each row to its predecessor (scan id seeds position 0)."""
    rows = []
    previous = None
    for position, payload in enumerate(payloads):
        content = ContentHasher.compute_hash(payload)
        chain = ChainHasher.compute_chain_hash(
            content_hash=content, previous_chain_hash=previous,
            scan_session_id=scan_id if position == 0 else None)
        row = EvidenceRecord(
            id=f"{scan_id}-e{position}", scan_id=scan_id, content_hash=content,
            chain_hash=chain, chain_position=position, previous_hash=previous,
            algorithm=payload.get("algorithm", "AES"), file_path="src/x.py",
            line_number=1, finding_data=payload)
        factory.add(row)
        rows.append(row)
        previous = chain
    factory.commit()
    return rows


@pytest.mark.asyncio
async def test_intact_record_verifies_pass_with_honest_scope():
    app, factory, engine = _make_app()
    factory.add(Scan(id="scan-a", status="COMPLETED", target_location="local://x",
                     target_type="LOCAL_DIRECTORY", operator="t", scan_start=NOW))
    factory.commit()
    rows = _commit_chain(factory, "scan-a", [
        {"algorithm": "AES", "mode": "GCM"},
        {"algorithm": "RSA", "key_size": 2048},
    ])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        r = await ac.get(f"/api/v1/findings/{rows[1].id}/verify")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["result"] == "PASS"
    assert body["evidence_id"] == rows[1].id
    assert body["content_intact"] and body["chain_intact"] and body["hash_format_valid"]
    assert body["scan_verify_path"] == "/api/v1/scans/scan-a/verify"
    # the scope disclaimer is part of the contract
    assert any("not a claim that the observation was true" in n for n in body["notes"])
    engine.dispose()


@pytest.mark.asyncio
async def test_tampered_payload_fails_content_hash():
    app, factory, engine = _make_app()
    factory.add(Scan(id="scan-b", status="COMPLETED", target_location="local://x",
                     target_type="LOCAL_DIRECTORY", operator="t", scan_start=NOW))
    factory.commit()
    rows = _commit_chain(factory, "scan-b", [
        {"algorithm": "AES"}, {"algorithm": "RSA", "key_size": 2048},
    ])
    rows[1].finding_data = {"algorithm": "RSA", "key_size": 4096}  # tampered after commit
    factory.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        r = await ac.get(f"/api/v1/findings/{rows[1].id}/verify")
    body = r.json()
    assert body["result"] == "FAIL"
    assert body["content_intact"] is False
    assert any("content hash mismatch" in e for e in body["errors"])
    engine.dispose()


@pytest.mark.asyncio
async def test_broken_predecessor_link_fails_chain():
    app, factory, engine = _make_app()
    factory.add(Scan(id="scan-c", status="COMPLETED", target_location="local://x",
                     target_type="LOCAL_DIRECTORY", operator="t", scan_start=NOW))
    factory.commit()
    rows = _commit_chain(factory, "scan-c", [
        {"algorithm": "AES"}, {"algorithm": "RSA"}, {"algorithm": "EC"},
    ])
    rows[2].previous_hash = "f" * 64  # predecessor link tampered
    factory.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        r = await ac.get(f"/api/v1/findings/{rows[2].id}/verify")
    body = r.json()
    assert body["result"] == "FAIL"
    assert body["chain_intact"] is False
    assert any("predecessor hash mismatch" in e for e in body["errors"])
    engine.dispose()


@pytest.mark.asyncio
async def test_first_record_seeds_from_scan_id():
    app, factory, engine = _make_app()
    factory.add(Scan(id="scan-d", status="COMPLETED", target_location="local://x",
                     target_type="LOCAL_DIRECTORY", operator="t", scan_start=NOW))
    factory.commit()
    rows = _commit_chain(factory, "scan-d", [{"algorithm": "AES"}])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        r = await ac.get(f"/api/v1/findings/{rows[0].id}/verify")
    assert r.status_code == 200
    assert r.json()["result"] == "PASS"  # position 0 chain hash seeds from the scan id
    engine.dispose()


@pytest.mark.asyncio
async def test_unknown_evidence_is_404():
    app, factory, engine = _make_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        r = await ac.get("/api/v1/findings/does-not-exist/verify")
    assert r.status_code == 404
    engine.dispose()
