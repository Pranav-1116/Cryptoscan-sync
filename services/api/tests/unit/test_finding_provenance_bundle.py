"""Finding provenance bundle — the hash-integrity-versus-truth distinction,
preserved as data.

Hashing the evidence detects later modification. It does not independently
prove that the collector observed the truth. Every finding must carry: the
collector, the asset inspected, when it was observed, the source and
collection method, the original evidence reference, the parser and
detection-rule version, the resulting finding, and the integrity
verification result — and the response must never upgrade a verified hash
into a claim about truth.
"""
from __future__ import annotations

import os
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
from db.models.collector_authority import CollectorAuthority
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan
from evidence.hashing.chain_hasher import ChainHasher
from evidence.hashing.content_hasher import ContentHasher

NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)


def _make_app():
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "provenance-bundle-" + "z" * 14)
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


def _seed(factory, *, scan_id="scan-p", evidence_id="ev-p", tamper: bool = False,
          authorize: bool = False):
    factory.add(Scan(
        id=scan_id, status="COMPLETED",
        scanner_id="static-java-scanner-v0.1", scanner_version="1.4.2",
        target_type="GIT_REPOSITORY", target_location="https://bank.example/repo.git",
        target_commit="abc123", operator="svc-collector",
        scan_start=NOW, scan_end=NOW + timedelta(minutes=2),
        manifest_hash="m" * 64))
    if authorize:
        factory.add(CollectorAuthority(
            tenant_id="t1", plane="collection", entry="https://bank.example/repo.git",
            permission="READ", target_kind="GIT_REPOSITORY",
            approved_by="security-lead", approved_at=NOW - timedelta(days=1),
            expires_at=NOW + timedelta(days=89)))
    payload = {"algorithm": "RSA", "key_size": 2048, "finding": "RSA-2048 configuration"}
    content = ContentHasher.compute_hash(payload)
    chain = ChainHasher.compute_chain_hash(
        content_hash=content, previous_chain_hash=None, scan_session_id=scan_id)
    row = EvidenceRecord(
        id=evidence_id, scan_id=scan_id, tenant_id="t1", content_hash=content,
        chain_hash=chain, chain_position=0, previous_hash=None,
        algorithm="RSA", key_size=2048, file_path="src/crypto/RsaConfig.java",
        line_number=42, class_name="RsaConfig", method_name="init",
        finding_data=payload,
        provenance={"scanner_ids": ["static-java-scanner-v0.1"]})
    if tamper:
        row.chain_hash = "f" * 64  # a chain link that does not verify
    factory.add(row)
    factory.commit()
    return row


@pytest.mark.asyncio
async def test_the_bundle_preserves_every_item_and_caps_the_claim():
    app, factory, engine = _make_app()
    _seed(factory)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        r = await ac.get("/api/v1/findings/ev-p/provenance")
    assert r.status_code == 200, r.text
    b = r.json()

    # 1-3: which collector, which asset, when
    assert b["collector"]["scanner_id"] == "static-java-scanner-v0.1"
    assert b["collector"]["scanner_version"] == "1.4.2"
    assert b["asset"]["file_path"] == "src/crypto/RsaConfig.java"
    assert b["asset"]["target_commit"] == "abc123"
    assert b["observed"]["scan_start"].startswith("2026-10-16")

    # 4: source and collection method (+ authorization, exact-match)
    assert b["source_and_method"]["target_location"] == "https://bank.example/repo.git"
    assert b["source_and_method"]["collection_method"] == "static-java-scanner-v0.1"
    assert b["source_and_method"]["collection_authorization"]["status"] == "NOT_RECORDED"

    # 5: the original evidence reference
    assert b["evidence_reference"]["storage_key"].endswith(".bin")
    assert b["evidence_reference"]["content_hash"]
    assert b["evidence_reference"]["manifest_hash"] == "m" * 64

    # 6: parser and detection-rule version
    assert b["detection"]["detection_rule_version"] == "1.4.2"

    # 7: the resulting finding
    assert b["finding"]["key_size"] == 2048

    # 8: the integrity verification result — and the CLAIM stays capped
    assert b["integrity"]["chain_link_verified"] is True
    assert b["integrity"]["verification_result"] == "CHAIN_LINK_VERIFIED"
    assert b["integrity"]["claim"] == "HASH_INTEGRITY_ONLY"
    assert "does not independently prove" in b["integrity"]["statement"]
    assert b["truth"]["independently_verified"] is False
    assert b["truth"]["status"] == "NOT_INDEPENDENTLY_VERIFIED"
    # nowhere does the bundle claim the hash proves truth
    assert "proves the collector" not in str(b).lower()
    engine.dispose()


@pytest.mark.asyncio
async def test_a_broken_chain_link_is_reported_not_smoothed_over():
    app, factory, engine = _make_app()
    _seed(factory, evidence_id="ev-x", tamper=True)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        r = await ac.get("/api/v1/findings/ev-x/provenance")
    b = r.json()
    assert b["integrity"]["chain_link_verified"] is False
    assert b["integrity"]["verification_result"] == "CHAIN_LINK_BROKEN"
    engine.dispose()


@pytest.mark.asyncio
async def test_an_exact_match_authority_is_reported_with_its_window():
    app, factory, engine = _make_app()
    _seed(factory, evidence_id="ev-a", authorize=True)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        r = await ac.get("/api/v1/findings/ev-a/provenance")
    auth = r.json()["source_and_method"]["collection_authorization"]
    assert auth["status"] == "AUTHORIZED"
    assert auth["permission"] == "READ"
    assert auth["approved_by"] == "security-lead"
    assert auth["expires_at"].startswith("2027")  # the window is visible
    engine.dispose()


@pytest.mark.asyncio
async def test_unknown_findings_404():
    app, factory, engine = _make_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        r = await ac.get("/api/v1/findings/nope/provenance")
    assert r.status_code == 404
    engine.dispose()
