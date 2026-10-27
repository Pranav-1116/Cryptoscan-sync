"""Evidence soft delete: tombstones that preserve the hash chain (audits 15/16).

Covers the full contract of POST /findings/{id}/soft-delete and
/findings/{id}/restore:

* auditor gate (non-auditor gets 403);
* reason is mandatory;
* listing surfaces exclude tombstones, raw projection shows them;
* chain verification still passes with a tombstone present (the entire
  point — retraction must not break integrity);
* restore reverses the tombstone; double-delete and restore-of-alive
  return 409;
* retracted evidence generates no remediation suggestions (409).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register all tables
from api.dependencies import get_current_user, get_db_session, require_auditor
from api.main import create_app
from db.connection.session import Base
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan
from evidence.core.pipeline import EvidencePipeline


def _make_app(roles_user="auditor-admin", override_auditor=True, db_roles=None):
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    if db_roles is not None:
        # seed the users-table role the real gate reads via _user_roles
        from db.models.user import User

        session.add(User(username=roles_user, roles=db_roles, password_hash="x"))
        session.flush()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: roles_user
    if override_auditor:
        app.dependency_overrides[require_auditor] = lambda: roles_user
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session, engine


def _seed(session, scan_id="scan-softdel", count=3):
    """Seed a scan whose evidence chain genuinely verifies (EvidencePipeline)."""
    findings = []
    for index in range(count):
        findings.append(
            {
                "finding_id": f"f{index}",
                "source": {"file_path": f"src/Crypto{index}.java", "line_number": index + 1},
                "crypto": {"algorithm": "RSA", "key_size": 1024},
                "metadata": {"confidence": "HIGH"},
            }
        )
    records, manifest = EvidencePipeline(scan_id).process(findings, scan_id=scan_id)
    session.add(
        Scan(
            id=scan_id,
            scan_start=datetime(2026, 10, 9, tzinfo=timezone.utc),
            target_location="https://github.com/org/payments.git",
            target_type="GIT_REPOSITORY",
            status="COMPLETED",
            manifest_hash=manifest.manifest_hash,
            statistics={"total_findings": len(records)},
        )
    )
    session.flush()
    rows = []
    for record in records:
        row = EvidenceRecord(
            id=record.evidence_id,
            scan_id=scan_id,
            content_hash=record.content_hash,
            chain_hash=record.chain_hash,
            previous_hash=record.previous_hash,
            chain_position=record.chain_position,
            finding_data=record.finding,
            algorithm="RSA",
            key_size=1024,
            confidence="HIGH",
            purpose="SIGNING",
            mode=None,
            file_path=record.finding["source"]["file_path"],
            line_number=record.finding["source"]["line_number"],
            compliance_status="FAIL",
        )
        session.add(row)
        rows.append(row)
    session.commit()
    return rows


@pytest.mark.asyncio
async def test_soft_delete_hides_from_listing_but_chain_and_raw_stay():
    app, session, engine = _make_app()
    rows = _seed(session)
    target = rows[1]
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # auditor retracts the middle finding with a reason
        resp = await client.post(
            f"/api/v1/findings/{target.id}/soft-delete", json={"reason": "false positive — test fixture"}
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["deleted_at"] is not None
        assert body["deleted_by"] == "auditor-admin"
        assert body["delete_reason"] == "false positive — test fixture"

        # listing surfaces (per-scan and global) drop the tombstone
        listed = (await client.get("/api/v1/scans/scan-softdel/findings")).json()
        listed_ids = {f["evidence_id"] for f in listed["findings"]}
        assert target.id not in listed_ids
        assert len(listed_ids) == 2
        all_findings = (await client.get("/api/v1/findings")).json()
        assert target.id not in {f["evidence_id"] for f in all_findings["findings"]}

        # raw projection still shows the tombstone (auditor inspectability)
        raw = (await client.get(f"/api/v1/findings/{target.id}")).json()
        assert raw["deleted_at"] is not None
        assert raw["delete_reason"] == "false positive — test fixture"

        # chain verification must still pass: the tombstone stays in the
        # chain it committed to
        verdict = (
            await client.get("/api/v1/scans/scan-softdel/verify")
        ).json()
        assert verdict["result"] == "PASS", verdict
        assert verdict["records"] == 3, "tombstone must still be counted in the chain"
    engine.dispose()


@pytest.mark.asyncio
async def test_soft_delete_requires_reason_and_auditor_role():
    # the real require_auditor gate runs (no override): a viewer with a
    # bearer token is refused on both endpoints
    app, session, engine = _make_app(
        roles_user="plain-user", override_auditor=False, db_roles="viewer"
    )
    rows = _seed(session)
    transport = ASGITransport(app=app)
    headers = {"Authorization": "Bearer test-token"}
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # non-auditor is rejected even with a valid reason
        resp = await client.post(
            f"/api/v1/findings/{rows[0].id}/soft-delete",
            json={"reason": "not allowed anyway"},
            headers=headers,
        )
        assert resp.status_code == 403, resp.text
        # restore is gated the same way
        assert (
            await client.post(f"/api/v1/findings/{rows[0].id}/restore", headers=headers)
        ).status_code == 403
    engine.dispose()

    # auditor without a reason is rejected by validation
    app2, session2, engine2 = _make_app()
    rows2 = _seed(session2)
    transport2 = ASGITransport(app=app2)
    async with AsyncClient(transport=transport2, base_url="http://test") as client:
        resp = await client.post(f"/api/v1/findings/{rows2[0].id}/soft-delete", json={"reason": "no"})
        assert resp.status_code == 422, resp.text
    engine2.dispose()


@pytest.mark.asyncio
async def test_restore_round_trip_and_conflict_semantics():
    app, session, engine = _make_app()
    rows = _seed(session)
    target = rows[0]
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # double delete -> 409
        first = await client.post(
            f"/api/v1/findings/{target.id}/soft-delete", json={"reason": "first retraction"}
        )
        assert first.status_code == 200
        second = await client.post(
            f"/api/v1/findings/{target.id}/soft-delete", json={"reason": "second retraction"}
        )
        assert second.status_code == 409
        assert "already retracted" in second.json()["detail"]

        # restore -> alive again, tombstone cleared
        restored = await client.post(f"/api/v1/findings/{target.id}/restore")
        assert restored.status_code == 200
        assert restored.json()["deleted_at"] is None
        assert restored.json()["delete_reason"] is None
        listed = (await client.get("/api/v1/scans/scan-softdel/findings")).json()
        assert target.id in {f["evidence_id"] for f in listed["findings"]}

        # restore of a live finding -> 409
        assert (
            await client.post(f"/api/v1/findings/{target.id}/restore")
        ).status_code == 409

        # unknown finding -> 404 on both
        assert (
            await client.post("/api/v1/findings/does-not-exist/soft-delete", json={"reason": "missing"})
        ).status_code == 404
        assert (await client.post("/api/v1/findings/does-not-exist/restore")).status_code == 404
    engine.dispose()


@pytest.mark.asyncio
async def test_retracted_evidence_blocks_remediation_suggestions():
    app, session, engine = _make_app()
    rows = _seed(session)
    target = rows[2]
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        assert (
            await client.post(
                f"/api/v1/findings/{target.id}/soft-delete", json={"reason": "scanner false positive"}
            )
        ).status_code == 200
        # fix suggestions for a retracted finding are refused
        resp = await client.post(
            "/api/v1/remediation/fix-branch", json={"evidence_id": target.id}
        )
        assert resp.status_code == 409, resp.text
        assert "retracted" in resp.json()["detail"]
        # and so is remediation-task creation
        resp = await client.post(
            "/api/v1/remediation/tasks", json={"evidence_id": target.id}
        )
        assert resp.status_code == 409, resp.text
    engine.dispose()
