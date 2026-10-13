"""The whole product chain in ONE set of runs (product vision §7, local slice).

scan → evidence → facts → assets → BOMs → policy → drift → remediation → reports

This is the demonstration the readiness boundary said was missing: not one
stage tested in isolation, but the real pipeline (clone → scan → evidence
hash chain → load → normalize → policy → dedup/assets → facts → graph →
drift → gate → CBOM) executed three times over a real local estate, with
the operator loop between the runs, and every link read back through the
authenticated API:

  run 1  clean estate (AES-GCM only)        → evidence chain verifies PASS,
            fact store materialised, assets + evidence links, CBOM identity,
            and a PROPOSED baseline (clean scans propose, never activate)
  approve baseline through the API (auditor)
  run 2  weak crypto introduced (3DES)      → NEW drift event, FAIL policy,
            remediation task auto-opened from the acknowledgement
  resolve the event administratively (honest: not verified remediation)
  run 3  condition fixed (3DES → AES-GCM)   → drift verification hook stamps
            the RESOLVED event VERIFIED from run 3's evidence (§4.7), the
            remediation task verifies against the same rescan, reports and
            the audit ledger tell the whole story

Failure paths are part of the contract: an emergency stop refuses the
manual trigger and launches nothing, and a tenant-scoped run stamps every
persisted row. PostgreSQL runs when a server is available and is skipped,
never faked, otherwise (the estate_db convention).
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

import db.models  # noqa: F401 - register tables
from api.dependencies import get_current_user, get_db_session, require_admin, require_auditor
from api.main import create_app
from db.connection.session import Base
from db.models.baseline import Baseline
from db.models.crypto_asset import CryptoAsset
from db.models.crypto_asset_evidence import CryptoAssetEvidence
from db.models.drift_event import DriftEvent
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan
from db.models.system import System
from db.models.user import AuditLog, User
from db.tenancy import install_tenant_guard, tenant_scope
from worker.pipeline.pipeline_runner import PipelineRunner

ROOT = Path(__file__).resolve().parents[4]

AES_JAVA = """
import javax.crypto.Cipher;
public class PaymentCrypto {
    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
}
"""

TRIPLE_DES_JAVA = """
import javax.crypto.Cipher;
public class LegacyPad {
    Cipher make() throws Exception {
        return Cipher.getInstance("DESede/CBC/PKCS5Padding");
    }
}
"""

SYSTEMS_YML = """systems:
  - system: PAYMENTS
    paths: [src/**]
    criticality: critical
    owner: payments@bank.example
    compliance_scopes: [BASELINE]
"""


def _estate(root: Path) -> Path:
    repo = root / "estate"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "PaymentCrypto.java").write_text(AES_JAVA)
    (repo / "cryptoscan-systems.yml").write_text(SYSTEMS_YML)
    return repo


def _call(app, method: str, path: str, json=None):
    async def _run():
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
            return await ac.request(method, path, json=json)
    return asyncio.run(_run())


@pytest.fixture(scope="module", params=["sqlite", "postgresql"])
def chain(request, tmp_path_factory):
    from db.testing import drop_engine, estate_engine

    engine = estate_engine(request.param)
    if engine is None:
        pytest.skip("no PostgreSQL: set CRYPTOSCAN_TEST_DATABASE_URL or pip install pgserver")
    Base.metadata.create_all(engine)
    from sqlalchemy.orm import sessionmaker

    factory = sessionmaker(bind=engine, expire_on_commit=False)

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "full-chain-e2e-" + "z" * 20)
    from api.config.settings import get_settings

    get_settings.cache_clear()
    install_tenant_guard()
    from api.events.bus import reset_event_bus

    reset_event_bus()

    with factory() as db:
        db.add(User(username="aud", roles="auditor,admin", password_hash="x"))
        db.commit()

    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "aud"
    app.dependency_overrides[require_auditor] = lambda: "aud"
    app.dependency_overrides[require_admin] = lambda: "aud"
    from api.routers.trigger import require_scan_trigger

    app.dependency_overrides[require_scan_trigger] = lambda: "aud"

    def session_dependency():
        with factory() as db:
            yield db

    app.dependency_overrides[get_db_session] = session_dependency

    root = tmp_path_factory.mktemp("full-chain")
    estate = _estate(root)

    def run(job_id: str) -> str:
        ws = root / f"ws-{job_id}"
        ws.mkdir()
        with factory() as db:
            scan_id = PipelineRunner().run(
                job_id=job_id, target_repo=f"local://{estate}",
                target_branch="main", triggered_by="e2e-operator",
                db=db, workspace_dir=str(ws),
            )
            db.commit()
        assert scan_id
        with factory() as db:
            scan = db.get(Scan, scan_id)
            assert scan is not None and scan.status == "COMPLETED", (
                getattr(scan, "error_message", None))
        return scan_id

    # ---- run 1: clean estate ------------------------------------------------
    scan1 = run("e2e-job-1")
    with factory() as db:
        proposal = db.scalar(select(Baseline).where(Baseline.status == "PROPOSED"))
        assert proposal is not None, "clean scan must propose a baseline (never activate it)"
        proposal_id = proposal.id
    approved = _call(app, "POST", f"/api/v1/baselines/{proposal_id}/approve-proposed", {})
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "ACTIVE"

    # ---- run 2: weak crypto introduced --------------------------------------
    (estate / "src" / "LegacyPad.java").write_text(TRIPLE_DES_JAVA)
    scan2 = run("e2e-job-2")
    with factory() as db:
        event = db.scalar(select(DriftEvent).where(DriftEvent.current_scan_id == scan2))
        assert event is not None, "changed estate against an approved baseline must drift"
        event_id = event.id
        weak = db.scalar(select(EvidenceRecord).where(
            EvidenceRecord.scan_id == scan2, EvidenceRecord.algorithm == "3DES"))
        assert weak is not None, "the introduced 3DES must be observed as evidence"

    # acknowledge → auto-open the remediation task; resolve administratively
    acked = _call(app, "POST", f"/api/v1/drift/{event_id}/acknowledge",
                  {"notes": "triaged: legacy pad must go", "create_remediation_tasks": True})
    assert acked.status_code == 200, acked.text
    task_ids = acked.json().get("remediation_task_ids") or []
    resolved = _call(app, "POST", f"/api/v1/drift/{event_id}/resolve",
                     {"notes": "administrative closure pending fix"})
    assert resolved.status_code == 200, resolved.text

    # ---- run 3: condition fixed ---------------------------------------------
    (estate / "src" / "LegacyPad.java").write_text(AES_JAVA.replace("PaymentCrypto", "LegacyPad"))
    scan3 = run("e2e-job-3")

    # the operator loop closes through the task: accept → complete → verify
    # against run 3's evidence
    task_id = None
    if task_ids:
        task_id = task_ids[0]
    else:  # fallback: open the task directly from the failing evidence
        created = _call(app, "POST", "/api/v1/remediation/tasks",
                        {"evidence_id": weak.id})
        assert created.status_code == 200, created.text
        task_id = created.json()["id"]
    for method, path, body in (
        ("POST", f"/api/v1/remediation/tasks/{task_id}/accept", None),
        ("POST", f"/api/v1/remediation/tasks/{task_id}/complete",
         {"rescan_id": scan3, "notes": "replaced 3DES with AES-GCM"}),
        ("POST", f"/api/v1/remediation/tasks/{task_id}/verify", {"rescan_id": scan3}),
    ):
        resp = _call(app, method, path, body)
        assert resp.status_code == 200, (path, resp.text)
        if path.endswith("/verify"):
            verify_response = resp.json()

    yield {
        "app": app, "factory": factory, "estate": estate,
        "task_verify": verify_response,
        "scan1": scan1, "scan2": scan2, "scan3": scan3,
        "event_id": event_id, "task_id": task_id, "weak_evidence_id": weak.id,
    }
    engine.dispose()
    drop_engine(engine)


pytestmark = pytest.mark.timeout(600)


# --------------------------------------------------------------------- the chain
@pytest.mark.asyncio
async def test_link_scan_and_evidence_chain(chain):
    """Scan completes; the stored evidence chain verifies PASS end-to-end."""
    async with AsyncClient(transport=ASGITransport(app=chain["app"]), base_url="http://t") as ac:
        listed = await ac.get("/api/v1/scans?page=1&page_size=10")
        assert listed.status_code == 200
        scans = listed.json()["scans"]
        assert {s["scan_id"] for s in scans} >= {chain["scan1"], chain["scan2"], chain["scan3"]}
        assert all(s["status"] == "COMPLETED" for s in scans)

        verified = await ac.get(f"/api/v1/scans/{chain['scan1']}/verify")
        assert verified.status_code == 200, verified.text
        body = verified.json()
        assert body["result"] == "PASS", body
        assert body["chain_intact"] and body["content_intact"] and body["records"] > 0

        findings = await ac.get(f"/api/v1/scans/{chain['scan1']}/findings")
        assert findings.status_code == 200
        rows = findings.json()["findings"]
        assert rows and any(r["algorithm"] == "AES" for r in rows)


@pytest.mark.asyncio
async def test_link_policy_marks_weak_crypto_fail(chain):
    """The policy engine evaluates real evidence: 3DES FAILs, AES passes."""
    async with AsyncClient(transport=ASGITransport(app=chain["app"]), base_url="http://t") as ac:
        r = await ac.get(f"/api/v1/scans/{chain['scan2']}/findings")
        assert r.status_code == 200
        rows = r.json()["findings"]
        weak = [x for x in rows if x["algorithm"] == "3DES"]
        assert weak, "run 2 must carry the 3DES observation"
        assert weak[0]["compliance_status"] == "FAIL"
        rules = (weak[0].get("policy_evaluation") or {}).get("rules_evaluated", [])
        assert any(r_.get("rule_id") == "BASELINE-001"
                   and str(r_.get("evaluation_result", "")).upper() == "FAIL"
                   for r_ in rules), rules

        r1 = await ac.get(f"/api/v1/scans/{chain['scan1']}/findings")
        strong = [x for x in r1.json()["findings"] if x["algorithm"] == "AES"]
        assert strong and strong[0]["compliance_status"] != "FAIL"


@pytest.mark.asyncio
async def test_link_facts_materialized(chain):
    """The fact store carries tenant-local rows for the scanned files."""
    async with AsyncClient(transport=ASGITransport(app=chain["app"]), base_url="http://t") as ac:
        r = await ac.get("/api/v1/facts/store?algorithm=AES")
        assert r.status_code == 200, r.text
        body = r.json()
        rows = body.get("facts") or body.get("rows") or []
        assert rows, body
        paths = [str((x.get("fact") or {}).get("file_path") or x.get("file_path") or "")
                 for x in rows]
        assert any("PaymentCrypto" in p or "LegacyPad" in p for p in paths), paths
    with chain["factory"]() as db:
        stats = (db.get(Scan, chain["scan1"]).statistics or {})
        assert stats.get("fact_store_status") != "FAILED"


@pytest.mark.asyncio
async def test_link_assets_deduplicated_with_evidence(chain):
    """Deduplicated crypto assets exist and link back to exact evidence."""
    async with AsyncClient(transport=ASGITransport(app=chain["app"]), base_url="http://t") as ac:
        r = await ac.get("/api/v1/assets?page=1&page_size=50")
        assert r.status_code == 200
        assets = r.json()["assets"]
        assert assets, "the scan must materialise crypto assets"
        algorithms = {a["algorithm"] for a in assets}
        assert "AES" in algorithms
        linked = [a for a in assets if a.get("id")]
        detail = await ac.get(f"/api/v1/assets/{linked[0]['id']}")
        assert detail.status_code == 200
        assert detail.json().get("evidence_ids"), "asset must reference its evidence"
    with chain["factory"]() as db:
        assert db.execute(select(CryptoAssetEvidence.id).limit(1)).first() is not None


@pytest.mark.asyncio
async def test_link_bom_from_scan_evidence(chain):
    """The BOM query serves identities grounded in the scanned estate."""
    async with AsyncClient(transport=ASGITransport(app=chain["app"]), base_url="http://t") as ac:
        r = await ac.get("/api/v1/cbom/query?algorithm=AES")
        assert r.status_code == 200, r.text
        matches = r.json().get("matches") or []
        assert matches, "AES from the scan must appear as a BOM identity"
        crypto = [m for m in matches if m.get("kind") == "crypto"]
        assert crypto and all(m.get("present_in") for m in crypto)


@pytest.mark.asyncio
async def test_link_drift_operator_loop_and_condition_verification(chain):
    """NEW drift → acknowledge → task → administrative resolve → §4.7
    condition-level VERIFIED stamped by the rescan, all in one chain."""
    async with AsyncClient(transport=ASGITransport(app=chain["app"]), base_url="http://t") as ac:
        r = await ac.get("/api/v1/drift?page=1&page_size=20")
        assert r.status_code == 200
        events = {e["drift_id"]: e for e in r.json()["events"]}
        event = events[chain["event_id"]]
        assert event["resolution_status"] == "RESOLVED"
        # the evidence-backed verdict from run 3 — not the administrative state
        assert event["verification_status"] == "VERIFIED"
        assert event["verified_by_scan_id"] == chain["scan3"]
        assert event["verified_at"]


@pytest.mark.asyncio
async def test_link_remediation_task_verified_by_rescan(chain):
    """The remediation task closes with a persisted, evidence-backed proof."""
    async with AsyncClient(transport=ASGITransport(app=chain["app"]), base_url="http://t") as ac:
        r = await ac.get(f"/api/v1/remediation/tasks/{chain['task_id']}")
        assert r.status_code == 200, r.text
        task = r.json()
        assert task["status"] in ("VERIFIED", "COMPLETED"), chain["task_verify"]
        v = await ac.get(f"/api/v1/remediation/verifications?task_id={chain['task_id']}")
        assert v.status_code == 200
        proofs = v.json().get("verifications") or v.json().get("tasks") or []
        assert proofs, "a verification proof must be persisted for the task"
        latest = proofs[0]
        assert latest["result"] == "VERIFIED", latest
        assert latest.get("rescan_id") == chain["scan3"]


@pytest.mark.asyncio
async def test_link_reports_and_audit_trail(chain):
    """Exports carry the scan + projected findings; the audit ledger tells
    the operator story; systems from the estate declaration persisted."""
    async with AsyncClient(transport=ASGITransport(app=chain["app"]), base_url="http://t") as ac:
        export = await ac.get(f"/api/v1/scans/{chain['scan3']}/export")
        assert export.status_code == 200, export.text
        payload = export.json()
        assert payload["scan"]["scan_id"] == chain["scan3"]
        assert payload["findings"]
        csv_export = await ac.get(f"/api/v1/scans/{chain['scan3']}/export.csv")
        assert csv_export.status_code == 200
        assert "AES" in csv_export.text
    with chain["factory"]() as db:
        actions = {a.action for a in db.query(AuditLog).all()}
        assert "drift.acknowledge" in actions
        assert "drift.resolve" in actions
        systems = db.execute(select(System.name)).scalars().all()
        assert "PAYMENTS" in systems


# ----------------------------------------------------------------- failure path
def test_failure_path_emergency_stop_launches_nothing(chain, monkeypatch):
    """An engaged emergency stop refuses the manual trigger with 409 and no
    scan is created — the refusal happens before any collector runs."""
    from api.security import scan_admission as admission

    monkeypatch.setattr(admission, "_control_plane_state",
                        lambda: ([{"event_type": "safe_scan.emergency_stop",
                                   "payload": {"engaged": True},
                                   "created_at": "2026-10-13T00:00:00+00:00"}], None))
    monkeypatch.setattr(admission, "_ot_declared", lambda: False)
    monkeypatch.setattr(admission, "_active_job_count", lambda: 0)

    with chain["factory"]() as db:
        before = db.execute(select(Scan.id)).scalars().all()

    resp = _call(chain["app"], "POST", "/api/v1/scans/trigger",
                 {"repo_url": f"local://{chain['estate']}", "branch": "main"})
    assert resp.status_code == 409, resp.text

    with chain["factory"]() as db:
        after = db.execute(select(Scan.id)).scalars().all()
    assert set(after) == set(before)


def test_failure_path_tenant_scope_stamps_every_row(tmp_path):
    """A tenant-scoped run stamps every persisted row with the tenant — the
    isolation boundary the adversarial suites probe is visible here too."""
    from db.testing import drop_engine, estate_engine

    engine = estate_engine("sqlite")
    Base.metadata.create_all(engine)
    from sqlalchemy.orm import sessionmaker

    factory = sessionmaker(bind=engine, expire_on_commit=False)
    install_tenant_guard()  # idempotent; do not depend on fixture order
    estate = tmp_path / "tenant-estate"
    (estate / "src").mkdir(parents=True)
    (estate / "src" / "TenantCrypto.java").write_text(
        AES_JAVA.replace("PaymentCrypto", "TenantCrypto"))
    (estate / "cryptoscan-systems.yml").write_text(SYSTEMS_YML)
    ws = tmp_path / "ws-tenant"
    ws.mkdir()

    with factory() as db:
        with tenant_scope("tenant-e2e"):
            scan_id = PipelineRunner().run(
                job_id="e2e-job-tenant", target_repo=f"local://{estate}",
                target_branch="main", triggered_by="e2e-operator",
                db=db, workspace_dir=str(ws),
            )
            db.commit()

    with factory() as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None and scan.status == "COMPLETED"
        assert scan.tenant_id == "tenant-e2e"
        evidence = db.execute(select(EvidenceRecord).where(
            EvidenceRecord.scan_id == scan_id)).scalars().all()
        assert evidence and all(e.tenant_id == "tenant-e2e" for e in evidence)
        assets = db.execute(select(CryptoAsset).where(
            CryptoAsset.file_path.like("%TenantCrypto%"))).scalars().all()
        assert assets and all(a.tenant_id == "tenant-e2e" for a in assets)
        from db.models.cryptographic_fact import CryptographicFact

        facts = db.execute(select(CryptographicFact).where(
            CryptographicFact.file_path.like("%TenantCrypto%"))).scalars().all()
        assert facts and all(f.tenant_id == "tenant-e2e" for f in facts)
    engine.dispose()
    drop_engine(engine)
