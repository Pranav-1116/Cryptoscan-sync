"""SNB-profile estate, read back through the real HTTP API.

`services/worker/tests/unit/test_pipeline_snb_estate.py` proves the pipeline writes the right evidence, systems,
verdicts and key reconciliation into the database. This test closes the last hop: the same representative
Saudi-bank estate (synthetic — not SNB's systems) is pushed through `PipelineRunner` into one SQLite database, and
everything a bank analyst would open in the console is then fetched through `create_app()` with a **real signed
session** (no dependency overrides except the DB): scan detail, findings, cascade systems, key reconciliation,
declared systems, and the portfolio CBOM. Every number the API returns is cross-checked against the rows in the DB.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

import db.models  # noqa: F401 — register all tables
from api.dependencies import get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan
from db.models.system import System

ROOT = Path(__file__).resolve().parents[4]
for p in ("services/worker", "services/worker/tests/unit", "services/scanner", "services/scanner/tests", "shared/shared_models"):
    if str(ROOT / p) not in sys.path:
        sys.path.insert(0, str(ROOT / p))

from test_pipeline_snb_estate import DEPENDS, LAYOUT, _estate, _key_drop  # noqa: E402  (the estate builder is shared with the worker test)
from worker.pipeline.pipeline_runner import PipelineRunner  # noqa: E402

FAIL = {"NON_COMPLIANT", "FAIL", "VIOLATION"}


def _make_app(backend: str):
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings
    from db.testing import estate_engine

    get_settings.cache_clear()
    engine = estate_engine(backend)
    if engine is None:
        pytest.skip("no PostgreSQL: set CRYPTOSCAN_TEST_DATABASE_URL or pip install pgserver")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session, engine


def _act_as(client, session, username: str, roles: str = "superadmin"):
    from api.security.session_manager import SessionManager
    from db.repositories.user_repository import UserRepository

    # A platform principal: this estate is one bank's, written by the pipeline
    # with no tenant stamp, and every read below is a read of that one estate.
    # A tenant-scoped analyst account would resolve to a tenant whose rows these
    # are not, and the 403/empty-list that follows would be reported as a product
    # bug when it is really the test asking for the wrong principal.
    if UserRepository(session).get_by_username(username) is None:
        UserRepository(session).create_user(username, "x", roles=[roles])
        session.commit()
    client.headers["Authorization"] = f"Bearer {SessionManager().create_session(username, roles=[roles])}"


def _run(runner, session, tmp_path, target: Path, job_id: str) -> str:
    ws = tmp_path / f"ws-{job_id}"
    ws.mkdir()
    return runner.run(job_id=job_id, target_repo=f"local://{target}", target_branch="main", triggered_by="snb-pilot", db=session, workspace_dir=str(ws))


async def _get(client, url: str, **params):
    r = await client.get(url, params=params or None)
    assert r.status_code == 200, (url, r.status_code, r.text[:300])
    return r.json()


@pytest.mark.timeout(300)
@pytest.mark.asyncio
@pytest.mark.parametrize("backend", ["sqlite", "postgresql"])
async def test_snb_estate_readable_through_the_api(tmp_path, monkeypatch, backend):
    monkeypatch.setenv("CRYPTOSCAN_KEY_INVENTORY", "1")
    app, session, engine = _make_app(backend)
    try:
        await _scenario(tmp_path, app, session)
    finally:
        from db.testing import drop_engine

        session.close()
        drop_engine(engine)


async def _scenario(tmp_path, app, session):
    repo, labels = _estate(tmp_path)
    runner = PipelineRunner()
    scan_id = _run(runner, session, tmp_path, repo, "job-snb-api-code")
    inv_id = _run(runner, session, tmp_path, _key_drop(tmp_path), "job-snb-api-keys")
    session.commit()
    rows = session.execute(select(EvidenceRecord).where(EvidenceRecord.scan_id == scan_id)).scalars().all()
    assert rows and session.get(Scan, scan_id).status == "COMPLETED"

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # unauthenticated → refused (401/403), never a listing
        assert (await client.get(f"/api/v1/scans/{scan_id}")).status_code in (401, 403)
        _act_as(client, session, "snb-analyst", roles="superadmin")

        # ---- scan detail -------------------------------------------------------------------------------
        detail = await _get(client, f"/api/v1/scans/{scan_id}")
        assert detail["status"] == "COMPLETED" and detail["scan_id"] == scan_id
        stats = detail.get("statistics") or {}
        assert stats.get("cascade_summary") or stats.get("cascade"), "scan detail must expose the cascade summary"

        # ---- findings: every persisted evidence row is reachable, with file + algorithm + verdict -------
        seen: list[dict] = []
        page, size = 1, 100
        while True:
            body = await _get(client, f"/api/v1/scans/{scan_id}/findings", page=page, page_size=size)
            items = body["findings"]
            seen.extend(items)
            total = body["total_count"]
            if not items or len(seen) >= total:
                break
            page += 1
        assert len(seen) == len(rows), (len(seen), len(rows))
        by_id = {r.id: r for r in rows}
        for item in seen:
            row = by_id[item["evidence_id"]]
            assert item["file_path"] == row.file_path and item["algorithm"] == row.algorithm
        api_files = {str(i["file_path"]).split("!", 1)[0].lstrip("./") for i in seen}
        # the labelled positives are all visible; the Arabic negatives are not
        positives = {p for p, exp in labels.items() if exp}
        assert positives <= api_files, sorted(positives - api_files)
        for neg in ("core-ledger/HijriDateConverter.java", "sadad/SadadBillModels.cs", "infra/sama-reporting-schedule.yaml"):
            assert neg not in api_files
        # the weak spots read as failures through the API too
        gpo = [i for i in seen if i["file_path"].endswith("legacy-branch-gpo.inf") and str(i["algorithm"]).upper() == "RC4"]
        assert gpo and all(str(i.get("compliance_status") or "").upper() in FAIL for i in gpo), gpo[:2]
        md5 = [i for i in seen if i["file_path"].endswith("legacy_pwd_hash.sql") and str(i["algorithm"]).upper() == "MD5"]
        assert md5 and all(str(i.get("compliance_status") or "").upper() in FAIL for i in md5)

        # ---- cascade: systems roll-up and per-system filter ---------------------------------------------
        cas = await _get(client, f"/api/v1/scans/{scan_id}/cascade", section="systems")
        systems = {s["system"]: s for s in (cas.get("systems") or cas.get("items") or [])}
        assert set(systems) == set(LAYOUT), sorted(systems)
        assert "3DES" in systems["MADA-SWITCH"]["algorithms"] and systems["MADA-SWITCH"]["criticality"] == "critical"
        assert "CORE-LEDGER" in (systems["MADA-SWITCH"].get("depends_on_systems") or [])
        only_mobile = await _get(client, f"/api/v1/scans/{scan_id}/cascade", section="providers", system="SNB-MOBILE")
        assert only_mobile, "per-system cascade filter must answer"

        # ---- key reconciliation: the join the console shows ------------------------------------------
        rec = await _get(client, f"/api/v1/scans/{inv_id}/key-reconciliation")
        assert scan_id in {s["scan_id"] if isinstance(s, dict) else s for s in rec["source_scans"]}
        assert {c["label"] for c in rec["consumers"]} >= {"MADA.ZPK.ACQ.001"}
        assert rec["summary"]["orphans"] >= 1 and rec["summary"]["not_in_inventory"] >= 1
        assert rec["summary"] == session.get(Scan, inv_id).statistics["key_reconciliation"]["summary"]

        # ---- UI contract: the exact fields the console panels read (CodeCascadePanel / KeyReconciliationPanel) --
        for sy in systems.values():
            assert {"system", "criticality", "providers", "algorithms", "weak_parameters", "dependent_systems", "depends_on_systems", "files"} <= set(sy), sorted(sy)
        assert {"inventory_keys", "consumers", "orphans", "not_in_inventory"} <= set(rec["summary"])
        assert all({"system", "label"} <= set(c) for c in rec["consumers"])
        assert all({"kind", "identifier", "files", "sample_files"} <= set(n) for n in rec["not_in_inventory"])

        # ---- declared systems + portfolio CBOM ----------------------------------------------------------
        listed = await _get(client, "/api/v1/systems", page_size=200)
        names = {s["name"] for s in listed["systems"]}
        persisted = {s.name for s in session.execute(select(System)).scalars().all()}
        assert set(LAYOUT) <= names and names <= persisted, (sorted(names), sorted(persisted))
        for parent, children in DEPENDS.items():
            assert parent in names and all(c in names for c in children)
        cbom = await _get(client, "/api/v1/cbom/portfolio")
        comps = cbom.get("components") or []
        assert comps, "portfolio CBOM is empty after a completed scan"
        algo_names = {str(c.get("name", "")).upper() for c in comps}
        assert {"3DES", "AES", "RSA"} & algo_names or any("3DES" in n or "TRIPLE" in n for n in algo_names), sorted(algo_names)[:30]
        assert any((c.get("type") == "cryptographic-asset") for c in comps)
