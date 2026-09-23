"""POST /devsecops/binary/batch + GET /devsecops/binary/batches/{id}.

A fleet pass is judged by two things: that it queues each distinct binary exactly
once, and that everything it did *not* queue comes back with a reason and the
artifact that already covers it.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base

_SERVICES = Path(__file__).resolve().parents[3]


def _binary_fixtures():
    path = _SERVICES / "devsecops" / "tests" / "test_binary_scan.py"
    name = "binary_scan_fixtures"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


fixtures = _binary_fixtures()
_elf64 = fixtures._elf64


@pytest.fixture(autouse=True)
def _inline_queue(monkeypatch):
    """Queue without Redis, so the inline runner is the path under test."""
    import api.routers.trigger as trigger

    monkeypatch.setattr(trigger, "get_settings", lambda: SimpleNamespace(
        REDIS_URL="", SCAN_JOB_QUEUE_KEY="cryptoscan:jobs:queue"))


@pytest.fixture()
def app_db(tmp_path, monkeypatch):
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    application = create_app()
    application.dependency_overrides[get_current_user] = lambda: "operator"
    monkeypatch.setenv("SBOM_STORAGE_DIR", str(tmp_path / "sboms"))
    monkeypatch.setenv("CRYPTOSCAN_SOURCE_ROOTS", str(tmp_path))
    import api.routers.devsecops as ds

    monkeypatch.setattr(ds, "_SBOM_STORE", None)

    def _session():
        yield session

    application.dependency_overrides[get_db_session] = _session
    yield application, session, tmp_path
    application.dependency_overrides.clear()


def _viewer_app(tmp_path, monkeypatch):
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    from db.models.user import User

    session.add(User(username="viewer1", password_hash="x", roles="viewer"))
    session.commit()
    application = create_app()
    application.dependency_overrides[get_current_user] = lambda: "viewer1"
    monkeypatch.setenv("CRYPTOSCAN_SOURCE_ROOTS", str(tmp_path))
    import api.routers.devsecops as ds

    monkeypatch.setattr(ds, "_SBOM_STORE", None)

    def _session():
        yield session

    application.dependency_overrides[get_db_session] = _session
    return application


async def _post(application, url, payload, token="Bearer test-token"):
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.post(url, json=payload, headers={"Authorization": token})


async def _get(application, url, token="Bearer test-token"):
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.get(url, headers={"Authorization": token})


def _spool(tmp_path: Path) -> Path:
    """A release drop: one binary, a second copy of it, a different one, and noise."""
    drop = tmp_path / "drop"
    (drop / "lib").mkdir(parents=True)
    payload = _elf64(soname="libacme.so", imports=("EVP_EncryptInit_ex",))
    (drop / "lib" / "libacme.so").write_bytes(payload)
    (drop / "lib" / "copy-of-libacme.so").write_bytes(payload)
    (drop / "gateway.elf").write_bytes(_elf64(soname="gateway.elf", imports=("RSA_sign",)))
    (drop / "readme.txt").write_text("not a binary")
    return drop


def _stub_runner(monkeypatch, session):
    """Stand in for the worker: record the jobs and complete them in the test session."""
    import api.routers.trigger as trigger

    seen: list[dict] = []

    def _run_inline(payload: dict) -> None:
        seen.append(payload)
        from db.repositories.job_repository import JobRepository

        options = ((payload.get("progress") or {}).get("scan_options") or {})
        JobRepository(session).update_status(
            payload["job_id"], "COMPLETED",
            progress={"current_stage": "binary_ingest", "percent": 100,
                      "scan_options": options,
                      "binary": {"artifact_id": options.get("artifact_id"),
                                 "binaries_scanned": 1, "findings": 2, "yara_matches": 0,
                                 "report_url": f"/api/v1/devsecops/sbom/{options.get('artifact_id')}"
                                               "/report?fmt=markdown"}},
        )
        session.commit()

    monkeypatch.setattr(trigger, "_run_inline", _run_inline)
    return seen


# --------------------------------------------------------------------------- #
# planning
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_a_dry_run_returns_the_plan_and_queues_nothing(app_db):
    application, session, tmp_path = app_db
    drop = _spool(tmp_path)
    resp = await _post(application, "/api/v1/devsecops/binary/batch", {"spool": str(drop)})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["dry_run"] is True and body["queued"] == 2, body["files"]
    assert body["considered"] == 4
    assert "nothing was queued" in body["message"]
    assert body["state_path"].endswith(".cryptoscan-intake.json")

    from db.models.scan_job import ScanJob

    assert session.query(ScanJob).count() == 0, "a dry run must not touch the queue"
    assert not (drop / ".cryptoscan-intake.json").exists(), "a plan is not a scan: no memory yet"


@pytest.mark.asyncio
async def test_every_file_that_is_not_queued_says_why(app_db):
    application, _session, tmp_path = app_db
    resp = await _post(application, "/api/v1/devsecops/binary/batch", {"spool": str(_spool(tmp_path))})
    # the walk is sorted by path, so the copy is scanned and the original is the duplicate
    files = {Path(f["path"]).name: f for f in resp.json()["files"]}
    assert files["readme.txt"]["action"] == "skip"
    assert "not a binary-looking name" in files["readme.txt"]["reason"]
    assert "appears twice" in files["libacme.so"]["reason"]
    assert files["libacme.so"]["prior_path"].endswith("copy-of-libacme.so")
    assert {f["action"] for f in resp.json()["files"] if f["action"] == "queue"} == {"queue"}


@pytest.mark.asyncio
async def test_a_capped_pass_says_what_it_did_not_take(app_db):
    application, _session, tmp_path = app_db
    resp = await _post(application, "/api/v1/devsecops/binary/batch",
                       {"spool": str(_spool(tmp_path)), "limit": 1})
    body = resp.json()
    assert body["queued"] == 1
    assert any("over this pass's limit" in f["reason"] for f in body["files"])


@pytest.mark.asyncio
async def test_a_spool_outside_the_source_roots_is_a_400_and_a_missing_one_a_404(app_db):
    application, _session, _tmp_path = app_db
    outside = await _post(application, "/api/v1/devsecops/binary/batch", {"spool": "/etc"})
    assert outside.status_code == 400, outside.text
    missing = await _post(application, "/api/v1/devsecops/binary/batch",
                          {"spool": "/tmp/cryptoscan-no-such-spool"})
    assert missing.status_code in (400, 404), missing.text


@pytest.mark.asyncio
async def test_a_viewer_cannot_queue_a_fleet_pass(app_db, tmp_path, monkeypatch):
    application, _session, _tmp_path = app_db
    del application
    viewer_app = _viewer_app(tmp_path, monkeypatch)
    drop = _spool(tmp_path)
    resp = await _post(viewer_app, "/api/v1/devsecops/binary/batch",
                       {"spool": str(drop), "dry_run": False}, token="Bearer viewer-token")
    assert resp.status_code == 403, resp.text


# --------------------------------------------------------------------------- #
# queueing
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_queueing_creates_one_job_per_distinct_binary(app_db, monkeypatch):
    application, session, tmp_path = app_db
    seen = _stub_runner(monkeypatch, session)
    drop = _spool(tmp_path)
    resp = await _post(application, "/api/v1/devsecops/binary/batch",
                       {"spool": str(drop), "dry_run": False, "ingest_cbom": True})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["queued"] == 2 and body["state_saved"] is True
    assert len(seen) == 2, "one job per distinct binary, not per file"
    assert all(payload["job_type"] == "BINARY" for payload in seen)
    assert all(payload["target_repo"].startswith("binary://") for payload in seen)
    options = [((p.get("progress") or {}).get("scan_options") or {}) for p in seen]
    assert all(o.get("batch_id") == body["batch_id"] for o in options)
    assert all(o.get("ingest_cbom") is True for o in options)
    assert {Path(o["target"]).name for o in options} == {"copy-of-libacme.so", "gateway.elf"}

    from db.models.scan_job import ScanJob

    assert session.query(ScanJob).count() == 2
    assert len(body["queued_files"]) == 2
    assert all(row["artifact_id"] and row["job_id"] for row in body["queued_files"])


@pytest.mark.asyncio
async def test_a_second_pass_skips_what_the_first_one_scanned(app_db, monkeypatch):
    application, session, tmp_path = app_db
    seen = _stub_runner(monkeypatch, session)
    drop = _spool(tmp_path)
    first = await _post(application, "/api/v1/devsecops/binary/batch",
                        {"spool": str(drop), "dry_run": False})
    assert first.json()["queued"] == 2
    state_file = Path(first.json()["state_path"])
    assert state_file.is_file()

    second = await _post(application, "/api/v1/devsecops/binary/batch", {"spool": str(drop)})
    body = second.json()
    assert body["queued"] == 0
    covered = {Path(f["path"]).name: f for f in body["files"]}
    assert covered["gateway.elf"]["artifact_id"], "a skip names the artifact that covers it"
    assert "unchanged since the last pass" in covered["gateway.elf"]["reason"]
    assert covered["libacme.so"]["reason"] == "this content was already scanned under another path"

    before = len(seen)
    forced = await _post(application, "/api/v1/devsecops/binary/batch",
                         {"spool": str(drop), "force": True, "dry_run": False})
    assert forced.json()["queued"] == 2, "force scans it again"
    assert len(seen) - before == 2, "and it queues real jobs, not just a plan"


@pytest.mark.asyncio
async def test_an_unwritable_spool_reports_a_lost_memory(app_db, monkeypatch):
    application, session, tmp_path = app_db
    _stub_runner(monkeypatch, session)
    drop = _spool(tmp_path)
    drop.chmod(0o555)
    try:
        resp = await _post(application, "/api/v1/devsecops/binary/batch",
                           {"spool": str(drop), "dry_run": False})
    finally:
        drop.chmod(0o755)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["queued"] == 2, "the queue still gets fed"
    assert body["state_saved"] is False, "but the memory must not be reported as written"
    assert "re-scan" in body["state_note"]


@pytest.mark.asyncio
async def test_a_batch_pass_is_audited(app_db, monkeypatch):
    application, session, tmp_path = app_db
    _stub_runner(monkeypatch, session)
    resp = await _post(application, "/api/v1/devsecops/binary/batch",
                       {"spool": str(_spool(tmp_path))})
    assert resp.status_code == 200
    import json

    from db.models.user import AuditLog

    rows = [row for row in session.query(AuditLog).all() if row.action == "devsecops.binary_batch"]
    assert len(rows) == 1
    detail = json.loads(rows[0].detail) if isinstance(rows[0].detail, str) else rows[0].detail
    assert detail["dry_run"] is True and detail["queued"] == 0 and detail["considered"] == 4


# --------------------------------------------------------------------------- #
# status
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_batch_status_aggregates_the_jobs_it_queued(app_db, monkeypatch):
    application, session, tmp_path = app_db
    _stub_runner(monkeypatch, session)
    created = await _post(application, "/api/v1/devsecops/binary/batch",
                          {"spool": str(_spool(tmp_path)), "dry_run": False})
    batch_id = created.json()["batch_id"]
    resp = await _get(application, f"/api/v1/devsecops/binary/batches/{batch_id}")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["jobs"] == 2
    assert body["by_status"] == {"COMPLETED": 2}
    assert len(body["artifacts"]) == 2
    assert body["totals"]["findings"] == 4, "each stub job reported two findings"
    assert all(row["artifact_id"] and row["report_url"] for row in body["files"])
    assert body["window"]["truncated"] is False


@pytest.mark.asyncio
async def test_batch_status_is_honest_about_an_unknown_batch(app_db):
    application, _session, _tmp_path = app_db
    resp = await _get(application, "/api/v1/devsecops/binary/batches/does-not-exist")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["jobs"] == 0 and body["by_status"] == {}
    assert "may report 0" in body["window"]["note"], "the window is stated, not implied"


@pytest.mark.asyncio
async def test_a_job_listed_by_batch_id_finds_only_that_batch(app_db, monkeypatch):
    application, session, tmp_path = app_db
    _stub_runner(monkeypatch, session)
    drop = _spool(tmp_path)
    first = (await _post(application, "/api/v1/devsecops/binary/batch",
                         {"spool": str(drop), "dry_run": False})).json()
    second = (await _post(application, "/api/v1/devsecops/binary/batch",
                          {"spool": str(drop), "dry_run": False,
                           "batch_id": "batch-two"})).json()
    assert second["queued"] == 0 and second["batch_id"] == "batch-two"

    from db.repositories.job_repository import JobRepository

    repo = JobRepository(session)
    assert len(repo.list_by_scan_option("batch_id", first["batch_id"])) == 2
    assert repo.list_by_scan_option("batch_id", "batch-two") == []
