"""POST /devsecops/binary/dynamic — the opt-in dynamic path, end to end.

Two things are being pinned here: that nothing runs unless the host said so, and
that what *did* run reaches the runtime inventory with a usable verdict.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base

OPENSSL = "/usr/bin/openssl"


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
    monkeypatch.delenv("BINARY_EXECUTION_ENABLED", raising=False)
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


def _sample(tmp_path: Path) -> Path:
    """A real, dynamically linked ELF the preflight will accept."""
    sample = tmp_path / "sample.elf"
    sample.write_bytes(Path(OPENSSL).read_bytes())
    sample.chmod(0o755)
    return sample


def _executed_result(*observations: dict) -> dict:
    """A tracer result, as if the sample had run — so the wiring can be tested."""
    return {
        "target": "/tmp/cryproscan/sample.elf", "executed": True, "runnable": True,
        "refusals": [], "checks": {"policy": {"timeout_seconds": 10, "enabled": True}},
        "tracer": "ld_preload", "duration_ms": 900, "timed_out": False, "returncode": 0,
        "stdout": "", "stderr": "", "sha256_before": "c" * 64, "sha256_after": "c" * 64,
        "changed": False, "limits": ["no kernel sandbox"],
        "observations": list(observations),
        "findings": [{"code": "BIN-DYNAMIC-EXECUTED", "severity": "INFO", "title": "executed",
                      "detail": "ran", "path": "/tmp/cryproscan/sample.elf"}],
    }


def _observation(algorithm: str, *, pid: int = 99, count: int = 2, tls: int | None = None) -> dict:
    extra = {"source": "ld-preload"}
    if tls is not None:
        extra["tls_min_version"] = tls
    return {"process_name": "sample.elf", "pid": pid, "function": "EVP_CipherInit_ex",
            "algorithm": algorithm, "mode": None, "key_size": 16, "observation_count": count,
            "extra": extra}


# --------------------------------------------------------------------------- #
# the gate
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_a_dry_run_reports_the_preflight_and_starts_nothing(app_db, monkeypatch):
    application, _session, tmp_path = app_db
    monkeypatch.setenv("BINARY_EXECUTION_ENABLED", "true")
    resp = await _post(application, "/api/v1/devsecops/binary/dynamic", {"target": str(_sample(tmp_path))})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["executed"] is False
    assert any("dry run" in reason for reason in body["refusals"])
    assert body["findings"][0]["code"] == "BIN-DYNAMIC-DRY-RUN"
    assert body["limits"], "the API states what is not isolating the run"
    assert body["checks"]["tracer"] == "ld_preload"
    assert body["checks"]["policy"]["enabled"] is True


@pytest.mark.asyncio
async def test_with_execution_disabled_even_the_dry_run_says_why(app_db):
    """The preflight is still a preflight when the host forbids running at all."""
    application, _session, tmp_path = app_db
    resp = await _post(application, "/api/v1/devsecops/binary/dynamic", {"target": str(_sample(tmp_path))})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["executed"] is False and body["runnable"] is False
    assert any("execution is disabled" in reason for reason in body["refusals"])
    assert body["findings"][0]["code"] == "BIN-DYNAMIC-REFUSED"


@pytest.mark.asyncio
async def test_asking_to_execute_without_the_hosts_consent_is_refused_with_every_reason(app_db):
    application, _session, tmp_path = app_db
    resp = await _post(application, "/api/v1/devsecops/binary/dynamic",
                       {"target": str(_sample(tmp_path)), "execute": True})
    assert resp.status_code == 403, resp.text
    detail = resp.json()["detail"]
    assert detail["message"] == "the sample was not executed"
    assert any("execution is disabled" in reason for reason in detail["refusals"])
    assert detail["limits"] and detail["checks"]


@pytest.mark.asyncio
async def test_execution_is_allowed_when_the_host_opts_in_but_the_sample_still_has_to_pass(
        app_db, monkeypatch):
    application, _session, tmp_path = app_db
    sample = _sample(tmp_path)
    monkeypatch.setenv("BINARY_EXECUTION_ENABLED", "true")
    from devsecops import dynamic_scan as dyn

    monkeypatch.setattr(dyn, "dynamic_scan", lambda *a, **kw: _executed_result(_observation("AES-128-CBC")))
    resp = await _post(application, "/api/v1/devsecops/binary/dynamic",
                       {"target": str(sample), "execute": True})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["executed"] is True
    assert body["runtime_ingest"] is None, "nothing is ingested unless submit was asked for"


@pytest.mark.asyncio
async def test_a_sample_the_loader_refuses_is_a_403_not_a_silent_success(app_db, monkeypatch):
    application, _session, tmp_path = app_db
    sample = _sample(tmp_path)
    monkeypatch.setenv("BINARY_EXECUTION_ENABLED", "true")
    from devsecops import dynamic_scan as dyn

    monkeypatch.setattr(dyn, "dynamic_scan", lambda *a, **kw: {
        **_executed_result(), "executed": False, "returncode": None,
        "refusals": ["the sample could not be started: OSError: Exec format error"],
        "findings": [{"code": "BIN-DYNAMIC-REFUSED", "severity": "INFO", "title": "Sample not executed",
                      "detail": "refused", "path": str(sample)}],
    })
    resp = await _post(application, "/api/v1/devsecops/binary/dynamic",
                       {"target": str(sample), "execute": True})
    assert resp.status_code == 403
    assert any("could not be started" in reason for reason in resp.json()["detail"]["refusals"])


@pytest.mark.asyncio
async def test_a_missing_sample_is_a_404_and_a_path_outside_the_roots_is_a_400(app_db):
    application, _session, _tmp_path = app_db
    missing = await _post(application, "/api/v1/devsecops/binary/dynamic",
                          {"target": "/tmp/cryproscan-not-here"})
    assert missing.status_code in (400, 404), missing.text
    outside = await _post(application, "/api/v1/devsecops/binary/dynamic",
                          {"target": str(Path(OPENSSL))})
    assert outside.status_code == 400, outside.text
    assert "outside" in outside.json()["detail"].lower() or "root" in outside.json()["detail"].lower()


@pytest.mark.asyncio
async def test_a_viewer_cannot_run_a_sample(app_db, tmp_path, monkeypatch):
    application, _session, _tmp_path = app_db
    del application
    viewer_app = _viewer_app(tmp_path, monkeypatch)
    resp = await _post(viewer_app, "/api/v1/devsecops/binary/dynamic",
                       {"target": str(_sample(tmp_path))}, token="Bearer viewer-token")
    assert resp.status_code == 403, resp.text
    assert "requires one of roles" in resp.json()["detail"].lower()


# --------------------------------------------------------------------------- #
# observations -> runtime inventory
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_observations_land_in_the_runtime_inventory_with_a_verdict(app_db, monkeypatch):
    application, _session, tmp_path = app_db
    sample = _sample(tmp_path)
    monkeypatch.setenv("BINARY_EXECUTION_ENABLED", "true")
    from devsecops import dynamic_scan as dyn

    monkeypatch.setattr(dyn, "dynamic_scan", lambda *a, **kw: _executed_result(
        _observation("AES-128-CBC", pid=99), _observation("MD5", pid=99, tls=0x0301),
    ))
    resp = await _post(application, "/api/v1/devsecops/binary/dynamic",
                       {"target": str(sample), "execute": True, "submit": True, "hostname": "host-a"})
    assert resp.status_code == 200, resp.text
    ingest = resp.json()["runtime_ingest"]
    assert ingest["accepted"] == 2
    assert ingest["persisted"]["created"] == 2, "two algorithms in one process are two rows"
    assert ingest["anomalies"] == 1, "the TLSv1.0 observation is the anomaly"

    listed = await _get(application, "/api/v1/scans/runtime-findings")
    assert listed.status_code == 200, listed.text
    rows = listed.json()["findings"]
    assert len(rows) == 2
    by_algorithm = {row["algorithm"]: row for row in rows}
    assert by_algorithm["AES"]["status"] == "ALLOWED", "the registry judged the observed cipher"
    assert by_algorithm["MD5"]["status"] == "DISALLOWED"
    assert by_algorithm["MD5"]["weak_tls"] is True, "TLSv1.0 arrived as a name, not as a code"
    assert by_algorithm["MD5"]["tls_version"] == "TLSv1.0"
    assert by_algorithm["AES"]["kind"] == "session"
    assert by_algorithm["AES"]["extra"]["kind"] == "binary-dynamic"
    assert by_algorithm["AES"]["extra"]["target_sha256"] == "c" * 64
    assert by_algorithm["AES"]["extra"]["classification"]["category"] == "symmetric-marginal"


@pytest.mark.asyncio
async def test_nothing_is_ingested_from_a_run_that_did_not_happen(app_db, monkeypatch):
    application, _session, tmp_path = app_db
    monkeypatch.delenv("BINARY_EXECUTION_ENABLED", raising=False)
    resp = await _post(application, "/api/v1/devsecops/binary/dynamic",
                       {"target": str(_sample(tmp_path)), "submit": True})
    assert resp.status_code == 200, resp.text
    assert resp.json()["runtime_ingest"] is None
    listed = await _get(application, "/api/v1/scans/runtime-findings")
    assert listed.json()["total_count"] == 0


@pytest.mark.asyncio
async def test_the_endpoint_is_audited(app_db, monkeypatch):
    application, session, tmp_path = app_db
    monkeypatch.setenv("BINARY_EXECUTION_ENABLED", "true")
    from devsecops import dynamic_scan as dyn

    monkeypatch.setattr(dyn, "dynamic_scan", lambda *a, **kw: _executed_result(_observation("DES")))
    resp = await _post(application, "/api/v1/devsecops/binary/dynamic",
                       {"target": str(_sample(tmp_path)), "execute": True, "submit": True})
    assert resp.status_code == 200, resp.text
    from db.models.user import AuditLog

    rows = [row for row in session.query(AuditLog).all()
            if row.action == "devsecops.binary_dynamic"]
    assert len(rows) == 1
    detail = rows[0].detail
    detail = json.loads(detail) if isinstance(detail, str) else detail
    assert detail["executed"] is True
    assert detail["observations"] == 1
    assert detail["runtime_findings_ingested"] == 1
    assert rows[0].target_id.endswith("sample.elf")
