"""POST /estate/evidence/collect — collectors run, the six BOMs re-project.

The point of the endpoint is that a collector *run* reaches the evidence graph, so
these tests assert the whole chain: run → merged observation → projections → measured
BOM depth, plus the refusals that keep an empty input from reading as an empty estate.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from api.security.session_manager import SessionManager
from db.models.base import Base


@pytest.fixture
def api(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "tester"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    # require_roles() reads the roles of the real signed token, so the client carries one
    token = SessionManager().create_session("tester", roles=["admin"])
    try:
        yield TestClient(app, headers={"Authorization": f"Bearer {token}"}), session
    finally:
        session.close()
        engine.dispose()
        app.dependency_overrides.clear()


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _proc_tree(base: Path) -> Path:
    _write(base / "101" / "comm", "nginx\n")
    _write(base / "101" / "cmdline", "nginx: master process\x00")
    _write(base / "101" / "maps",
           "7f0000000000-7f0000010000 r--p 00000000 08:01 100 /usr/lib/libcrypto.so.3\n")
    return base


def _windows_artifacts(base: Path) -> list[str]:
    reg = base / "schannel.reg"
    _write(reg,
           "Windows Registry Editor Version 5.00\n\n"
           "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders"
           "\\SCHANNEL\\Protocols\\TLS 1.0\\Server]\n"
           '"Enabled"=dword:00000000\n')
    suites = base / "suites.json"
    _write(suites, '[{"Name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"}]')
    return [str(reg), str(suites)]


def test_capabilities_say_which_collector_can_run(api):
    client, _ = api
    response = client.get("/api/v1/estate/evidence/collect/capabilities")
    assert response.status_code == 200, response.text
    body = response.json()
    by_id = {row["id"]: row for row in body["collectors"]}
    assert set(by_id) == {"runtime", "network", "windows"}
    assert by_id["runtime"]["state"] in {"AVAILABLE", "UNAVAILABLE"}
    # with no stored observation the target estate is stated, not assumed
    assert body["target_estate"]["state"] == "NO_OBSERVATION"


def test_collect_windows_artefacts_creates_an_estate_and_measures_its_depth(api, tmp_path):
    client, _ = api
    response = client.post("/api/v1/estate/evidence/collect", json={
        "collectors": ["windows"],
        "artifacts": _windows_artifacts(tmp_path),
        "windows_host": "win-bank-01",
        "estate": "windows-collect",
        "merge": False,
    })
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["estate"] == "windows-collect"
    # one host asset carries the policy: a suite list does not invent endpoint assets
    assert body["counts"]["assets"] == 1
    assert body["collectors"][0]["id"] == "windows"
    assert body["collectors"][0]["protocols"] == 1
    # the BOMs were projected from the collection and their depth was measured
    assert body["bom_maturity"]["after"]["CBOM"] in {"CONFIGURED", "OBSERVED"}
    assert body["bom_maturity"]["after"]["VBOM"] == "EMPTY"
    assert body["run_id"]

    # and the estate now answers the BOM routes from the stored observation
    boms = client.get("/api/v1/estate/evidence/boms?bom=CBOM")
    assert boms.status_code == 200
    components = boms.json()["components"]
    assert components, "the projected CBOM must hold what was collected"
    assert {row["algorithm"] for row in components} >= {"AES-256-GCM"}
    assert all(row["usage_state"] == "CONFIGURED" for row in components)


def test_runtime_collect_merges_into_the_stored_estate(api, tmp_path):
    client, _ = api
    proc = _proc_tree(tmp_path / "proc")
    first = client.post("/api/v1/estate/evidence/collect", json={
        "collectors": ["runtime"], "proc_base": str(proc), "estate": "host-01", "merge": False,
    })
    assert first.status_code == 200, first.text

    second = client.post("/api/v1/estate/evidence/collect", json={
        "collectors": ["runtime"], "proc_base": str(proc), "merge": True,
    })
    assert second.status_code == 200, second.text
    body = second.json()
    assert body["merged_into_stored_observation"] is True
    assert body["estate"] == "host-01"
    # the same host and library are not duplicated by a second run
    assert body["counts"]["assets"] == first.json()["counts"]["assets"]
    # SBOM gained a library backed by a runtime observation
    assert body["bom_maturity"]["after"]["SBOM"] in {"OBSERVED", "CONFIGURED"}


def test_network_without_targets_is_refused_rather_than_collected_empty(api):
    client, _ = api
    response = client.post("/api/v1/estate/evidence/collect", json={"collectors": ["network"]})
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail["error"] == "no_targets"
    assert "no endpoints" in detail["reason"]


def test_windows_without_artifacts_is_refused(api):
    client, _ = api
    response = client.post("/api/v1/estate/evidence/collect", json={"collectors": ["windows"]})
    assert response.status_code == 422
    assert response.json()["detail"]["error"] == "no_artifacts"


def test_unknown_collector_is_named(api):
    client, _ = api
    response = client.post("/api/v1/estate/evidence/collect", json={"collectors": ["eBPF"]})
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail["error"] == "unknown_collector"
    assert "eBPF" in detail["reason"]


def test_runtime_depth_route_counts_estate_evidence(api, tmp_path):
    client, _ = api
    proc = _proc_tree(tmp_path / "proc")
    assert client.post("/api/v1/estate/evidence/collect", json={
        "collectors": ["runtime"], "proc_base": str(proc), "estate": "host-01", "merge": False,
    }).status_code == 200

    matrix = client.get("/api/v1/estate/evidence/discovery/runtime-depth").json()
    estate = matrix["observed"]["estate"]
    assert estate is not None
    assert estate["process_library_evidence"] >= 1
    # a mapped library is not an invocation
    assert estate["invocation_evidence"] == 0
    by_id = {row["id"]: row for row in matrix["paths"]}
    assert by_id["jvm"]["depth"] == "PROCESS_LIBRARY"
    assert by_id["openssl_native"]["depth"] == "INVOCATION"


def test_windows_matrix_names_the_offline_parser_as_a_producer(api):
    client, _ = api
    body = client.get("/api/v1/estate/evidence/discovery/windows-collector").json()
    layer = next(row for row in body["layers"] if row["id"] == "schannel_policy")
    refs = {row["ref"] for row in layer["producers"]}
    assert "api.windows_artifacts:parse_schannel_registry" in refs
    assert all(row["present"] for row in layer["producers"])
