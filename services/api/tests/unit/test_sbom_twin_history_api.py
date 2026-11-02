"""The SBOM's two new read surfaces: the twin edges and the stored history."""

from __future__ import annotations

import json

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base

DIGEST = "sha256:" + "a" * 64
REFERENCE = "ghcr.io/bank/payments-api"


@pytest.fixture()
def app_db(tmp_path, monkeypatch):
    engine = create_engine("sqlite:///:memory:",
                           connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()
    application = create_app()
    application.dependency_overrides[get_current_user] = lambda: "operator"
    monkeypatch.setenv("SBOM_STORAGE_DIR", str(tmp_path / "sboms"))
    monkeypatch.setenv("CRYPTOSCAN_SOURCE_ROOTS", str(tmp_path))
    import api.routers.devsecops as ds

    monkeypatch.setattr(ds, "_SBOM_STORE", None)

    def _session():
        yield session

    application.dependency_overrides[get_db_session] = _session
    yield application, tmp_path
    application.dependency_overrides.clear()


def _run(application, method, path, *, json_body=None):
    import asyncio

    async def go():
        async with ASGITransport(app=application) as transport:
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                return await client.request(method, f"/api/v1/devsecops{path}", json=json_body,
                                            headers={"Authorization": "Bearer test-token"})

    return asyncio.run(go())


def _scan(application, tmp_path, requirements, *, name="app"):
    src = tmp_path / name
    src.mkdir(parents=True, exist_ok=True)
    (src / "requirements.txt").write_text(requirements)
    resp = _run(application, "POST", "/sbom/scan",
                json_body={"kind": "source", "target": str(src), "format": "cyclonedx"})
    assert resp.status_code == 201, resp.text
    return resp.json()["artifact_id"]


def _observation():
    return {"deployment": "payments/api-1", "environment": "PRODUCTION",
            "artifact": {"reference": REFERENCE, "digest": DIGEST},
            "workload": "payments/api-1", "observed_at": "2026-11-02",
            "evidence_id": "K8S-1", "source": "k8s"}


# --------------------------------------------------------------------------- #
# twin


def test_twin_writes_declared_edges_for_a_stored_sbom(app_db):
    application, tmp_path = app_db
    artifact_id = _scan(application, tmp_path, "openssl==3.0.13\n")
    body = _run(application, "POST", f"/sbom/{artifact_id}/twin").json()
    assert body["applied"]["written"] == len(body["edges"]["edges"]) >= 2
    assert "OBSERVED" not in body["applied"]["by_provenance"]
    assert body["applied"]["refused"] == []
    assert body["graph"]["edges"]


def test_twin_without_a_digest_reaches_no_deployment(app_db):
    application, tmp_path = app_db
    artifact_id = _scan(application, tmp_path, "openssl==3.0.13\n")
    body = _run(application, "POST", f"/sbom/{artifact_id}/twin",
                json_body={"observations": [_observation()]}).json()
    assert "OBSERVED" not in body["applied"]["by_provenance"]
    assert "no observation reaches this artifact" in body["edges"]["statement"]


def test_twin_with_a_digest_and_an_observation_is_observed(app_db):
    application, tmp_path = app_db
    artifact_id = _scan(application, tmp_path, "openssl==3.0.13\n")
    body = _run(application, "POST", f"/sbom/{artifact_id}/twin",
                json_body={"image_reference": REFERENCE, "image_digest": DIGEST,
                           "application": "application:payments-api",
                           "business_system": "business:cards",
                           "observations": [_observation()]}).json()
    assert body["applied"]["by_provenance"]["OBSERVED"] == 2  # DEPLOYED_AS + RUNS_AS
    assert body["applied"]["by_provenance"]["DECLARED"] >= 2
    relationships = {edge["label"] for edge in body["graph"]["edges"]}
    assert {"DEPLOYED_AS", "RUNS_AS"} <= relationships


def test_twin_capabilities_are_inferred_not_observed(app_db):
    application, tmp_path = app_db
    artifact_id = _scan(application, tmp_path, "cryptography==42.0.0\n")
    body = _run(application, "POST", f"/sbom/{artifact_id}/twin",
                json_body={"algorithms": {"cryptography": ["AES-256-GCM"]}}).json()
    assert body["applied"]["by_provenance"]["INFERRED"] == 1


def test_twin_refuses_a_bad_digest(app_db):
    application, tmp_path = app_db
    artifact_id = _scan(application, tmp_path, "openssl==3.0.13\n")
    resp = _run(application, "POST", f"/sbom/{artifact_id}/twin",
                json_body={"image_reference": REFERENCE, "image_digest": "latest"})
    assert resp.status_code == 422


def test_twin_refuses_an_observation_without_a_digest(app_db):
    application, tmp_path = app_db
    artifact_id = _scan(application, tmp_path, "openssl==3.0.13\n")
    broken = {**_observation(), "artifact": {"reference": REFERENCE}}
    resp = _run(application, "POST", f"/sbom/{artifact_id}/twin",
                json_body={"observations": [broken]})
    assert resp.status_code == 422


def test_twin_of_an_unknown_artifact_is_404(app_db):
    application, _tmp_path = app_db
    resp = _run(application, "POST", "/sbom/nope/twin")
    assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# history


def test_history_of_two_scans_is_a_timeline(app_db):
    application, tmp_path = app_db
    first = _scan(application, tmp_path, "openssl==3.0.13\ncurl==8.5.0\n", name="app")
    second = _scan(application, tmp_path, "openssl==3.0.14\n", name="app")
    body = _run(application, "GET", f"/sbom/{second}/history").json()
    assert body["schema"] == "cryptoscan.sbom-timeline/1"
    assert body["snapshots"] == [first, second]
    assert body["changed_transitions"] == 1
    assert "VERSION_CHANGED" in body["event_counts"]
    event = next(row for row in body["events"] if row["type"] == "VERSION_CHANGED")
    assert (event["from"], event["to"]) == ("3.0.13", "3.0.14")
    assert (event["from_sbom"], event["to_sbom"]) == (first, second)


def test_history_of_one_scan_says_drift_is_unmeasured(app_db):
    application, tmp_path = app_db
    artifact_id = _scan(application, tmp_path, "openssl==3.0.13\n")
    body = _run(application, "GET", f"/sbom/{artifact_id}/history").json()
    assert body["snapshots"] == [artifact_id]
    assert body["events"] == []
    assert "drift is unmeasured" in body["statement"]
    assert "no change" not in body["statement"]


def test_history_keeps_the_schema_key(app_db):
    application, tmp_path = app_db
    artifact_id = _scan(application, tmp_path, "openssl==3.0.13\n")
    raw = _run(application, "GET", f"/sbom/{artifact_id}/history")
    assert "schema" in json.loads(raw.text)
    assert "schema_" not in json.loads(raw.text)


def test_history_of_an_unknown_artifact_is_404(app_db):
    application, _tmp_path = app_db
    assert _run(application, "GET", "/sbom/nope/history").status_code == 404
