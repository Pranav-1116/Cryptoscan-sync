"""API surface for distribution-model obligations and deployment correlation."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base


@pytest.fixture()
def client(tmp_path, monkeypatch):
    engine = create_engine("sqlite:///:memory:",
                           connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()
    application = create_app()
    application.dependency_overrides[get_current_user] = lambda: "operator"
    monkeypatch.setenv("SBOM_STORAGE_DIR", str(tmp_path / "sboms"))

    def _session():
        yield session

    application.dependency_overrides[get_db_session] = _session
    yield application
    application.dependency_overrides.clear()


def _bom(components):
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": components}


def _mit(name="requests"):
    return {"name": name, "version": "2.31.0",
            "licenses": [{"license": {"id": "MIT"}}]}


def _gpl(name="busybox"):
    return {"name": name, "version": "1.36.1",
            "licenses": [{"license": {"id": "GPL-3.0-only"}}]}


def _post(client, path, body):
    async def go():
        async with ASGITransport(app=client) as transport:
            async with AsyncClient(transport=transport, base_url="http://test") as http:
                return await http.post(f"/api/v1/devsecops{path}", json=body,
                                       headers={"Authorization": "Bearer test-token"})
    import asyncio
    return asyncio.run(go())


def test_obligations_differ_by_distribution_model(client):
    doc = _bom([_mit(), _gpl()])
    internal = _post(client, "/sbom/obligations",
                     {"doc": doc, "distribution_model": "INTERNAL"}).json()
    shipped = _post(client, "/sbom/obligations",
                    {"doc": doc, "distribution_model": "BINARY_SHIPPED"}).json()
    assert "SOURCE_DISCLOSURE" not in internal["counts"]
    assert shipped["counts"]["SOURCE_DISCLOSURE"] == 1
    assert shipped["counts"]["ATTRIBUTION"] == 2


def test_obligations_never_report_compliance(client):
    body = _post(client, "/sbom/obligations",
                 {"doc": _bom([_mit()]), "distribution_model": "INTERNAL"}).json()
    assert body["verdict"] in {"NO_ACTION", "REVIEW", "NEEDS_LEGAL"}
    assert "legal opinion" in body["statement"]


def test_an_unidentified_licence_needs_legal(client):
    body = _post(client, "/sbom/obligations",
                 {"doc": _bom([{"name": "mystery", "version": "1.0"}]),
                  "distribution_model": "BINARY_SHIPPED"}).json()
    assert body["unknown_components"] == ["mystery"]
    assert body["verdict"] == "NEEDS_LEGAL"


def test_modification_is_scoped_to_the_named_components(client):
    doc = _bom([_gpl("busybox"), _gpl("tar")])
    body = _post(client, "/sbom/obligations",
                 {"doc": doc, "distribution_model": "BINARY_SHIPPED",
                  "modified": ["busybox"]}).json()
    rows = {row["component"]: row for row in body["components"]}
    assert "MODIFICATION_DISCLOSURE" in rows["busybox"]["open"]
    assert "MODIFICATION_DISCLOSURE" not in rows["tar"]["open"]


def test_an_unknown_distribution_model_is_a_validation_error(client):
    resp = _post(client, "/sbom/obligations",
                 {"doc": _bom([_mit()]), "distribution_model": "PILOT"})
    assert resp.status_code == 422
    assert "distribution model" in resp.json()["detail"]


def test_obligations_render_as_markdown(client):
    body = _post(client, "/sbom/obligations",
                 {"doc": _bom([_gpl()]), "distribution_model": "BINARY_SHIPPED",
                  "fmt": "markdown"}).json()
    assert body["markdown"].startswith("# Licence obligations — BINARY_SHIPPED")
    assert "Offer the corresponding source" in body["markdown"]


def test_obligations_require_one_source_document(client):
    assert _post(client, "/sbom/obligations", {"distribution_model": "INTERNAL"}).status_code == 422


def _pod(name="api-1", image="ghcr.io/bank/api:2026.11.02", digest="sha256:" + "a" * 64):
    return {"kind": "Pod", "metadata": {"namespace": "payments", "name": name},
            "spec": {"containers": [{"name": "api", "image": image}]},
            "status": {"containerStatuses": [{"name": "api",
                                              "imageID": f"docker-pullable://{image.split(':')[0]}@{digest}",
                                              "state": {"running": {}}}]}}


def test_deployments_collects_observations_from_a_pod_listing(client):
    body = _post(client, "/sbom/deployments",
                 {"pods": {"items": [_pod()]}, "observed_at": "2026-11-02",
                  "environment": "production"}).json()
    assert len(body["collection"]["observations"]) == 1
    assert body["collection"]["observations"][0]["artifact"]["digest"] == "sha256:" + "a" * 64


def test_deployments_refuses_a_tag_only_image_without_failing_the_request(client):
    pod = _pod(image="ghcr.io/bank/api:latest")
    pod["status"]["containerStatuses"][0]["imageID"] = "docker-pullable://ghcr.io/bank/api:latest"
    body = _post(client, "/sbom/deployments", {"pods": {"items": [pod]}}).json()
    assert body["collection"]["observations"] == []
    assert body["collection"]["refused"]


def test_deployments_correlates_a_bound_sbom(client):
    body = _post(client, "/sbom/deployments", {
        "pods": {"items": [_pod()]},
        "doc": _bom([{"name": "openssl", "version": "3.0.13"}]),
        "image_reference": "ghcr.io/bank/api", "image_digest": "sha256:" + "a" * 64,
        "cmdb": {"applications": [{"name": "payments-api", "business_system": "Cards",
                                       "workloads": ["pod/payments/api-1"]}]},
    }).json()
    row = body["correlation"]["rows"][0]
    assert row["state"] == "PRESENT_IN_DEPLOYMENT"
    assert row["business_systems"] == ["Cards"]


def test_deployments_without_an_image_digest_stays_at_the_document(client):
    body = _post(client, "/sbom/deployments", {
        "pods": {"items": [_pod()]},
        "doc": _bom([{"name": "openssl", "version": "3.0.13"}]),
    }).json()
    assert body["correlation"]["rows"][0]["state"] == "PRESENT_IN_SBOM_ONLY"


def test_deployments_needs_a_source(client):
    resp = _post(client, "/sbom/deployments", {"cmdb": {"applications": []}})
    assert resp.status_code == 422
