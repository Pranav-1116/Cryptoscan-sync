"""Real SQLite/file-store/API joins; no claimed registry or runtime observation."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool, StaticPool

from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models import System, SystemDependency
from db.models.software_supply_chain import ReleaseSbomBinding, SoftwareArtifact, SoftwareDeployment

PREFIX = "/api/v1/software-supply-chain"
EVIDENCE = {"assertion_source": "OPERATOR_DECLARED", "evidence_ref": "change/BANK-123"}
DIGEST = "sha256:" + "a" * 64


@pytest.fixture()
def estate(tmp_path, monkeypatch):
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    session.add_all([System(id="pay", name="payments", environment="prod"),
                     System(id="web", name="mobile", environment="prod"), System(id="db", name="ledger", environment="prod")])
    session.flush()
    session.add_all([SystemDependency(parent_id="web", child_id="pay", relation="CALLS"),
                     SystemDependency(parent_id="pay", child_id="db", relation="DEPENDS_ON")])
    session.commit()
    monkeypatch.setenv("SBOM_STORAGE_DIR", str(tmp_path / "sboms"))
    monkeypatch.setenv("CRYPTOSCAN_SOURCE_ROOTS", str(tmp_path))
    import api.routers.devsecops as ds
    monkeypatch.setattr(ds, "_SBOM_STORE", None)
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "operator"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    with TestClient(app, headers={"Authorization": "Bearer test-token"}) as client:
        yield client, session, tmp_path, app
    session.close()
    engine.dispose()


def register(client, digest=DIGEST):
    response = client.post(PREFIX + "/artifacts", json={"digest": digest, **EVIDENCE})
    assert response.status_code == 201, response.text
    return response.json()


def scan(client, tmp_path, fmt="cyclonedx"):
    src = tmp_path / "source"
    src.mkdir(exist_ok=True)
    (src / "requirements.txt").write_text("requests==2.31.0\n")
    response = client.post("/api/v1/devsecops/sbom/scan", json={"kind": "source", "target": str(src), "format": fmt})
    assert response.status_code == 201, response.text
    body = response.json()
    from devsecops.software_identity import sbom_components
    purl = next((row["package_identity"] for row in sbom_components(body["bom"]) if row["package_identity"]), None)
    assert purl
    return body, purl


def attach(client, artifact, sbom):
    response = client.post(PREFIX + f"/artifacts/{artifact['id']}/sboms", json={
        "sbom_artifact_id": sbom["artifact_id"], "expected_sbom_sha256": sbom["manifest"]["sha256"], **EVIDENCE})
    assert response.status_code == 201, response.text
    return response.json()


def deploy(client, artifact, **extra):
    return client.post(PREFIX + f"/artifacts/{artifact['id']}/deployments", json={
        "system_id": "pay", "environment": "prod", "deployment_key": "cluster/payments/revision-17", **EVIDENCE, **extra})


def cascade(client, target, **params):
    response = client.post("/api/v1/technology-bom/cascade", json={"target": target, "kind": "package"}, params=params)
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.parametrize("fmt", ["cyclonedx", "spdx"])
def test_real_source_sbom_to_digest_to_application_and_consumers(estate, fmt):
    client, session, tmp_path, _app = estate
    sbom, purl = scan(client, tmp_path, fmt)
    assert cascade(client, purl)["verdict"] == "NOT_FOUND"  # no auto-adoption
    artifact = register(client)
    binding = attach(client, artifact, sbom)
    assert binding["sbom_sha256"] != artifact["digest"].split(":")[1]
    assert cascade(client, purl)["verdict"] == "INSUFFICIENT_DATA"
    assert deploy(client, artifact).status_code == 201
    result = cascade(client, purl)
    assert result["impact"]["system_classification"]["direct_exposure"]["systems"] == ["pay"]
    assert result["impact"]["system_classification"]["dependent_consumers"]["systems"] == ["web"]
    assert result["impact"]["system_classification"]["supporting_context"]["systems"] == ["db"]
    assert result["layers"]["software"]["artifacts"][0]["identity_source"] == "OPERATOR_DECLARED"
    assert result["layers"]["software"]["sbom_bindings"][0]["evidence_ref"] == EVIDENCE["evidence_ref"]
    stored = client.get(f"/api/v1/technology-bom/cascade/runs/{result['run_id']}").json()["result"]
    assert stored["layers"]["software"] == result["layers"]["software"]
    assert session.query(SoftwareDeployment).count() == 1


def test_measurement_hashes_actual_bytes_not_filename_or_sbom_document(estate):
    client, _session, _tmp, _app = estate
    payload = b"bank immutable release bytes\x00\xff"
    response = client.post(PREFIX + "/artifacts/measure", params={"evidence_ref": "build/release-17"},
                           content=payload, headers={"Content-Type": "application/octet-stream"})
    assert response.status_code == 201, response.text
    artifact = response.json()
    assert artifact["digest"] == "sha256:" + hashlib.sha256(payload).hexdigest()
    assert artifact["byte_count"] == len(payload) and artifact["identity_source"] == "CONTENT_HASHED"
    assert client.get(PREFIX + f"/artifacts/{artifact['id']}").json()["deployments"] == []


@pytest.mark.parametrize("digest", ["registry/pay:latest", "/var/releases/pay", "a" * 64, "sha256:wrong"])
def test_nonimmutable_artifact_identifiers_are_rejected(estate, digest):
    client, session, *_ = estate
    response = client.post(PREFIX + "/artifacts", json={"digest": digest, **EVIDENCE})
    assert response.status_code == 422
    assert session.query(SoftwareArtifact).count() == 0


def test_idempotence_and_conflicts_never_overwrite_identity_or_deployment(estate):
    client, session, tmp_path, _app = estate
    first = register(client)
    assert register(client)["id"] == first["id"]
    conflicting = client.post(PREFIX + "/artifacts", json={"digest": DIGEST, **EVIDENCE, "evidence_ref": "different"})
    assert conflicting.status_code == 409
    sbom, _purl = scan(client, tmp_path)
    one = attach(client, first, sbom)
    assert attach(client, first, sbom)["id"] == one["id"]
    d1 = deploy(client, first)
    assert d1.status_code == 201 and deploy(client, first).json()["id"] == d1.json()["id"]
    second = register(client, "sha256:" + "b" * 64)
    assert deploy(client, second).status_code == 409
    assert deploy(client, first, environment="staging", deployment_key="another").status_code == 409
    assert deploy(client, first, system_id="payments", deployment_key="another").status_code == 404  # ID, not name
    assert session.query(SoftwareDeployment).count() == 1
    assert session.query(SoftwareArtifact).filter_by(id=first["id"]).one().digest == DIGEST


def test_sbom_tamper_and_wrong_expected_digest_are_refused(estate):
    client, session, tmp_path, _app = estate
    artifact = register(client)
    sbom, _purl = scan(client, tmp_path)
    endpoint = PREFIX + f"/artifacts/{artifact['id']}/sboms"
    body = {"sbom_artifact_id": sbom["artifact_id"], "expected_sbom_sha256": "0" * 64, **EVIDENCE}
    assert client.post(endpoint, json=body).status_code == 409
    from api.routers.devsecops import _sbom_storage
    # A legacy normalized platform bucket must not override a raw foreign
    # tenant stamp, even when the physical file hash is otherwise correct.
    _sbom_storage().put_manifest(sbom["manifest"]["storage_key"],
                                {**sbom["manifest"], "tenant_id": "foreign-bank"})
    body["expected_sbom_sha256"] = sbom["manifest"]["sha256"]
    assert client.post(endpoint, json=body).status_code == 404
    _sbom_storage().put_manifest(sbom["manifest"]["storage_key"], sbom["manifest"])
    _sbom_storage().put(sbom["manifest"]["storage_key"], b'{"tampered":true}')
    body["expected_sbom_sha256"] = sbom["manifest"]["sha256"]
    assert client.post(endpoint, json=body).status_code == 409
    assert session.query(ReleaseSbomBinding).count() == 0


def test_capture_replay_remains_unbound_after_later_live_deployment(estate):
    client, _session, tmp_path, _app = estate
    sbom, purl = scan(client, tmp_path)
    artifact = register(client)
    attach(client, artifact, sbom)
    cap = client.post("/api/v1/digital-twin/snapshot")
    assert cap.status_code == 200, cap.text
    version = cap.json()["version"]
    assert deploy(client, artifact).status_code == 201
    assert cascade(client, purl)["verdict"] == "AFFECTED"
    replay = cascade(client, purl, version=version)
    assert replay["verdict"] == "INSUFFICIENT_DATA"
    assert replay["layers"]["software"]["deployments"] == []
    assert replay["replayed_over"]["twin_snapshot_version"] == version


def test_readonly_can_inspect_but_cannot_register_or_deploy(estate, monkeypatch):
    client, _session, *_ = estate
    artifact = register(client)
    import api.dependencies as deps
    monkeypatch.setattr(deps, "_user_roles", lambda *_: ["readonly"])
    assert client.get(PREFIX + "/artifacts").status_code == 200
    assert client.post(PREFIX + "/artifacts", json={"digest": DIGEST, **EVIDENCE}).status_code == 403
    assert deploy(client, artifact).status_code == 403
    assert client.post(PREFIX + "/artifacts/measure", params={"evidence_ref": "build/1"}, content=b"x").status_code == 403


def test_measurement_limits_and_no_fake_observed_provenance(estate, monkeypatch):
    client, session, *_ = estate
    import api.routers.software_supply_chain as supply
    monkeypatch.setattr(supply, "MAX_ARTIFACT_BYTES", 4)
    assert client.post(PREFIX + "/artifacts/measure", params={"evidence_ref": "build/1"},
                       content=b"12345", headers={"Content-Type": "application/octet-stream"}).status_code == 413
    assert client.post(PREFIX + "/artifacts/measure", params={"evidence_ref": "build/1"},
                       content=b"", headers={"Content-Type": "application/octet-stream"}).status_code == 422
    assert client.post(PREFIX + "/artifacts", json={"digest": DIGEST, **EVIDENCE,
                                                  "assertion_source": "OBSERVED"}).status_code == 422
    assert session.query(SoftwareArtifact).count() == 0


@pytest.fixture()
def banks(tmp_path, monkeypatch):
    """Actual session auth + tenant middleware, not a forged tenant dependency."""
    from api.middleware.tenant_scope import TenantScopeMiddleware
    from api.security.passwords import hash_password
    from api.security.session_manager import SessionManager
    from db.connection.session import configure_session, SessionLocal
    from db.models.tenant import Tenant, TenantMembership
    from db.repositories.user_repository import UserRepository

    previous = SessionLocal.kw.get("bind")
    # WebSocket rechecks execute in other threads. In-memory StaticPool shares
    # ONE SQLite connection across the mutating test thread and socket reader,
    # so a commit can race with a borrowed transaction and expose stale state.
    # File-backed SQLite gives each thread its own real connection and
    # transaction; WAL permits revocation writes during socket reads.
    engine = create_engine(
        f"sqlite:///{tmp_path / 'tenant-banks.db'}",
        connect_args={"check_same_thread": False, "timeout": 10},
        poolclass=NullPool)
    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA journal_mode=WAL")
        connection.commit()
    Base.metadata.create_all(engine)
    configure_session(engine)
    session = SessionLocal()
    users = UserRepository(session)
    for name, roles in [("bank_a", ["security_analyst"]), ("bank_b", ["security_analyst"]),
                        ("reader_a", ["readonly"]), ("platform_admin", ["superadmin"])]:
        users.create_user(name, hash_password("unused-test-password"), roles)
    for key in ("a", "b"):
        session.add(Tenant(id=key, name="Bank " + key, slug="bank-" + key))
        session.add(TenantMembership(tenant_id=key, username="bank_" + key, tenant_role="member"))
        session.add(System(id="system-" + key, tenant_id=key, name="Core " + key, environment="prod"))
    session.add(TenantMembership(tenant_id="a", username="reader_a", tenant_role="member"))
    session.add(System(id="platform-system", name="Platform", environment="prod"))
    session.commit()
    monkeypatch.setenv("SBOM_STORAGE_DIR", str(tmp_path / "sboms"))
    monkeypatch.setenv("CRYPTOSCAN_SOURCE_ROOTS", str(tmp_path))
    import api.routers.devsecops as ds
    monkeypatch.setattr(ds, "_SBOM_STORE", None)
    app = create_app()
    app.add_middleware(TenantScopeMiddleware)
    clients = {}
    for username in ("bank_a", "bank_b", "reader_a", "platform_admin"):
        token = SessionManager().create_session(username, roles=[])
        users.create_session(token, username, datetime.now(timezone.utc) + timedelta(hours=1), ip="127.0.0.1")
        session.commit()
        client = TestClient(app)
        client.cookies.set("cryptoscan_session", token)
        clients[username] = client
    try:
        yield clients, session, tmp_path
    finally:
        for client in clients.values():
            client.close()
        session.close()
        SessionLocal.configure(bind=previous)
        engine.dispose()


def test_actual_tenant_auth_denies_foreign_platform_and_forged_join_ids(banks):
    clients, session, tmp_path = banks
    a, b, platform = clients["bank_a"], clients["bank_b"], clients["platform_admin"]
    aa, bb, pp = register(a), register(b), register(platform)
    assert len({aa["id"], bb["id"], pp["id"]}) == 3  # same digest, separate estates
    assert a.get(PREFIX + f"/artifacts/{bb['id']}").status_code == 404
    assert a.get(PREFIX + f"/artifacts/{pp['id']}").status_code == 404
    assert platform.get(PREFIX + f"/artifacts/{aa['id']}").status_code == 404
    assert deploy(a, aa, system_id="system-b").status_code == 404
    assert deploy(a, aa, system_id="platform-system").status_code == 404
    assert deploy(a, bb, system_id="system-a").status_code == 404
    forged = a.get(PREFIX + "/artifacts", headers={"X-Tenant-ID": "b"})
    assert forged.status_code in (403, 404)
    asbom, purl = scan(a, tmp_path)
    bsbo, _ = scan(b, tmp_path)
    assert asbom["manifest"]["tenant_id"] == "a"
    denied = a.post(PREFIX + f"/artifacts/{aa['id']}/sboms", json={
        "sbom_artifact_id": bsbo["artifact_id"], "expected_sbom_sha256": bsbo["manifest"]["sha256"], **EVIDENCE})
    assert denied.status_code == 404
    attach(a, aa, asbom)
    attach(b, bb, bsbo)
    assert deploy(a, aa, system_id="system-a").status_code == 201
    assert deploy(b, bb, system_id="system-b").status_code == 201
    result = cascade(a, purl)
    assert result["impact"]["affected_systems"] == ["system-a"]
    assert result["layers"]["software"]["artifacts"][0]["id"] == aa["id"]
    assert bb["id"] not in json.dumps(result) and pp["id"] not in json.dumps(result)
    listed = platform.get(PREFIX + "/artifacts").json()["artifacts"]
    assert [row["id"] for row in listed] == [pp["id"]]
    reader = clients["reader_a"]
    assert reader.get(PREFIX + f"/artifacts/{aa['id']}").status_code == 200
    assert deploy(reader, aa, system_id="system-a").status_code == 403
    assert session.query(SoftwareDeployment).count() == 2


def test_snapshot_component_budget_reports_missing_coverage(estate, monkeypatch):
    from api import software_supply_chain as projection
    client, _session, tmp_path, _ = estate
    sbom, purl = scan(client, tmp_path)
    attach(client, register(client), sbom)
    monkeypatch.setattr(projection, "COMPONENT_CAP", 0)
    capture = client.post("/api/v1/digital-twin/snapshot").json()
    stored = client.get(f"/api/v1/digital-twin/snapshots/{capture['version']}").json()
    # Inspect actual capture shape; the result must advertise the zero budget.
    state = stored.get("state") or stored.get("snapshot")
    assert state["software_supply_chain_coverage"]["truncated"] is True
    assert state["software_supply_chain_coverage"]["collections"]["components"]["returned"] == 0
    assert state["software_sbom_bindings"] == []
    assert state["source_coverage"]["schema"] == "cryptoscan.source-coverage/1"
    components = state["software_supply_chain_coverage"]["collections"]["components"]
    assert components["limit"] == 0 and components["unit"] == "components"
    assert components["known_total"] > 0


def test_external_supplier_sbom_persists_in_existing_store_but_does_not_deploy(estate):
    client, _session, _tmp, _app = estate
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
        {"bom-ref": "crypto-ref", "type": "library", "name": "cryptography", "version": "42.0.0", "purl": "pkg:pypi/cryptography@42.0.0"}]}
    response = client.post(PREFIX + "/sboms", json={"doc": doc, "assertion_source": "SUPPLIER_DECLARED", "evidence_ref": "supplier/release-17"})
    assert response.status_code == 201, response.text
    stored = response.json()
    download = client.get(f"/api/v1/devsecops/sbom/{stored['artifact_id']}/download")
    assert download.status_code == 200
    assert hashlib.sha256(download.content).hexdigest() == stored["manifest"]["sha256"]
    purl = "pkg:pypi/cryptography@42.0.0"
    assert cascade(client, purl)["verdict"] == "NOT_FOUND"
    artifact = register(client)
    binding = attach(client, artifact, stored)
    assert binding["components"][0]["bom_ref"] == "crypto-ref"
    assert cascade(client, purl)["verdict"] == "INSUFFICIENT_DATA"
    assert deploy(client, artifact).status_code == 201
    assert cascade(client, purl)["verdict"] == "AFFECTED"


def test_sbom_component_bounds_refuse_partial_binding(estate, monkeypatch):
    client, session, *_ = estate
    import devsecops.software_identity as identity
    monkeypatch.setattr(identity, "MAX_COMPONENTS", 1)
    doc = {"bomFormat": "CycloneDX", "components": [{"name": "a"}, {"name": "b"}]}
    response = client.post(PREFIX + "/sboms", json={"doc": doc, **EVIDENCE})
    assert response.status_code == 422
    assert session.query(ReleaseSbomBinding).count() == 0


def test_declarations_cannot_silently_become_server_measured_identity(estate):
    client, session, *_ = estate
    payload = b"release bytes"
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    original = register(client, digest)
    measured = client.post(PREFIX + "/artifacts/measure", params={"evidence_ref": EVIDENCE["evidence_ref"]},
                           content=payload, headers={"Content-Type": "application/octet-stream"})
    assert measured.status_code == 409
    assert session.query(SoftwareArtifact).filter_by(id=original["id"]).one().identity_source == "OPERATOR_DECLARED"


def test_binding_reuses_pinned_components_without_requiring_live_artifact_store(estate):
    client, _session, tmp_path, _ = estate
    sbom, purl = scan(client, tmp_path)
    artifact = register(client)
    attach(client, artifact, sbom)
    assert deploy(client, artifact).status_code == 201
    from api.routers.devsecops import _sbom_storage
    _sbom_storage().delete(sbom["manifest"]["storage_key"])
    # Archived bindings are DB read models, not a fresh validation of that file.
    result = cascade(client, purl)
    assert result["verdict"] == "AFFECTED"
    assert result["layers"]["software"]["sbom_bindings"][0]["sbom_sha256"] == sbom["manifest"]["sha256"]


def test_reused_sbom_id_cannot_mask_new_document_content_for_another_release(estate):
    client, session, tmp_path, _ = estate
    sbom, _purl = scan(client, tmp_path)
    attach(client, register(client), sbom)
    other = register(client, "sha256:" + "b" * 64)
    from api.routers.devsecops import _sbom_storage
    changed = b'{"bomFormat":"CycloneDX","components":[]}'
    manifest = dict(sbom["manifest"], sha256=hashlib.sha256(changed).hexdigest())
    _sbom_storage().put(manifest["storage_key"], changed)
    _sbom_storage().put_manifest(manifest["storage_key"], manifest)
    response = client.post(PREFIX + f"/artifacts/{other['id']}/sboms", json={
        "sbom_artifact_id": sbom["artifact_id"], "expected_sbom_sha256": manifest["sha256"], **EVIDENCE})
    assert response.status_code == 409
    assert session.query(ReleaseSbomBinding).count() == 1


def test_new_identity_routes_require_credentials_even_with_test_user_override(estate):
    client, session, *_ = estate
    response = client.post(PREFIX + "/artifacts", json={"digest": DIGEST, **EVIDENCE}, headers={"Authorization": ""})
    assert response.status_code == 401
    assert session.query(SoftwareArtifact).count() == 0


def test_inspection_policy_matches_existing_twin_cascade_but_developers_cannot_write(estate, monkeypatch):
    client, _session, tmp_path, _ = estate
    sbom, purl = scan(client, tmp_path)
    artifact = register(client)
    attach(client, artifact, sbom)
    assert deploy(client, artifact).status_code == 201
    import api.dependencies as deps
    monkeypatch.setattr(deps, "_user_roles", lambda *_: ["developer"])
    assert client.get(PREFIX + f"/artifacts/{artifact['id']}").status_code == 200
    assert cascade(client, purl)["verdict"] == "AFFECTED"
    assert deploy(client, artifact, deployment_key="other-revision").status_code == 403
