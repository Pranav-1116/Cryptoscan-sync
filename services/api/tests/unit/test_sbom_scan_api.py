"""E2E SBOM scanner API: scan source tree -> persist hash-signed artifact ->
list + download with sha256 provenance, role gating, and target validation."""

from __future__ import annotations

import hashlib
import json

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base


@pytest.fixture()
def app_db(tmp_path, monkeypatch):
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()

    application = create_app()
    application.dependency_overrides[get_current_user] = lambda: "operator"
    # artifacts live in a per-test dir, not the production volume; the tmp tree
    # must also be an allowed scan root (fail-closed source-path policy)
    monkeypatch.setenv("SBOM_STORAGE_DIR", str(tmp_path / "sboms"))
    monkeypatch.setenv("CRYPTOSCAN_SOURCE_ROOTS", str(tmp_path))
    import api.routers.devsecops as ds

    monkeypatch.setattr(ds, "_SBOM_STORE", None)

    def _session():
        yield session

    application.dependency_overrides[get_db_session] = _session
    yield application, session, tmp_path
    application.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_scan_source_persists_and_downloads(app_db):
    application, session, tmp_path = app_db
    src = tmp_path / "app"
    (src / "sub").mkdir(parents=True)
    (src / "requirements.txt").write_text("requests==2.31.0\ncryptography>=3.4\nflask\n")
    (src / "sub" / "package.json").write_text(json.dumps({"dependencies": {"express": "4.18.0"}}))

    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/devsecops/sbom/scan",
                json={"kind": "source", "target": str(src), "format": "cyclonedx"},
                headers={"Authorization": "Bearer test-token"},
            )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    man = body["manifest"]
    assert man["kind"] == "source" and man["format"] == "cyclonedx"
    assert man["component_count"] == 4
    assert man["manifest_count"] == 2
    assert man["crypto_components"] == 1  # cryptography
    assert man["unpinned"] == 2  # cryptography range + flask missing
    assert body["bom"]["bomFormat"] == "CycloneDX" and body["bom"]["specVersion"] == "1.5"
    artifact_id = body["artifact_id"]

    # artifact is listed
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/devsecops/sbom/artifacts",
                                    headers={"Authorization": "Bearer test-token"})
    assert resp.status_code == 200
    arts = resp.json()["artifacts"]
    assert any(a["artifact_id"] == artifact_id for a in arts)

    # download returns the exact persisted bytes with sha256 provenance
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(f"/api/v1/devsecops/sbom/{artifact_id}/download",
                                    headers={"Authorization": "Bearer test-token"})
    assert resp.status_code == 200
    payload = resp.content
    assert hashlib.sha256(payload).hexdigest() == man["sha256"]
    assert resp.headers.get("x-sbom-sha256") == man["sha256"]
    assert "attachment" in resp.headers.get("content-disposition", "")
    assert json.loads(payload)["bomFormat"] == "CycloneDX"

    # audit trail recorded
    from db.models.user import AuditLog

    rows = session.execute(
        select(AuditLog).where(AuditLog.target_id == artifact_id)
    ).scalars().all()
    assert rows and rows[0].action == "devsecops.sbom_scan"
    assert rows[0].actor == "operator"


@pytest.mark.asyncio
async def test_scan_source_spdx_format(app_db):
    application, session, tmp_path = app_db
    src = tmp_path / "app"
    src.mkdir()
    (src / "requirements.txt").write_text("cryptography==42.0.0\n")

    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/devsecops/sbom/scan",
                json={"kind": "source", "target": str(src), "format": "spdx"},
                headers={"Authorization": "Bearer test-token"},
            )
    assert resp.status_code == 201, resp.text
    bom = resp.json()["bom"]
    assert bom["spdxVersion"] == "SPDX-2.3"
    assert any(p["name"] == "cryptography" for p in bom["packages"])


@pytest.mark.asyncio
async def test_scan_rejects_escaping_target(app_db):
    application, session, tmp_path = app_db
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/devsecops/sbom/scan",
                json={"kind": "source", "target": "/etc/passwd"},
                headers={"Authorization": "Bearer test-token"},
            )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_scan_rejects_bad_kind_and_format(app_db):
    application, session, tmp_path = app_db
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            r1 = await client.post(
                "/api/v1/devsecops/sbom/scan",
                json={"kind": "dockerfile", "target": str(tmp_path)},
                headers={"Authorization": "Bearer test-token"},
            )
            r2 = await client.post(
                "/api/v1/devsecops/sbom/scan",
                json={"kind": "source", "target": str(tmp_path), "format": "swf"},
                headers={"Authorization": "Bearer test-token"},
            )
    assert r1.status_code == 422
    assert r2.status_code == 422


@pytest.mark.asyncio
async def test_download_unknown_artifact_404(app_db):
    application, session, tmp_path = app_db
    fake = "00000000-0000-4000-8000-000000000000"
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            h = {"Authorization": "Bearer test-token"}
            r1 = await client.get(f"/api/v1/devsecops/sbom/{fake}/download", headers=h)
            r2 = await client.get("/api/v1/devsecops/sbom/../../etc/passwd/download", headers=h)
    assert r1.status_code == 404
    assert r2.status_code in (404, 405)


def _viewer_app(tmp_path, monkeypatch):
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()
    from db.models.user import User

    session.add(User(username="viewer1", password_hash="x", roles="viewer"))
    session.commit()

    application = create_app()
    application.dependency_overrides[get_current_user] = lambda: "viewer1"
    monkeypatch.setenv("SBOM_STORAGE_DIR", str(tmp_path / "sboms"))
    monkeypatch.setenv("CRYPTOSCAN_SOURCE_ROOTS", str(tmp_path))
    import api.routers.devsecops as ds

    monkeypatch.setattr(ds, "_SBOM_STORE", None)

    def _session():
        yield session

    application.dependency_overrides[get_db_session] = _session
    return application


@pytest.mark.asyncio
async def test_scan_forbidden_for_viewer(app_db, tmp_path, monkeypatch):
    application = _viewer_app(tmp_path / "viewer-store", monkeypatch)
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            r1 = await client.post(
                "/api/v1/devsecops/sbom/scan",
                json={"kind": "source", "target": str(tmp_path)},
                headers={"Authorization": "Bearer viewer-token"},
            )
            r2 = await client.get("/api/v1/devsecops/sbom/artifacts",
                                  headers={"Authorization": "Bearer viewer-token"})
            r3 = await client.delete(
                "/api/v1/devsecops/sbom/artifacts?older_than_days=0",
                headers={"Authorization": "Bearer viewer-token"})
    # generating and pruning SBOMs mutates state — operators only
    assert r1.status_code == 403
    assert r3.status_code == 403
    # reading the inventory is an auditor task, so the read-only role is allowed
    assert r2.status_code == 200


# ------------------------------------------------- new capabilities --------- #
async def _scan(client, tmp_path, name, *, kind="source", fmt="cyclonedx", extra=None):
    src = tmp_path / name
    src.mkdir(parents=True, exist_ok=True)
    (src / "requirements.txt").write_text("requests==2.31.0\ncryptography==42.0.0\n")
    body = {"kind": kind, "target": str(src), "format": fmt}
    body.update(extra or {})
    return await client.post("/api/v1/devsecops/sbom/scan", json=body,
                             headers={"Authorization": "Bearer test-token"})


@pytest.mark.asyncio
async def test_scan_reports_compliance_and_signature(app_db):
    application, session, tmp_path = app_db
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await _scan(client, tmp_path, "app")
    assert resp.status_code == 201, resp.text
    body = resp.json()
    compliance = body["compliance"]
    assert compliance["compliant"] is False  # third-party suppliers are unknown
    assert "Supplier name" in " ".join(compliance["gaps"])
    by_id = {e["id"]: e for e in compliance["elements"]}
    assert by_id["author"]["status"] == "PASS"   # operator recorded
    assert by_id["timestamp"]["status"] == "PASS"
    assert body["bom"]["metadata"]["authors"] == [{"name": "operator"}]
    assert body["manifest"].get("signature_alg") == "HMAC-SHA256"
    assert body["manifest"].get("signature")


@pytest.mark.asyncio
async def test_verify_artifact_ok_and_tamper_detected(app_db):
    application, session, tmp_path = app_db
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            scan = await _scan(client, tmp_path, "app")
            artifact_id = scan.json()["artifact_id"]
            headers = {"Authorization": "Bearer test-token"}
            good = await client.get(f"/api/v1/devsecops/sbom/{artifact_id}/verify", headers=headers)
    assert good.status_code == 200
    payload = good.json()
    assert payload["verdict"] == "OK" and payload["signed"] is True
    assert all(c["ok"] for c in payload["checks"])

    # tamper with the stored manifest -> signature check fails, blob still matches
    import api.routers.devsecops as ds

    store = ds._sbom_storage()
    man = next(m for m in store.list_manifests() if m["artifact_id"] == artifact_id)
    store.put_manifest(man["storage_key"], dict(man, component_count=999))
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            bad = await client.get(f"/api/v1/devsecops/sbom/{artifact_id}/verify",
                                   headers={"Authorization": "Bearer test-token"})
    assert bad.json()["verdict"] == "TAMPERED"
    checks = {c["check"]: c["ok"] for c in bad.json()["checks"]}
    assert checks["blob_sha256"] is True and checks["manifest_signature"] is False


@pytest.mark.asyncio
async def test_diff_two_artifacts(app_db):
    application, session, tmp_path = app_db
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            first = await _scan(client, tmp_path, "old")
            second = await _scan(client, tmp_path, "new")
            headers = {"Authorization": "Bearer test-token"}
            resp = await client.post(
                "/api/v1/devsecops/sbom/diff",
                json={"from_artifact": first.json()["artifact_id"],
                      "to_artifact": second.json()["artifact_id"]},
                headers=headers)
            missing = await client.post("/api/v1/devsecops/sbom/diff", json={}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["verdict"] == "UNCHANGED"
    assert resp.json()["sources"]["from"]["target"].endswith("old")
    assert missing.status_code == 422


@pytest.mark.asyncio
async def test_diff_inline_docs(app_db):
    application, session, tmp_path = app_db
    old = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
        {"type": "library", "name": "openssl", "version": "3.0.9", "purl": "pkg:generic/openssl@3.0.9",
         "properties": [{"name": "cryptoscan:crypto-library", "value": "true"}]}]}
    new = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
        {"type": "library", "name": "openssl", "version": "3.1.0", "purl": "pkg:generic/openssl@3.1.0",
         "properties": [{"name": "cryptoscan:crypto-library", "value": "true"}]}]}
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/v1/devsecops/sbom/diff",
                                     json={"from_doc": old, "to_doc": new},
                                     headers={"Authorization": "Bearer test-token"})
    assert resp.status_code == 200
    assert resp.json()["verdict"] == "CRYPTO_REVIEW"
    assert resp.json()["changed"][0]["direction"] == "upgrade"


@pytest.mark.asyncio
async def test_validate_endpoint_scores_supplier_document(app_db):
    application, session, tmp_path = app_db
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5",
           "metadata": {"timestamp": "2026-09-22T00:00:00Z", "authors": [{"name": "vendor"}]},
           "components": [{"type": "library", "name": "libfoo", "version": "1.0",
                           "purl": "pkg:generic/libfoo@1.0", "supplier": {"name": "ACME"}}],
           "dependencies": [{"ref": "pkg:generic/libfoo@1.0", "dependsOn": []}]}
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/v1/devsecops/sbom/validate", json={"doc": doc},
                                     headers={"Authorization": "Bearer test-token"})
            bad = await client.post("/api/v1/devsecops/sbom/validate", json={"doc": {"nope": 1}},
                                    headers={"Authorization": "Bearer test-token"})
    assert resp.status_code == 200
    assert resp.json()["compliant"] is True and resp.json()["score"] == "7/7"
    assert bad.json()["compliant"] is False


@pytest.mark.asyncio
async def test_report_markdown_and_json(app_db):
    application, session, tmp_path = app_db
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            scan = await _scan(client, tmp_path, "app")
            artifact_id = scan.json()["artifact_id"]
            headers = {"Authorization": "Bearer test-token"}
            md = await client.get(f"/api/v1/devsecops/sbom/{artifact_id}/report", headers=headers)
            js = await client.get(f"/api/v1/devsecops/sbom/{artifact_id}/report?fmt=json", headers=headers)
    assert md.status_code == 200 and "attachment" in md.headers.get("content-disposition", "")
    text = md.text
    assert "# SBOM report" in text and "Minimum elements (NTIA)" in text
    assert "cryptography" in text and "Crypto-relevant components" in text
    assert js.status_code == 200
    body = js.json()
    assert body["artifact"]["artifact_id"] == artifact_id
    assert body["compliance"]["score"].endswith("/7")
    assert any(c["name"] == "cryptography" for c in body["crypto_components"])


@pytest.mark.asyncio
async def test_prune_respects_age(app_db):
    application, session, tmp_path = app_db
    import api.routers.devsecops as ds

    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            scan = await _scan(client, tmp_path, "app")
            artifact_id = scan.json()["artifact_id"]
            headers = {"Authorization": "Bearer test-token"}
            # a just-created artifact survives a 1-day retention window
            keep = await client.delete("/api/v1/devsecops/sbom/artifacts?older_than_days=1",
                                       headers=headers)
            # backdate the manifest, then prune
            store = ds._sbom_storage()
            man = next(m for m in store.list_manifests() if m["artifact_id"] == artifact_id)
            store.put_manifest(man["storage_key"], dict(man, created_at="2020-01-01T00:00:00+00:00"))
            removed = await client.delete("/api/v1/devsecops/sbom/artifacts?older_than_days=30",
                                          headers=headers)
            gone = await client.get(f"/api/v1/devsecops/sbom/{artifact_id}/download", headers=headers)
            bad = await client.delete("/api/v1/devsecops/sbom/artifacts?older_than_days=0",
                                      headers=headers)
    assert keep.json() == {"deleted": 0, "kept": 1, "older_than_days": 1, "artifacts": []}
    assert removed.json()["deleted"] == 1
    assert gone.status_code == 404
    assert bad.status_code == 422


@pytest.mark.asyncio
async def test_spdx_report_excludes_document_root(app_db):
    """An SPDX report must not count the document's own subject as a component
    (it has no version, so it would surface as a phantom unpinned finding)."""
    application, session, tmp_path = app_db
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            scan = await _scan(client, tmp_path, "app", fmt="spdx")
            artifact_id = scan.json()["artifact_id"]
            resp = await client.get(f"/api/v1/devsecops/sbom/{artifact_id}/report?fmt=json",
                                    headers={"Authorization": "Bearer test-token"})
    assert resp.status_code == 200
    body = resp.json()
    manifest_components = scan.json()["manifest"]["component_count"]
    assert body["pinning"]["total_components"] == manifest_components
    assert body["pinning"]["unpinned"] == 0
    assert not [f for f in body["pinning"]["findings"] if f["code"] == "PIN-MISSING"]
    assert body["compliance"]["component_count"] == manifest_components


# --------------------------------------------------- gate + rescan + feeds --- #
_FEED = [
    {"cve_id": "CVE-2024-21538", "severity": "CRITICAL",
     "summary": "ReDoS in cross-spawn",
     "affected": [{"ecosystem": "npm", "package": "cross-spawn",
                   "ranges": [{"introduced": "0", "fixed": "7.0.5"}]}]},
    {"cve_id": "CVE-2023-32681", "severity": "MEDIUM",
     "summary": "proxy credential leak",
     "affected": [{"ecosystem": "pypi", "package": "requests",
                   "ranges": [{"introduced": "0", "fixed": "2.31.0"}]}]},
]


@pytest.mark.asyncio
async def test_scan_with_advisory_feed_records_vulnerabilities(app_db):
    """A feed is matched by manager->ecosystem, appears in the document and the
    gate fails on the critical one."""
    application, session, tmp_path = app_db
    src = tmp_path / "fed"
    src.mkdir()
    (src / "requirements.txt").write_text("requests==2.25.0\n")
    (src / "package.json").write_text(json.dumps({"dependencies": {"cross-spawn": "7.0.3"}}))

    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            scan = await client.post(
                "/api/v1/devsecops/sbom/scan",
                json={"kind": "source", "target": str(src), "format": "cyclonedx", "feed": _FEED},
                headers={"Authorization": "Bearer test-token"},
            )
            assert scan.status_code == 201, scan.text
            body = scan.json()
            artifact_id = body["artifact_id"]

            gate = await client.post(f"/api/v1/devsecops/sbom/{artifact_id}/gate",
                                     json={},
                                     headers={"Authorization": "Bearer test-token"})
            gate_allow = await client.post(
                f"/api/v1/devsecops/sbom/{artifact_id}/gate",
                json={"policy": {"allow_critical": 5, "max_unpinned": 5}},
                headers={"Authorization": "Bearer test-token"})
            ungated = await client.post("/api/v1/devsecops/sbom/scan",
                                        json={"kind": "source", "target": str(src)},
                                        headers={"Authorization": "Bearer test-token"})

    assert body["manifest"]["vulnerability_count"] == 2
    ids = {v["id"] for v in body["bom"]["vulnerabilities"]}
    assert ids == {"CVE-2024-21538", "CVE-2023-32681"}
    # the pypi advisory matched the pip component: version 2.25.0 < fixed 2.31.0
    pypi = next(v for v in body["bom"]["vulnerabilities"] if v["id"] == "CVE-2023-32681")
    assert pypi["affects"][0]["ref"].startswith("pkg:pypi/requests@2.25.0")

    assert gate.status_code == 200, gate.text
    assert gate.json()["verdict"] == "FAIL"
    codes = {b["code"] for b in gate.json()["blockers"]}
    assert "GATE-CVE-CRITICAL" in codes
    assert gate.json()["counts"]["CRITICAL"] == 1

    assert gate_allow.json()["verdict"] == "PASS"
    # no feed -> no advisory claims, and the manifest says so (an empty array
    # with feed_supplied=false is "not checked", not "verified clean")
    assert body["manifest"]["feed_supplied"] is True
    assert ungated.json()["manifest"]["vulnerability_count"] == 0
    assert ungated.json()["manifest"]["feed_supplied"] is False
    assert ungated.json()["bom"]["vulnerabilities"] == []


@pytest.mark.asyncio
async def test_gate_defaults_and_license_policy(app_db):
    """Default policy passes a clean SBOM; a deny-list policy blocks on the
    declared license it actually carries."""
    application, session, tmp_path = app_db
    src = tmp_path / "lic"
    src.mkdir()
    # a lockfile is where declared licenses actually live
    (src / "package-lock.json").write_text(json.dumps({
        "name": "app", "lockfileVersion": 3,
        "packages": {"": {"name": "app", "version": "1.0.0"},
                     "node_modules/picocolors": {"version": "1.0.0", "license": "Apache-2.0"}},
    }))

    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            scan = await client.post("/api/v1/devsecops/sbom/scan",
                                     json={"kind": "source", "target": str(src)},
                                     headers={"Authorization": "Bearer test-token"})
            artifact_id = scan.json()["artifact_id"]
            clean = await client.post(f"/api/v1/devsecops/sbom/{artifact_id}/gate",
                                      headers={"Authorization": "Bearer test-token"})
            denied = await client.post(
                f"/api/v1/devsecops/sbom/{artifact_id}/gate",
                json={"policy": {"deny_licenses": ["Apache-2.0"], "require_minimum_elements": True}},
                headers={"Authorization": "Bearer test-token"})
            permissive = await client.post(
                f"/api/v1/devsecops/sbom/{artifact_id}/gate",
                json={"policy": {"deny_licenses": ["GPL-3.0-only"]}},
                headers={"Authorization": "Bearer test-token"})
            unknown = await client.get("/api/v1/devsecops/sbom/11111111-2222-3333-4444-555555555555/gate",
                                       headers={"Authorization": "Bearer test-token"})

    assert clean.status_code == 200, clean.text  # no body at all -> default policy
    assert clean.json()["verdict"] == "PASS"
    licenses = {b["detail"] for b in denied.json()["blockers"] if b["code"] == "GATE-LICENSE-DENIED"}
    assert any("picocolors" in d and "Apache-2.0" in d for d in licenses)
    assert denied.json()["verdict"] == "FAIL"
    assert permissive.json()["verdict"] == "PASS"  # the deny list is honored exactly
    assert unknown.status_code in (404, 405)  # GET is not a gate operation


@pytest.mark.asyncio
async def test_rescan_detects_upstream_change(app_db):
    """Re-scanning a stored artifact after the tree changes must report the
    delta and produce a fresh artifact."""
    application, session, tmp_path = app_db
    src = tmp_path / "moving"
    src.mkdir()
    (src / "requirements.txt").write_text("requests==2.31.0\n")

    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            first = await client.post("/api/v1/devsecops/sbom/scan",
                                      json={"kind": "source", "target": str(src)},
                                      headers={"Authorization": "Bearer test-token"})
            assert first.status_code == 201, first.text
            artifact_id = first.json()["artifact_id"]

            unchanged = await client.post(f"/api/v1/devsecops/sbom/{artifact_id}/rescan",
                                         json={},
                                         headers={"Authorization": "Bearer test-token"})
            assert unchanged.status_code == 200, unchanged.text
            assert unchanged.json()["diff"]["verdict"] == "UNCHANGED"
            assert unchanged.json()["artifact_id"] != artifact_id

            # upstream bumped a version -> an ordinary update
            (src / "requirements.txt").write_text("requests==2.32.0\n")
            bumped = await client.post(f"/api/v1/devsecops/sbom/{unchanged.json()['artifact_id']}/rescan",
                                       json={},
                                       headers={"Authorization": "Bearer test-token"})
            assert bumped.status_code == 200, bumped.text
            delta = bumped.json()["diff"]
            assert delta["verdict"] == "UPDATED"
            assert any(c["name"] == "requests" and c["direction"] == "upgrade"
                       for c in delta["changed"])
            assert not delta["crypto_delta"]["added"]

            # ... and then pulled in a crypto library -> review, not a quiet update
            (src / "requirements.txt").write_text("requests==2.32.0\ncryptography==42.0.0\n")
            changed = await client.post(f"/api/v1/devsecops/sbom/{bumped.json()['artifact_id']}/rescan",
                                        json={},
                                        headers={"Authorization": "Bearer test-token"})
            assert changed.status_code == 200, changed.text
            delta = changed.json()["diff"]
            assert delta["verdict"] == "CRYPTO_REVIEW"
            assert any(a["name"] == "cryptography" and a["crypto"] for a in delta["crypto_delta"]["added"])
            # the fresh artifact carries the options needed to re-scan it again
            assert changed.json()["manifest"]["scan_options"]["target"] == str(src)
            assert changed.json()["gate"]["verdict"] == "PASS"

    # the recorded options describe the scan honestly (no feed was supplied)
    assert changed.json()["manifest"]["scan_options"]["feed_supplied"] is False
    assert changed.json()["notes"] == []


@pytest.mark.asyncio
async def test_rescan_reports_unavailable_target(app_db):
    """A target that has since disappeared fails loudly, not silently."""
    application, session, tmp_path = app_db
    src = tmp_path / "gone"
    src.mkdir()
    (src / "requirements.txt").write_text("requests==2.31.0\n")

    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            first = await client.post("/api/v1/devsecops/sbom/scan",
                                      json={"kind": "source", "target": str(src)},
                                      headers={"Authorization": "Bearer test-token"})
            artifact_id = first.json()["artifact_id"]
            import shutil

            shutil.rmtree(src)
            resp = await client.post(f"/api/v1/devsecops/sbom/{artifact_id}/rescan", json={},
                                     headers={"Authorization": "Bearer test-token"})

    assert resp.status_code == 400
    assert "re-scan" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_artifact_listing_filters(app_db):
    application, session, tmp_path = app_db
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            await _scan(client, tmp_path, "one", fmt="cyclonedx")
            await _scan(client, tmp_path, "two", fmt="spdx")

            def url(query=""):
                return f"/api/v1/devsecops/sbom/artifacts{query}"

            all_items = await client.get(url(), headers={"Authorization": "Bearer test-token"})
            only_spdx = await client.get(url("?fmt=spdx"), headers={"Authorization": "Bearer test-token"})
            by_query = await client.get(url(f"?q={tmp_path.name}"), headers={"Authorization": "Bearer test-token"})
            none_match = await client.get(url("?q=no-such-target-xyz"), headers={"Authorization": "Bearer test-token"})
            limited = await client.get(url("?limit=1"), headers={"Authorization": "Bearer test-token"})

    assert all_items.json()["total"] == 2
    assert only_spdx.json()["total"] == 1
    assert only_spdx.json()["artifacts"][0]["format"] == "spdx"
    assert by_query.json()["total"] == 2
    assert none_match.json()["total"] == 0
    assert limited.json()["returned"] == 1
    # the listing hands out the provenance links a caller needs
    first = all_items.json()["artifacts"][0]
    assert first["verify_url"].endswith("/verify") and first["report_url"].endswith("/report")
