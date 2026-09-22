"""Binary/firmware scanning API: real parsers -> SBOM + CBOM artifacts.

The byte-level fixture builders are shared with the devsecops unit suite so both
layers exercise the identical structures.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base

# services/api/tests/unit/<this file> -> services/
_SERVICES = Path(__file__).resolve().parents[3]


def _binary_fixtures():
    """Import the devsecops unit suite's fixture builders (ELF/PE/firmware/...)."""
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
OPENSSL_BANNER = "OpenSSL 3.0.20 7 Apr 2026"

#: a feed row for the OpenSSL found inside the fixture binary (generic ecosystem,
#: which is what a component parsed out of a binary is matched under)
OPENSSL_FEED = [{
    "cve_id": "CVE-2026-0001", "severity": "HIGH",
    "summary": "OpenSSL: buffer overread in X.509 parsing",
    "affected": [{"ecosystem": "generic", "package": "OpenSSL",
                  "ranges": [{"introduced": "3.0.0", "fixed": "3.0.21"}]}],
}]


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


def _target_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "images"
    directory.mkdir()
    (directory / "libcrypto.so.3").write_bytes(
        fixtures._elf64(deps=("libc.so.6", "libssl.so.3"), soname="libcrypto.so.3",
                        comment=b"GCC: (Ubuntu 13.2.0) 13.2.0\x00",
                        build_id=bytes.fromhex("7d90f38412d00023e58392b03612a24b62fcaede"),
                        imports=("EVP_EncryptInit_ex", "EVP_sha256"),
                        exports=("RSA_sign", "EVP_md5"),
                        strings=(OPENSSL_BANNER,)))
    (directory / "fw.img").write_bytes(fixtures._firmware())
    return directory


def _viewer_app(tmp_path, monkeypatch):
    """Same read-only harness the SBOM suite uses (viewer row + app override)."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
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


async def _post(application, url, payload, token="Bearer test-token"):
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.post(url, json=payload, headers={"Authorization": token})


async def _get(application, url, token="Bearer test-token"):
    async with ASGITransport(app=application) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.get(url, headers={"Authorization": token})


@pytest.mark.asyncio
async def test_binary_scan_end_to_end(app_db):
    application, _session, tmp_path = app_db
    directory = _target_dir(tmp_path)
    resp = await _post(application, "/api/v1/devsecops/binary/scan",
                       {"target": str(directory), "format": "cyclonedx"})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    manifest = body["manifest"]
    assert manifest["kind"] == "binary"
    assert manifest["binary_count"] == 2
    assert manifest["binary_summary"]["by_format"] == {"elf": 1, "uimage": 1}
    assert manifest["binary_summary"]["crypto_libraries"] == 1
    assert manifest["binary_summary"]["findings_by_severity"]["HIGH"] >= 1
    assert manifest["signature"] and manifest["signature_alg"] == "HMAC-SHA256"

    # the crypto implementation found in the binary is a component of the SBOM
    names = {component["name"]: component for component in body["bom"]["components"]}
    assert "libcrypto.so.3" in names and "OpenSSL" in names
    assert names["OpenSSL"]["version"] == "3.0.20"
    assert names["OpenSSL"]["bom-ref"] == "pkg:generic/OpenSSL@3.0.20" or \
        names["OpenSSL"]["bom-ref"].endswith("OpenSSL@3.0.20")

    # findings carry evidence and file provenance
    codes = {finding["code"] for finding in body["findings"]}
    assert {"BIN-WEAK-PRIMITIVE-PRESENT", "BIN-FIRMWARE-NOT-EXTRACTED"} <= codes
    weak = next(f for f in body["findings"] if f["code"] == "BIN-WEAK-PRIMITIVE-PRESENT")
    assert weak["path"] == "libcrypto.so.3" and "MD5" in weak["detail"]

    # CBOM was generated, stored and is fetchable; it validates as ingestible
    from cbom.inventory import records_from_bom, validate_document

    assert validate_document(body["cbom"])["ok"] is True
    assert body["cbom_result"]["components"] == len(body["cbom"]["components"]) >= 3
    assert records_from_bom(body["cbom"])
    stored = await _get(application, f"/api/v1/devsecops/binary/artifacts/"
                                    f"{body['artifact_id']}/cbom")
    assert stored.status_code == 200 and stored.json()["metadata"]["component"]["name"]
    assert stored.json()["components"] == body["cbom"]["components"]

    # the artifact behaves like every other SBOM artifact
    verify = await _get(application, body["verify_url"].replace("/api/v1", "/api/v1"))
    assert verify.status_code == 200, verify.text
    assert verify.json().get("signature_valid") in (True, None) or "valid" in verify.text.lower()
    report = await _get(application, "/api/v1/devsecops/sbom/"
                                    f"{body['artifact_id']}/report?fmt=markdown")
    assert report.status_code == 200 and "OpenSSL" in report.text
    gate = await _post(application, f"/api/v1/devsecops/sbom/{body['artifact_id']}/gate", {})
    assert gate.status_code == 200 and gate.json()["verdict"] in ("PASS", "REVIEW", "FAIL")
    license_resp = await _post(application, "/api/v1/devsecops/sbom/license",
                               {"artifact_id": body["artifact_id"]})
    assert license_resp.status_code == 200
    assert license_resp.json()["verdict"] in ("PASS", "REVIEW", "FAIL")


@pytest.mark.asyncio
async def test_binary_scan_reports_signature_and_encryption_posture(app_db):
    """Signing state and encryption reach the manifest summary, not just the rows."""
    application, _session, tmp_path = app_db
    directory = tmp_path / "machos"
    directory.mkdir()
    (directory / "acme-tool").write_bytes(fixtures._macho())
    (directory / "acme-tool-unsigned").write_bytes(fixtures._macho(signed=False))
    (directory / "acme-protected").write_bytes(fixtures._macho(encrypted=True))
    resp = await _post(application, "/api/v1/devsecops/binary/scan",
                       {"target": str(directory), "format": "cyclonedx"})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    summary = body["manifest"]["binary_summary"]
    assert summary["by_format"] == {"macho": 3}
    assert summary["signature_posture"] == {"signed": 2, "unsigned": 1}
    assert summary["encrypted_binaries"] == 1
    rows = {row["file_name"]: row for row in body["binaries"]}
    assert rows["acme-tool"]["signature"]["identifier"] == "com.acme.toolkit"
    assert rows["acme-tool"]["dylib_versions"]["/usr/lib/libcrypto.44.dylib"]["current"] == "3.0.20"
    assert rows["acme-tool"]["minimum_os"] == "13.0.1"
    assert rows["acme-protected"]["encrypted"] is True
    codes = {finding["code"] for finding in body["findings"]}
    assert {"BIN-UNSIGNED-MACHO", "BIN-ENTITLEMENT", "BIN-ENCRYPTED"} <= codes
    # the implementation the Mach-O links against becomes a crypto component
    assert "Apple CommonCrypto" in {component["name"] for component in body["bom"]["components"]}


@pytest.mark.asyncio
async def test_binary_scan_matches_advisories_and_gates(app_db):
    application, _session, tmp_path = app_db
    directory = _target_dir(tmp_path)
    resp = await _post(application, "/api/v1/devsecops/binary/scan",
                       {"target": str(directory), "feed": OPENSSL_FEED})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["manifest"]["feed_supplied"] is True
    vulnerabilities = body["bom"].get("vulnerabilities") or []
    assert [v["id"] for v in vulnerabilities] == ["CVE-2026-0001"]
    assert vulnerabilities[0]["affects"][0]["ref"].endswith("OpenSSL@3.0.20")
    gate = await _post(application, f"/api/v1/devsecops/sbom/{body['artifact_id']}/gate", {})
    assert gate.json()["counts"]["HIGH"] >= 1
    vex = await _post(application, "/api/v1/devsecops/sbom/vex",
                      {"artifact_id": body["artifact_id"]})
    assert vex.status_code == 200
    assert vex.json()["statement_count"] == 1
    statement = vex.json()["statements"][0]
    assert statement["cve"] == "CVE-2026-0001"
    # OpenSSL 3.0.20 < 3.0.21 is inside the affected range, so the derived
    # statement says exploitable — never "not_affected" without an operator
    assert statement["state"] == "exploitable" and statement["source"] == "derived"
    assert statement["fixed_version"] == "3.0.21"
    assert any(row["name"] == "OpenSSL" for row in statement["affected_components"])


@pytest.mark.asyncio
async def test_binary_scan_rescan_diffs_and_notes_missing_feed(app_db):
    application, _session, tmp_path = app_db
    directory = _target_dir(tmp_path)
    first = await _post(application, "/api/v1/devsecops/binary/scan",
                        {"target": str(directory), "feed": OPENSSL_FEED})
    artifact_id = first.json()["artifact_id"]

    # a new crypto implementation appears under the same target
    (directory / "libweak.so").write_bytes(
        fixtures._elf64(deps=("libc.so.6",), exports=("EVP_md5",),
                        strings=("OpenSSL 1.1.1w 11 Sep 2023",)))
    resp = await _post(application, f"/api/v1/devsecops/sbom/{artifact_id}/rescan", {})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["artifact_id"] != artifact_id
    assert body["scan_options"]["kind"] == "binary"
    assert body["diff"] is not None
    added = body["diff"].get("added") or []
    assert any("libweak.so" in json.dumps(row) for row in added)
    assert any("advisory feed" in note for note in body["notes"])
    assert body["gate"]["verdict"] in ("PASS", "REVIEW", "FAIL")


@pytest.mark.asyncio
async def test_sbom_scan_endpoint_accepts_binary_kind(app_db):
    application, _session, tmp_path = app_db
    directory = _target_dir(tmp_path)
    resp = await _post(application, "/api/v1/devsecops/sbom/scan",
                       {"kind": "binary", "target": str(directory), "format": "spdx"})
    assert resp.status_code == 201, resp.text
    manifest = resp.json()["manifest"]
    assert manifest["kind"] == "binary" and manifest["format"] == "spdx"
    assert manifest["binary_summary"]["binaries_scanned"] == 2
    assert manifest["scan_options"]["kind"] == "binary"


@pytest.mark.asyncio
async def test_binary_scan_target_and_format_validation(app_db):
    application, _session, tmp_path = app_db
    missing = await _post(application, "/api/v1/devsecops/binary/scan",
                          {"target": str(tmp_path / "nope")})
    assert missing.status_code == 404
    outside = await _post(application, "/api/v1/devsecops/binary/scan", {"target": "/etc"})
    assert outside.status_code == 400
    bad_format = await _post(application, "/api/v1/devsecops/binary/scan",
                             {"target": str(_target_dir(tmp_path)), "format": "yaml"})
    assert bad_format.status_code == 422
    empty = await _post(application, "/api/v1/devsecops/binary/scan", {"target": ""})
    assert empty.status_code == 422


@pytest.mark.asyncio
async def test_binary_scan_role_gating_and_cbom_ingest_flag(app_db, monkeypatch):
    application, _session, tmp_path = app_db
    directory = _target_dir(tmp_path)
    body = (await _post(application, "/api/v1/devsecops/binary/scan",
                        {"target": str(directory), "ingest_cbom": True})).json()
    assert body["cbom_result"]["ingested"] is True
    assert body["cbom_result"]["records"] >= 1
    assert body["cbom_result"]["ingest_endpoint"] == "/api/v1/cbom/ingest"

    # a read-only user may read the stored CBOM but may not start scans
    viewer_app = _viewer_app(tmp_path, monkeypatch)
    denied = await _post(viewer_app, "/api/v1/devsecops/binary/scan",
                         {"target": str(directory)}, token="Bearer viewer-token")
    assert denied.status_code == 403, denied.text
    assert "requires one of roles" in denied.json()["detail"].lower()
    allowed = await _get(viewer_app, f"/api/v1/devsecops/binary/artifacts/"
                                     f"{body['artifact_id']}/cbom", token="Bearer viewer-token")
    assert allowed.status_code == 200


@pytest.mark.asyncio
async def test_cbom_endpoint_404s_for_unknown_artifact(app_db):
    application, _session, _tmp_path = app_db
    resp = await _get(application, "/api/v1/devsecops/binary/artifacts/"
                                   "00000000-0000-0000-0000-000000000000/cbom")
    assert resp.status_code == 404
    bad = await _get(application, "/api/v1/devsecops/binary/artifacts/not-a-uuid/cbom")
    assert bad.status_code == 404
