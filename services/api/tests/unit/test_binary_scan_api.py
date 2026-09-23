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


def _key_fixtures():
    """Import the embedded-key suite's builders (DER/PEM/PGP/JKS key fixtures)."""
    path = _SERVICES / "devsecops" / "tests" / "test_embedded_keys.py"
    name = "embedded_key_fixtures"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


fixtures = _binary_fixtures()
key_fixtures = _key_fixtures()
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
async def test_binary_scan_summary_reports_what_the_constant_search_covered(app_db):
    """Coverage reaches the manifest: "no AES constants" needs a denominator."""
    application, _session, tmp_path = app_db
    directory = tmp_path / "tables"
    directory.mkdir()
    (directory / "libacme.so").write_bytes(
        fixtures._elf64(soname="libacme.so",
                        constants=fixtures.cc.aes_sbox() + fixtures.cc.sha256_k()))
    (directory / "quiet.so").write_bytes(fixtures._elf64(soname="quiet.so"))
    resp = await _post(application, "/api/v1/devsecops/binary/scan",
                       {"target": str(directory), "format": "cyclonedx"})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    coverage = body["manifest"]["binary_summary"]["constants"]
    assert coverage["artefacts_searched"] == 2 and coverage["searched_bytes"] > 0
    assert coverage["complete_tables"] == 2
    assert coverage["algorithms"] == ["AES", "SHA-256"]
    rows = {row["file_name"]: row for row in body["binaries"]}
    assert rows["libacme.so"]["constants"]["tables_matched"] == 2
    assert rows["quiet.so"]["constants"]["tables_matched"] == 0
    assert rows["quiet.so"]["constants"]["searched_bytes"] > 0

    # coverage counts what the ladder will not name. An eight-byte prefix of the
    # AES S-box is matched, and is not enough to report AES.
    weak = tmp_path / "weak"
    weak.mkdir()
    (weak / "libweak.so").write_bytes(
        fixtures._elf64(soname="libweak.so", constants=fixtures.cc.aes_sbox()[:8]))
    resp = await _post(application, "/api/v1/devsecops/binary/scan",
                       {"target": str(weak), "format": "cyclonedx"})
    assert resp.status_code == 201, resp.text
    coverage = resp.json()["manifest"]["binary_summary"]["constants"]
    assert coverage["tables_matched"] == 1 and coverage["complete_tables"] == 0
    assert coverage["algorithms"] == []

    # SHA-256's H and BLAKE2s's IV are the same words: the one that stores its IV
    # this way is named, the other is a counted ambiguity that is never confirmed
    shared = tmp_path / "shared"
    shared.mkdir()
    (shared / "libshared.so").write_bytes(
        fixtures._elf64(soname="libshared.so", constants=fixtures.cc.sha256_h()))
    resp = await _post(application, "/api/v1/devsecops/binary/scan",
                       {"target": str(shared), "format": "cyclonedx"})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    coverage = body["manifest"]["binary_summary"]["constants"]
    assert coverage["tables_matched"] == 2 and coverage["algorithms"] == ["SHA-256"]
    row = body["binaries"][0]
    assert row["crypto_constants"] == ["SHA-256"]      # BLAKE2s is counted, not confirmed
    assert row["constants"]["by_level"] == {"CONSTANT_COMPLETE": 1, "CONSTANT_WEAK": 1}
    assert row["algorithms"] == ["SHA-256"]


@pytest.mark.asyncio
async def test_stored_report_carries_the_scan_findings_and_constant_coverage(app_db):
    """The stored artefact is what an auditor reads; it has to name the findings."""
    application, _session, tmp_path = app_db
    directory = tmp_path / "reportme"
    directory.mkdir()
    (directory / "libacme.so").write_bytes(
        fixtures._elf64(soname="libacme.so",
                        constants=fixtures.cc.aes_sbox() + fixtures.cc.sha256_h()))
    resp = await _post(application, "/api/v1/devsecops/binary/scan",
                       {"target": str(directory), "format": "cyclonedx"})
    assert resp.status_code == 201, resp.text
    artifact_id = resp.json()["artifact_id"]

    report = await _get(application,
                        f"/api/v1/devsecops/sbom/{artifact_id}/report?fmt=markdown")
    assert report.status_code == 200, report.text
    text = report.text
    assert "## Binary scan" in text
    assert "Constant tables:" in text and "byte(s) searched" in text
    assert "Confirmed by constant table: AES, SHA-256" in text
    assert "## Scan findings" in text and "BIN-CRYPTO-CONSTANT-TABLE" in text
    # the ambiguity is in the report as the ambiguity it is
    assert "BIN-CRYPTO-CONSTANT-SHARED" in text and "shared with SHA-256" in text

    payload = (await _get(application,
                          f"/api/v1/devsecops/sbom/{artifact_id}/report?fmt=json")).json()
    assert payload["binary"]["constants"]["searched_bytes"] > 0
    excerpt = payload["binary"]["findings_excerpt"]
    assert {row["code"] for row in excerpt} >= {"BIN-CRYPTO-CONSTANT-TABLE",
                                                "BIN-CRYPTO-CONSTANT-SHARED"}
    assert all(row["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
               for row in excerpt)
    assert [row["severity"] for row in excerpt] == sorted(
        (row["severity"] for row in excerpt),
        key=lambda severity: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[severity])


@pytest.mark.asyncio
async def test_binary_scan_manifest_carries_the_fleet_fingerprint_comparison(app_db):
    """Same build, same code, resemblance — counted on the manifest, not inferred."""
    application, _session, tmp_path = app_db
    directory = tmp_path / "fleet"
    directory.mkdir()
    base = fixtures._elf64(soname="libacme.so", constants=fixtures.cc.aes_sbox() * 3)
    (directory / "libacme-a.so").write_bytes(base)
    (directory / "libacme-b.so").write_bytes(base)
    patched = bytearray(base)
    patched[patched.find(fixtures.cc.aes_sbox()) + 500] ^= 0xFF
    (directory / "variant.so").write_bytes(bytes(patched))
    (directory / "unrelated.so").write_bytes(fixtures._elf64(soname="other.so",
                                                            strings=("zzz",)))
    resp = await _post(application, "/api/v1/devsecops/binary/scan",
                       {"target": str(directory), "format": "cyclonedx"})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    summary = body["manifest"]["binary_summary"]["fingerprints"]
    assert summary["artefacts_fingerprinted"] == 4
    assert summary["exact_duplicate_groups"] == 1
    assert summary["exact_duplicate_artefacts"] == 2      # the two copies, not the variant
    assert summary["near_duplicate_pairs"] >= 1
    assert summary["duplicate_groups"][0]["byte_identical"] is True
    assert summary["similarity_threshold"] == 85

    rows = {row["file_name"]: row["fingerprints"] for row in body["binaries"]}
    assert rows["libacme-a.so"]["build_fingerprint"] == rows["libacme-b.so"]["build_fingerprint"]
    assert rows["libacme-a.so"]["build_id"] == rows["libacme-b.so"]["build_id"]
    assert rows["variant.so"]["build_fingerprint"] != rows["libacme-a.so"]["build_fingerprint"]
    assert rows["variant.so"]["code_sha256"] != rows["libacme-a.so"]["code_sha256"]
    codes = {finding["code"] for finding in body["findings"]}
    assert {"BIN-FINGERPRINT-DUPLICATE", "BIN-FINGERPRINT-NEAR-DUPLICATE"} <= codes


@pytest.mark.asyncio
async def test_fingerprint_match_answers_identical_same_code_and_similar(app_db):
    """Incident response: does this build appear elsewhere, and does anything resemble it?"""
    application, _session, tmp_path = app_db
    directory = tmp_path / "fleet"
    directory.mkdir()
    base = fixtures._elf64(soname="libacme.so", constants=fixtures.cc.aes_sbox() * 3)
    (directory / "libacme-a.so").write_bytes(base)
    (directory / "libacme-b.so").write_bytes(base)
    (directory / "reimported.so").write_bytes(fixtures._elf64(
        soname="libacme.so", constants=fixtures.cc.aes_sbox() * 3,
        imports=("RAND_bytes",)))
    patched = bytearray(base)
    patched[patched.find(fixtures.cc.aes_sbox()) + 500] ^= 0xFF
    (directory / "variant.so").write_bytes(bytes(patched))
    (directory / "unrelated.so").write_bytes(fixtures._elf64(soname="other.so",
                                                            strings=("zzz",)))

    resp = await _post(application, "/api/v1/devsecops/fingerprints/match",
                       {"target": str(directory),
                        "reference": str(directory / "libacme-a.so"),
                        "similarity": 40})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["query"]["source"]["path"].endswith("libacme-a.so")
    assert body["identical"] == 2                     # itself and its byte-identical twin
    assert body["same_code"] == 1                     # reimported: code matches, imports do not
    assert body["similar"] == 1                       # the patched copy
    matches = {row["path"]: row for row in body["matches"]}
    assert matches["variant.so"]["verdict"] == "similar"
    assert 40 <= matches["variant.so"]["score"] < 100
    assert "unrelated.so" not in matches
    assert body["limits"]["files_read"] == 5 and body["limits"]["truncated"] is False
    assert body["similarity_threshold"] == 40 and "resemblance, not identity" in body["note"]
    # identical first, then same-code, then resemblance
    assert [row["verdict"] for row in body["matches"]] == ["identical", "identical",
                                                           "same-code", "similar"]

    # an explicit fingerprint is a valid query, and a query with nothing in it is not
    query = {"target": str(directory),
             "build_fingerprint": matches["variant.so"]["build_fingerprint"]}
    resp = await _post(application, "/api/v1/devsecops/fingerprints/match", query)
    assert resp.status_code == 200 and resp.json()["identical"] == 1
    resp = await _post(application, "/api/v1/devsecops/fingerprints/match",
                       {"target": str(directory), "similarity": 85})
    assert resp.status_code == 400 and "needs a reference file" in resp.json()["detail"]

    # and the target is confined to the same allowed roots as every other scan
    resp = await _post(application, "/api/v1/devsecops/fingerprints/match",
                       {"target": "/etc", "code_sha256": "a" * 64})
    assert resp.status_code == 400 and "allowed source roots" in resp.json()["detail"]


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


@pytest.mark.asyncio
async def test_binary_scan_inventories_embedded_key_material(app_db):
    """A key inside a binary is a critical finding, a CBOM asset and an SBOM row."""
    application, _session, tmp_path = app_db
    directory = tmp_path / "fleet"
    directory.mkdir()
    private_key = key_fixtures._rsa_pem()
    (directory / "acme-agent").write_bytes(
        key_fixtures._elf_with(private_key + key_fixtures._pem("CERTIFICATE",
                                                               key_fixtures._certificate())))
    resp = await _post(application, "/api/v1/devsecops/binary/scan",
                       {"target": str(directory), "format": "cyclonedx"})
    assert resp.status_code == 201, resp.text
    body = resp.json()

    summary = body["manifest"]["binary_summary"]["key_material"]
    assert summary["private_keys"] == 1
    assert summary["unencrypted_private_keys"] == 1
    assert summary["certificates"] == 1
    assert summary["keystores"] == 0
    assert summary["artefacts_with_keys"] == 1
    assert body["manifest"]["binary_summary"]["signature_posture"] == {"signed": 0, "unsigned": 0}

    critical = [f for f in body["findings"] if f["code"] == "BIN-EMBEDDED-PRIVATE-KEY"]
    assert len(critical) == 1 and critical[0]["severity"] == "CRITICAL"
    assert critical[0]["path"] == "acme-agent"
    assert critical[0]["key"]["material_sha256"] and "material" not in critical[0]["key"]
    assert {f["code"] for f in body["findings"]} >= {"BIN-EMBEDDED-CERTIFICATE"}

    row = next(b for b in body["binaries"] if b["file_name"] == "acme-agent")
    assert row["embedded_keys"]["private_keys"] == 1
    key_row = next(k for k in row["embedded_keys"]["keys"] if k["kind"] == "private-key")
    assert key_row["key_bits"] == 1024 and key_row["key_type"] == "rsa"

    # the CBOM inventories the key as an asset, identified by its hash
    assets = [c for c in body["cbom"]["components"]
              if str(c.get("bom-ref", "")).startswith("cryptoscan:binary/key/")]
    assert len(assets) == 2
    private = next(c for c in assets
                   if c["cryptoProperties"]["assetType"] == "related-crypto-material")
    properties = {p["name"]: p["value"] for p in private["properties"]}
    assert properties["cryptoscan:key-type"] == "rsa"
    assert properties["cryptoscan:encrypted"] == "false"
    assert properties["cryptoscan:quantum-vulnerable"] == "true"
    assert len(properties["cryptoscan:material-sha256"]) == 64
    stored = await _get(application, f"/api/v1/devsecops/binary/artifacts/"
                                    f"{body['artifact_id']}/cbom")
    assert stored.status_code == 200
    assert [c for c in stored.json()["components"] if "key/" in str(c.get("bom-ref", ""))]

    # the stored report counts the key material *and* names the finding
    report = await _get(application,
                        f"/api/v1/devsecops/sbom/{body['artifact_id']}/report")
    assert "Embedded key material: 1 private key(s) (1 unencrypted)" in report.text
    assert "BIN-EMBEDDED-PRIVATE-KEY" in report.text
    # and the report never carries the key itself either
    for secret in (key_fixtures.MODULUS, key_fixtures.PRIVATE_EXPONENT):
        assert secret.hex() not in report.text

    # nothing in the response — summary, findings, SBOM or CBOM — carries the key itself
    dumped = json.dumps(body, sort_keys=True)
    for secret in (key_fixtures.MODULUS, key_fixtures.PRIVATE_EXPONENT):
        assert secret.hex() not in dumped
        assert secret.decode("latin-1") not in dumped
    assert key_fixtures._rsa_pkcs1().hex() not in dumped


@pytest.mark.asyncio
async def test_binary_scan_distinguishes_encrypted_and_test_key_material(app_db):
    """Encrypted keys are HIGH, keys labelled as samples do not cry wolf."""
    application, _session, tmp_path = app_db
    directory = tmp_path / "vendor"
    directory.mkdir()
    (directory / "vendor-lib").write_bytes(key_fixtures._elf_with(
        key_fixtures._pem("ENCRYPTED PRIVATE KEY", key_fixtures._rsa_pkcs8_encrypted())))
    (directory / "vendor-sample").write_bytes(key_fixtures._elf_with(
        b"# DO NOT USE - example key\n" + key_fixtures._rsa_pem()))
    resp = await _post(application, "/api/v1/devsecops/binary/scan",
                       {"target": str(directory), "format": "cyclonedx"})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    summary = body["manifest"]["binary_summary"]["key_material"]
    # the sample key is counted as a test vector, so it is not also a private-key leak
    assert summary["private_keys"] == 1
    assert summary["unencrypted_private_keys"] == 0
    assert summary["test_vectors"] == 1
    by_code = {}
    for finding in body["findings"]:
        by_code.setdefault(finding["code"], []).append(finding)
    assert by_code["BIN-EMBEDDED-PRIVATE-KEY"][0]["severity"] == "HIGH"
    assert by_code["BIN-EMBEDDED-PRIVATE-KEY"][0]["path"] == "vendor-lib"
    assert by_code["BIN-EMBEDDED-TEST-KEY"][0]["severity"] == "INFO"
    assert by_code["BIN-EMBEDDED-TEST-KEY"][0]["path"] == "vendor-sample"


@pytest.mark.asyncio
async def test_a_critical_scan_finding_fails_the_gate(app_db):
    """A leaked private key is not a CVE — the gate must still not say PASS."""
    application, _session, tmp_path = app_db
    directory = tmp_path / "fleet"
    directory.mkdir()
    (directory / "acme-agent").write_bytes(
        key_fixtures._elf_with(key_fixtures._rsa_pem()))
    resp = await _post(application, "/api/v1/devsecops/binary/scan",
                       {"target": str(directory), "format": "cyclonedx"})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["manifest"]["binary_summary"]["findings_by_severity"]["CRITICAL"] == 1
    assert body["bom"] and not body["bom"].get("vulnerabilities")

    gate = await _post(application, f"/api/v1/devsecops/sbom/{body['artifact_id']}/gate", {})
    assert gate.status_code == 200, gate.text
    verdict = gate.json()
    assert verdict["verdict"] == "FAIL"
    assert [b["code"] for b in verdict["blockers"]] == ["GATE-SCAN-CRITICAL"]
    assert verdict["counts"]["scanner_findings"]["CRITICAL"] == 1

    # a policy that allows one critical finding lets it through, as a warning
    allowed = await _post(application, f"/api/v1/devsecops/sbom/{body['artifact_id']}/gate",
                          {"policy": {"allow_scanner_critical": 1}})
    allowed_body = allowed.json()
    assert allowed_body["verdict"] == "PASS"
    assert "GATE-SCAN-CRITICAL-PRESENT" in {w["code"] for w in allowed_body["warnings"]}


@pytest.mark.asyncio
async def test_binary_scan_runs_customer_rules_and_publishes_the_ruleset(app_db):
    """A rule is only evidence if the manifest says which rules produced it."""
    application, _session, tmp_path = app_db
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "vendor.yar").write_text('''
        rule vendor_debug_socket {
            meta:
                description = "vendor build with the debug socket compiled in"
                severity = "HIGH"
                category = "vendor"
            strings:
                $listen = "debug-listen:0.0.0.0:31337"
            condition:
                $listen
        }
    ''', "utf-8")
    target = tmp_path / "images"
    target.mkdir()
    (target / "libcrypto.so.3").write_bytes(fixtures._elf64(
        soname="libcrypto.so.3", strings=(OPENSSL_BANNER, "debug-listen:0.0.0.0:31337")))

    resp = await _post(application, "/api/v1/devsecops/binary/scan",
                       {"target": str(target), "yara_rules": [str(rules)]})
    assert resp.status_code == 201, resp.text
    summary = resp.json()["manifest"]["binary_summary"]
    yara = summary["yara"]
    from devsecops import yara_rules as yr

    assert yara["digest"] == yr.load_rules([rules]).digest
    assert yara["matches"] == 1 and yara["files_matched"] == 1
    assert yara["by_rule"] == {"vendor_debug_socket": 1}
    assert yara["by_severity"] == {"HIGH": 1}
    assert yara["error_count"] == 0
    assert summary["findings_by_severity"].get("HIGH", 0) >= 1

    # the same rule matches inside a container, and the row says which rule fired
    archive = target / "bundle.zip"
    import zipfile

    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as handle:
        # deflated, so the marker exists *inside* the archive and nowhere in the
        # container's own bytes — a match can only come from the member
        handle.writestr("lib/payload.so", b"\x7fELF\x02\x01\x01" + b"\x00" * 32
                        + b"debug-listen:0.0.0.0:31337")
    resp = await _post(application, "/api/v1/devsecops/binary/scan",
                       {"target": str(archive), "yara_rules": [str(rules)]})
    assert resp.status_code == 201, resp.text
    rows = resp.json()["bom"].get("metadata", {}).get("component", {})
    assert rows, "the SBOM still renders when rules are supplied"
    assert resp.json()["manifest"]["binary_summary"]["yara"]["by_rule"] \
        == {"vendor_debug_socket": 1}

    # a rule path outside the allowed roots, and a path that does not exist
    outside = await _post(application, "/api/v1/devsecops/binary/scan",
                          {"target": str(target), "yara_rules": ["/etc/yara"]})
    assert outside.status_code == 400 and "allowed source roots" in outside.json()["detail"]
    missing = await _post(application, "/api/v1/devsecops/binary/scan",
                          {"target": str(target), "yara_rules": [str(tmp_path / "nope.yar")]})
    assert missing.status_code == 404 and "rule path not found" in missing.json()["detail"]


@pytest.mark.asyncio
async def test_yara_validate_says_what_will_run_and_what_was_refused(app_db):
    """The check before trusting a ruleset: what loaded, and what did not."""
    application, _session, tmp_path = app_db
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "good.yar").write_text('''
        private rule helper { strings: $h = "internal-marker" condition: $h }
        rule uses_helper : vendor {
            meta: description = "uses the shared helper" severity = "LOW"
            strings: $a = "second-marker"
            condition: helper or $a
        }
    ''', "utf-8")

    resp = await _post(application, "/api/v1/devsecops/yara/validate", {"rules": [str(rules)]})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    names = {row["name"] for row in body["rules"]}
    assert {"helper", "uses_helper"} <= names
    row = next(r for r in body["rules"] if r["name"] == "uses_helper")
    assert row["tags"] == ["vendor"] and row["severity"] == "LOW"
    assert row["condition_refers_to"] == ["helper"]
    assert body["summary"]["error_count"] == 0
    assert body["summary"]["digest"]

    # rule text can be checked without writing a file, and unsupported syntax is refused
    text = await _post(application, "/api/v1/devsecops/yara/validate",
                       {"text": 'rule pasted { strings: $a = "x" base64 condition: $a }'})
    assert text.status_code == 422 and "does not parse" in text.json()["detail"]
    good = await _post(application, "/api/v1/devsecops/yara/validate",
                       {"text": 'rule pasted { meta: severity = "INFO" condition: filesize > 0 }'})
    assert good.status_code == 200
    assert good.json()["text_rules"][0]["name"] == "pasted"

    outside = await _post(application, "/api/v1/devsecops/yara/validate", {"rules": ["/etc"]})
    assert outside.status_code == 400 and "allowed source roots" in outside.json()["detail"]
