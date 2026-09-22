"""Minimum-elements validation, SBOM diffing, and artifact provenance signing."""

from __future__ import annotations

import json

from devsecops import sbom_scan as sb
from devsecops.sbom_assurance import check_minimum_elements, diff_boms


def _write(path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _cdx(name="app", version="1.0.0", *, supplier=True, purl=True, deps=True, author=True):
    comp = {"type": "library", "name": name, "version": version,
            "bom-ref": f"pkg:pypi/{name}@{version}"}
    if purl:
        comp["purl"] = f"pkg:pypi/{name}@{version}"
    if supplier:
        comp["supplier"] = {"name": "pyca"}
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "metadata": {"timestamp": "2026-09-22T00:00:00+00:00"},
        "components": [comp],
    }
    if author:
        bom["metadata"]["authors"] = [{"name": "admin"}]
    if deps:
        bom["dependencies"] = [{"ref": comp["bom-ref"], "dependsOn": []}]
    return bom


# ------------------------------------------------------- minimum elements ---- #
def test_minimum_elements_complete_document():
    report = check_minimum_elements(_cdx())
    assert report["compliant"] is True
    assert report["score"] == "7/7"
    assert report["gaps"] == []
    assert report["format"] == "cyclonedx"


def test_minimum_elements_reports_each_gap():
    report = check_minimum_elements(_cdx(author=False, supplier=False, purl=False, deps=False))
    assert report["compliant"] is False
    assert report["score"] == "3/7"
    by_id = {e["id"]: e for e in report["elements"]}
    assert by_id["unique_id"]["status"] == "FAIL"
    assert by_id["dependencies"]["status"] == "FAIL"
    assert by_id["author"]["status"] == "FAIL"
    assert by_id["supplier"]["status"] == "FAIL"
    assert by_id["version"]["status"] == "PASS"
    assert len(report["gaps"]) == 4


def test_minimum_elements_partial_coverage():
    bom = _cdx(supplier=True)
    second = {"type": "library", "name": "flask", "version": "3.0.2", "purl": "pkg:pypi/flask@3.0.2"}
    bom["components"].append(second)
    report = check_minimum_elements(bom)
    supplier_row = next(e for e in report["elements"] if e["id"] == "supplier")
    assert supplier_row["status"] == "PARTIAL"
    assert supplier_row["detail"] == "1/2 components"
    assert report["compliant"] is False


def test_minimum_elements_empty_and_unknown_documents():
    empty = check_minimum_elements({})
    assert empty["compliant"] is False and "empty" in empty["gaps"][0]
    unknown = check_minimum_elements({"hello": "world"})
    assert unknown["compliant"] is False and unknown["format"] == "unknown"


def test_minimum_elements_spdx_counts_only_real_components():
    spdx = {
        "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "demo",
        "creationInfo": {"created": "2026-09-22T00:00:00Z", "creators": ["Tool: CryptoScan"]},
        "packages": [
            {"name": "demo", "SPDXID": "SPDXRef-Container", "versionInfo": "NOASSERTION"},
            {"name": "requests", "SPDXID": "SPDXRef-Package-1-requests", "versionInfo": "2.31.0",
             "supplier": "Organization: Python Software Foundation",
             "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:pypi/requests@2.31.0"}]},
        ],
        "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
             "relatedSpdxElement": "SPDXRef-Container"},
        ],
    }
    report = check_minimum_elements(spdx)
    assert report["format"] == "spdx"
    assert report["component_count"] == 1  # the described root is not a component
    assert report["score"] == "7/7"


# ------------------------------------------------------------------- diff ---- #
def test_diff_detects_add_remove_and_version_change():
    old = _cdx("requests", "2.30.0")
    new = _cdx("requests", "2.31.0")
    new["components"].append({"type": "library", "name": "urllib3", "version": "2.2.1",
                              "bom-ref": "pkg:pypi/urllib3@2.2.1", "purl": "pkg:pypi/urllib3@2.2.1"})
    report = diff_boms(old, new)
    assert report["verdict"] == "UPDATED"
    assert [c["name"] for c in report["changed"]] == ["requests"]
    assert report["changed"][0]["direction"] == "upgrade"
    assert [a["name"] for a in report["added"]] == ["urllib3"]
    assert report["removed"] == []


def test_diff_flags_crypto_and_downgrades():
    old = _cdx("openssl", "3.1.0")
    new = _cdx("openssl", "3.0.9")
    old["components"][0]["properties"] = [{"name": "cryptoscan:crypto-library", "value": "true"}]
    new["components"][0]["properties"] = [{"name": "cryptoscan:crypto-library", "value": "true"}]
    report = diff_boms(old, new)
    assert report["verdict"] == "CRYPTO_REVIEW"
    assert report["changed"][0]["direction"] == "downgrade"
    assert report["changed"][0]["crypto"] is True
    assert [c["name"] for c in report["crypto_delta"]["changed"]] == ["openssl"]


def test_diff_identical_is_unchanged():
    report = diff_boms(_cdx(), _cdx())
    assert report["verdict"] == "UNCHANGED"
    assert report["change_count"] == 0


def test_diff_across_formats_normalizes():
    cdx = _cdx("requests", "2.31.0")
    spdx = {
        "spdxVersion": "SPDX-2.3",
        "packages": [{"name": "requests", "SPDXID": "SPDXRef-Package-1-requests",
                      "versionInfo": "2.31.0",
                      "externalRefs": [{"referenceType": "purl",
                                        "referenceLocator": "pkg:pypi/requests@2.31.0"}]}],
        "relationships": [],
    }
    report = diff_boms(cdx, spdx)
    assert report["verdict"] == "UNCHANGED"


def test_diff_detects_license_change():
    old = _cdx("lib", "1.0.0")
    new = _cdx("lib", "1.0.0")
    old["components"][0]["licenses"] = [{"license": {"id": "MIT"}}]
    new["components"][0]["licenses"] = [{"license": {"id": "GPL-3.0-only"}}]
    report = diff_boms(old, new)
    row = next(c for c in report["changed"] if c["direction"] == "license_change")
    assert row["from"] == "MIT" and row["to"] == "GPL-3.0-only"
    assert report["verdict"] == "UPDATED"


# ---------------------------------------------------------------- signing ---- #
def test_sign_and_verify_manifest_roundtrip():
    manifest = {"artifact_id": "x", "sha256": "abc", "component_count": 3}
    signature = sb.sign_manifest(manifest, "secret")
    signed = dict(manifest, signature=signature, signature_alg="HMAC-SHA256")
    assert sb.verify_manifest(signed, "secret") is True
    assert sb.verify_manifest(signed, "wrong-secret") is False
    tampered = dict(signed, component_count=4)
    assert sb.verify_manifest(tampered, "secret") is False


def test_verify_artifact_reports_each_check():
    blob = b'{"bomFormat": "CycloneDX"}'
    import hashlib

    manifest = {"sha256": hashlib.sha256(blob).hexdigest()}
    good = sb.verify_artifact(manifest, blob, None)
    assert good["verdict"] == "OK" and good["signed"] is False
    bad = sb.verify_artifact(dict(manifest, sha256="0" * 64), blob, None)
    assert bad["verdict"] == "TAMPERED"
    signed_manifest = dict(manifest)
    signed_manifest["signature"] = sb.sign_manifest(signed_manifest, "s")
    signed_manifest["signature_alg"] = "HMAC-SHA256"
    assert sb.verify_artifact(signed_manifest, blob, "s")["verdict"] == "OK"
    assert sb.verify_artifact(signed_manifest, blob, "other")["verdict"] == "TAMPERED"


def test_rendered_bom_carries_graph_and_author(tmp_path):
    _write(tmp_path / "package.json", json.dumps({"dependencies": {"express": "^4.18.0"}}))
    _write(tmp_path / "package-lock.json", json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"express": "^4.18.0"}},
            "node_modules/express": {"version": "4.19.2", "dependencies": {"cookie": "0.6.0"}},
            "node_modules/cookie": {"version": "0.6.0", "license": "MIT"},
        },
    }))
    result = sb.scan_source(str(tmp_path))
    cdx = sb.render_sbom(result, fmt="cyclonedx", created_by="auditor1")
    assert cdx["metadata"]["authors"] == [{"name": "auditor1"}]
    refs = {d["ref"]: d["dependsOn"] for d in cdx["dependencies"]}
    assert refs["pkg:npm/express@4.19.2"] == ["pkg:npm/cookie@0.6.0"]
    cookie = next(c for c in cdx["components"] if c["name"] == "cookie")
    assert cookie["licenses"] == [{"license": {"id": "MIT"}}]
    assert check_minimum_elements(cdx)["score"] == "6/7"  # only supplier is unknown

    spdx = sb.render_sbom(result, fmt="spdx", created_by="auditor1")
    cookie_spdx = next(p for p in spdx["packages"] if p["name"] == "cookie")
    assert cookie_spdx["licenseDeclared"] == "MIT"
    assert any(r["relationshipType"] == "DEPENDS_ON" for r in spdx["relationships"])
