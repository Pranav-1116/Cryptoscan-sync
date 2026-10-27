"""Deterministic tests for the E2E SBOM scanner: source-tree manifest walk,
crypto enrichment, CycloneDX 1.5 / SPDX 2.3 rendering, and image-ref safety.
No network: containers are exercised through the deterministic scanner only."""

from __future__ import annotations

import json

import pytest

from devsecops import sbom_scan as sb


def _write(path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# ------------------------------------------------------------- scan_source -- #
def test_scan_source_parses_manifests(tmp_path):
    _write(tmp_path / "requirements.txt", "requests==2.31.0\ncryptography>=3.4\nflask\n")
    _write(tmp_path / "package.json", json.dumps({"dependencies": {"express": "4.18.0"}}))
    _write(tmp_path / "go.mod", "module m\n\ngo 1.21\n\nrequire (\n\tgithub.com/golang-jwt/jwt/v5 v5.2.0\n)\n")
    # node_modules is always skipped (declared-dependency policy)
    _write(tmp_path / "node_modules" / "left-pad" / "package.json", json.dumps({"dependencies": {}}))

    r = sb.scan_source(str(tmp_path))
    pkgs = {p["name"]: p for p in r["packages"]}
    assert r["target_kind"] == "source"
    assert r["manifest_count"] == 3
    assert pkgs["requests"]["version"] == "2.31.0" and pkgs["requests"]["manager"] == "pip"
    assert pkgs["cryptography"]["manager"] == "pip"
    assert pkgs["flask"]["version"] is None  # unpinned
    assert pkgs["express"]["version"] == "4.18.0" and pkgs["express"]["manager"] == "npm"
    assert "github.com/golang-jwt/jwt/v5" in {p["name"] for p in r["packages"]}
    assert not any("left-pad" in (p.get("name") or "") for p in r["packages"])
    assert r["binaries"] == [] and r["vulnerabilities"] == []


def test_scan_source_vendor_skipped_by_default(tmp_path):
    _write(tmp_path / "vendor" / "libfoo" / "requirements.txt", "foo==1.0.0\n")
    off = sb.scan_source(str(tmp_path))
    assert not any(p["name"] == "foo" for p in off["packages"])
    on = sb.scan_source(str(tmp_path), include_vendored=True)
    assert any(p["name"] == "foo" and p["version"] == "1.0.0" for p in on["packages"])


def test_scan_source_dedupes_across_manifests(tmp_path):
    _write(tmp_path / "a" / "requirements.txt", "requests==2.31.0\n")
    _write(tmp_path / "b" / "requirements.txt", "requests==2.31.0\n")
    r = sb.scan_source(str(tmp_path))
    assert len([p for p in r["packages"] if p["name"] == "requests"]) == 1
    assert r["manifest_count"] == 2


def test_scan_source_not_a_directory(tmp_path):
    with pytest.raises(ValueError):
        sb.scan_source(str(tmp_path / "missing"))


def test_scan_source_crypto_enrichment(tmp_path):
    _write(tmp_path / "requirements.txt", "cryptography==42.0.0\npyjwt==2.8.0\n")
    r = sb.scan_source(str(tmp_path))
    libs = {l["name"]: l for l in r["libraries"]}
    assert "cryptography" in libs
    assert libs["cryptography"]["vendor"] == "pyca"
    assert "Ed25519" in libs["cryptography"]["algorithms"]
    assert "pyjwt" not in libs  # curated registry only


def test_scan_source_bad_manifest_does_not_kill_scan(tmp_path):
    _write(tmp_path / "requirements.txt", "requests==2.31.0\n")
    _write(tmp_path / "package.json", "{not valid json")
    r = sb.scan_source(str(tmp_path))
    assert any(p["name"] == "requests" for p in r["packages"])
    assert r["manifest_count"] >= 1


def test_scan_container_rootfs(tmp_path):
    """A filesystem root (docker-extracted rootfs) scans offline via the real
    container scanner — no docker/registry needed."""
    sp = tmp_path / "rootfs" / "usr" / "lib" / "python3.11" / "site-packages"
    di = sp / "cryptography-42.0.0.dist-info"
    di.mkdir(parents=True)
    (di / "METADATA").write_text("Metadata-Version: 2.1\nName: cryptography\nVersion: 42.0.0\n")

    r = sb.scan_container(str(tmp_path / "rootfs"))
    pkgs = {p["name"]: p for p in r["packages"]}
    assert "cryptography" in pkgs
    assert pkgs["cryptography"]["version"] == "42.0.0"
    assert r["target_kind"] in ("filesystem", "image")

    cdx = sb.render_sbom(r, fmt="cyclonedx")
    assert cdx["bomFormat"] == "CycloneDX"
    assert any(c["name"] == "cryptography" for c in cdx["components"])


# ------------------------------------------------------------------ rendering -- #
def _small_tree(tmp_path) -> dict:
    _write(tmp_path / "requirements.txt", "cryptography==42.0.0\nflask\n")
    return sb.scan_source(str(tmp_path))


def test_render_cyclonedx_1_5(tmp_path):
    r = _small_tree(tmp_path)
    cdx = sb.render_sbom(r, fmt="cyclonedx")
    assert cdx["bomFormat"] == "CycloneDX"
    assert cdx["specVersion"] == "1.5"
    comps = {c["name"]: c for c in cdx["components"]}
    assert "cryptography" in comps and "flask" in comps
    props = comps["cryptography"].get("properties") or []
    names = {p["name"]: p["value"] for p in props}
    assert names.get("cryptoscan:crypto-library") == "true"
    assert names.get("cryptoscan:vendor") == "pyca"
    assert names.get("cryptoscan:deprecated") == "false"
    # every component carries provenance metadata; only crypto libs carry vendor
    flask_props = {p["name"]: p["value"] for p in comps["flask"].get("properties") or []}
    assert flask_props.get("cryptoscan:scope") == "declared"
    assert flask_props.get("cryptoscan:direct") == "true"
    assert "cryptoscan:crypto-library" not in flask_props


def test_render_spdx_2_3(tmp_path):
    r = _small_tree(tmp_path)
    spdx = sb.render_sbom(r, fmt="spdx")
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert spdx["SPDXID"] == "SPDXRef-DOCUMENT"
    pkgs = {p["name"]: p for p in spdx["packages"]}
    assert "cryptography" in pkgs and "flask" in pkgs
    assert pkgs["cryptography"]["versionInfo"] == "42.0.0"
    # relationships: every package RELATED TO the target
    assert len(spdx["relationships"]) == 1 + len([p for p in spdx["packages"] if p["SPDXID"] != "SPDXRef-Container"])


def test_render_rejects_unknown_format(tmp_path):
    r = _small_tree(tmp_path)
    with pytest.raises(ValueError):
        sb.render_sbom(r, fmt="swf")


# -------------------------------------------------------------- image ref ---- #
def test_is_image_ref():
    assert sb.is_image_ref("nginx:1.27")
    assert sb.is_image_ref("docker.io/library/nginx:1.27")
    assert sb.is_image_ref("ghcr.io/acme/app")
    assert not sb.is_image_ref("/tmp/some/path")
    assert not sb.is_image_ref("~/.cache")
    assert not sb.is_image_ref("a;b")
    assert not sb.is_image_ref("with space:1")
    assert not sb.is_image_ref("")
    assert not sb.is_image_ref("$(`id`)")


# ------------------------------------------------------- integrity hashes --- #
def test_decode_integrity_understands_sri_and_hex():
    import base64

    sha512 = base64.b64encode(b"a" * 64).decode()
    assert sb.decode_integrity(f"sha512-{sha512}")[0]["alg"] == "SHA-512"
    assert sb.decode_integrity("sha256:" + "ab" * 32) == [
        {"alg": "SHA-256", "content": "ab" * 32}]
    # the strongest algorithm wins when several are present
    sha1 = base64.b64encode(b"b" * 20).decode()
    assert sb.decode_integrity(f"sha1-{sha1} sha512-{sha512}")[0]["alg"] == "SHA-512"


def test_decode_integrity_ignores_what_it_must_not_convert():
    # Go's h1: is a directory-listing hash, not a component content digest
    assert sb.decode_integrity("h1:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=") == []
    assert sb.decode_integrity("not-a-hash") == []
    assert sb.decode_integrity("") == []
    assert sb.decode_integrity(None) == []
    assert sb.decode_integrity("sha512-!!!!") == []   # malformed base64 is skipped, not guessed


def test_npm_integrity_lands_in_both_formats(tmp_path):
    import base64

    integrity = "sha512-" + base64.b64encode(b"c" * 64).decode()
    _write(tmp_path / "package-lock.json", json.dumps({
        "name": "app", "lockfileVersion": 3,
        "packages": {"": {"name": "app"},
                     "node_modules/nanoid": {"version": "3.3.7", "integrity": integrity}}}))

    result = sb.scan_source(str(tmp_path))
    cdx = sb.render_sbom(result, fmt="cyclonedx", created_by="t")
    nanoid = next(c for c in cdx["components"] if c["name"] == "nanoid")
    assert nanoid["hashes"][0]["alg"] == "SHA-512"

    spdx = sb.render_sbom(result, fmt="spdx", created_by="t")
    pkg = next(p for p in spdx["packages"] if p["name"] == "nanoid")
    assert pkg["checksums"] == [{"algorithm": "SHA512",
                                 "checksumValue": "63" * 64}]


# ----------------------------------------------------- vulnerability feed --- #
_FEED = [
    {"cve_id": "CVE-2024-0001", "severity": "HIGH", "summary": "boom",
     "affected": [{"ecosystem": "npm", "package": "lodash",
                   "ranges": [{"introduced": "0", "fixed": "4.17.21"}]}]},
]


def test_enrich_vulnerabilities_maps_manager_to_ecosystem(tmp_path):
    _write(tmp_path / "package.json", json.dumps({"dependencies": {"lodash": "4.17.20"}}))
    result = sb.scan_source(str(tmp_path))
    found = sb.enrich_vulnerabilities(result, _FEED)
    assert [v["cve"] for v in found] == ["CVE-2024-0001"]
    assert found[0]["manager"] == "npm" and found[0]["fixed_version"] == "4.17.21"

    cdx = sb.render_sbom(result, fmt="cyclonedx", created_by="t")
    vuln = cdx["vulnerabilities"][0]
    assert vuln["id"] == "CVE-2024-0001"
    assert vuln["affects"][0]["ref"].startswith("pkg:npm/lodash@4.17.20")


def test_enrich_vulnerabilities_without_feed_claims_nothing(tmp_path):
    _write(tmp_path / "package.json", json.dumps({"dependencies": {"lodash": "4.17.20"}}))
    result = sb.scan_source(str(tmp_path))
    assert sb.enrich_vulnerabilities(result, []) == []
    assert result["vulnerabilities"] == []
    # an unpinned component cannot be matched — versions are never guessed
    _write(tmp_path / "other" / "package.json", json.dumps({"dependencies": {"lodash": "4.17.20"}}))
    result["packages"][0]["version"] = None
    assert sb.enrich_vulnerabilities(result, _FEED) == []


def test_enrich_vulnerabilities_ignores_unaffected_versions(tmp_path):
    _write(tmp_path / "package.json", json.dumps({"dependencies": {"lodash": "4.17.21"}}))
    result = sb.scan_source(str(tmp_path))
    assert sb.enrich_vulnerabilities(result, _FEED) == []
