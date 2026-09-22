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
