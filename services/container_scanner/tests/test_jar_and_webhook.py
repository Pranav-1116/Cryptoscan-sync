"""Container scanner tests — jar scanner + registry webhook handler (untested)."""

from __future__ import annotations

import zipfile
from pathlib import Path


from container_scanner.analyzers.embedded.jar_scanner import _jar_string_hits, scan_jars
from container_scanner.registry.registry_webhook_handler import parse_registry_event


def _make_jar(path: Path, *, entries: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, blob in entries.items():
            archive.writestr(name, blob)


class TestScanJars:
    def test_no_jars_empty(self, tmp_path: Path):
        assert scan_jars(tmp_path) == []

    def test_detects_jar_and_fingerprints(self, tmp_path: Path):
        lib = tmp_path / "lib" / "bcprov-jdk15on-1.70.jar"
        lib.parent.mkdir(parents=True)
        _make_jar(lib, entries={
            "org/bouncycastle/crypto/Cipher.class": (
                b"\xca\xfe\xba\xbe AES/CBC/PKCS5Padding Cipher javax.crypto"
            ),
        })
        findings = scan_jars(tmp_path)
        assert len(findings) == 1
        entry = findings[0]
        assert entry["type"] == "jar"
        assert entry["name"] == "bcprov-jdk15on-1.70"
        assert entry["path"] == "lib/bcprov-jdk15on-1.70.jar"
        # bouncycastle recognized by the fingerprint repository
        assert entry.get("library")
        assert entry["algorithms"]

    def test_string_hits_included(self, tmp_path: Path):
        jar = tmp_path / "app.jar"
        _make_jar(jar, entries={
            "com/example/Pay.class": (
                b"\xca\xfe\xba\xbe MessageDigest.getInstance(\"MD5\")"
            ),
        })
        entry = scan_jars(tmp_path)[0]
        assert "string_hits" in entry
        assert any(hit.get("algorithm") == "MD5" for hit in entry["string_hits"])
        assert "MD5" in entry["algorithms"]

    def test_invalid_jar_still_reported_without_algorithms(self, tmp_path: Path):
        # a corrupt .jar is still surfaced as a fingerprint entry, but with
        # no algorithms and no string hits
        bad = tmp_path / "broken.jar"
        bad.write_bytes(b"this is not a zip file at all")
        entry = scan_jars(tmp_path)[0]
        assert entry["name"] == "broken"
        assert entry["algorithms"] == []
        assert "string_hits" not in entry

    def test_nested_jar_relative_path(self, tmp_path: Path):
        deep = tmp_path / "a" / "b" / "crypto.jar"
        deep.parent.mkdir(parents=True)
        _make_jar(deep, entries={"x.class": b"Cipher"})
        entry = scan_jars(tmp_path)[0]
        assert entry["path"] == "a/b/crypto.jar"

    def test_jar_string_hits_missing_module_returns_empty(self, tmp_path: Path, monkeypatch):
        import sys

        jar = tmp_path / "x.jar"
        _make_jar(jar, entries={"x.class": b"Cipher AES"})
        monkeypatch.setitem(
            sys.modules, "scanner.detectors.java.jar_string_scanner", None)
        assert _jar_string_hits(jar, tmp_path) == []


class TestParseRegistryEvent:
    def test_generic_push_payload(self):
        result = parse_registry_event({
            "image": "registry.example.com/acme/api",
            "tag": "v1.2.3",
            "digest": "sha256:abc",
            "action": "push",
        })
        assert result["source"] == "generic"
        assert result["accepted"] is True
        assert result["image"] == "registry.example.com/acme/api"
        assert result["tag"] == "v1.2.3"
        assert result["reference"] == "registry.example.com/acme/api:v1.2.3"
        assert result["scan_requested"] is True

    def test_dockerhub_hub_style(self):
        result = parse_registry_event({
            "repository": {"repo_name": "library/nginx"},
            "target": {"tag": "1.25", "digest": "sha256:xyz"},
        }, source="dockerhub")
        assert result["source"] == "dockerhub"
        assert result["image"] == "library/nginx"
        assert result["tag"] == "1.25"
        assert result["digest"] == "sha256:xyz"
        assert result["reference"] == "library/nginx:1.25"

    def test_gcr_resources_style(self):
        result = parse_registry_event({
            "event_data": {"repository": "us.gcr.io/proj/svc"},
            "resources": [{"resource_url": "us.gcr.io/proj/svc", "tag": "latest"}],
        }, source="gcr")
        assert result["image"] == "us.gcr.io/proj/svc"
        assert result["tag"] == "latest"
        assert result["reference"] == "us.gcr.io/proj/svc:latest"

    def test_image_with_tag_does_not_double_append(self):
        result = parse_registry_event({"image": "acme/app:1.0"})
        assert result["reference"] == "acme/app:1.0"

    def test_image_with_digest_kept_as_is(self):
        result = parse_registry_event({"image": "acme/app@sha256:deadbeef"})
        assert result["reference"] == "acme/app@sha256:deadbeef"

    def test_path_and_archive(self):
        result = parse_registry_event({
            "path": "/tmp/layers/acme/app",
            "archive": "/tmp/tarballs/app.tar",
        })
        assert result["path"] == "/tmp/layers/acme/app"
        assert result["archive"] == "/tmp/tarballs/app.tar"
        assert result["scan_requested"] is True

    def test_empty_payload(self):
        result = parse_registry_event(None)
        assert result["image"] is None
        assert result["tag"] is None
        assert result["reference"] is None
        assert result["scan_requested"] is False

    def test_no_reference_no_scan(self):
        result = parse_registry_event({"action": "delete"})
        assert result["scan_requested"] is False

    def test_detail_style_harbor(self):
        result = parse_registry_event({
            "detail": {
                "repository-name": "harbor.local/team/app",
                "image-tag": "sha256:feed",
            },
        }, source="harbor")
        assert result["image"] == "harbor.local/team/app"
        assert result["tag"] == "sha256:feed"
        assert result["reference"] == "harbor.local/team/app:sha256:feed"

    def test_action_defaults_to_push(self):
        result = parse_registry_event({"image": "x/y"})
        assert result["action"] == "push"
