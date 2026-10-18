"""Opt-in real-Docker qualification; skipped by default, never replaced by mocks."""
import os
import shutil

import pytest


@pytest.mark.live
@pytest.mark.skipif(not os.environ.get("CRYPTOSCAN_SCANNER_IMAGE") or not shutil.which("docker"),
                    reason="requires Docker and a preloaded digest-pinned scanner image")
def test_static_parser_in_restricted_container(tmp_path, monkeypatch):
    from worker.core.static_scan_isolation import scan_static

    source = tmp_path / "admitted-checkout"
    source.mkdir(mode=0o755)
    (source / "crypto.py").write_text("import hashlib\nhashlib.md5(b'qualification-fixture')\n")
    (source / "crypto.py").chmod(0o644)
    (source / ".git").mkdir(mode=0o755)
    (source / ".git" / "config").write_text("[remote \"origin\"]\nurl = https://ci-only-clone-sentinel@repo.invalid/x\n")
    monkeypatch.setenv("CRYPTOSCAN_STATIC_SCAN_MODE", "container")
    result = scan_static(root_path=source, scan_id="docker-qualification")
    assert result.status == "COMPLETED"
    assert result.scan_id == "docker-qualification"
    assert any(finding.crypto.algorithm == "MD5" for finding in result.findings)
    assert result.isolation["mode"] == "container"
    assert all(result.isolation["runtime_checks"].values())
    assert not list(source.glob(".cryptoscan-scan-*"))
