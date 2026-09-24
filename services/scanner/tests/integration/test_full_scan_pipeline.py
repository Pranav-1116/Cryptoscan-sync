"""Full scan pipeline tests against the live Scanner API."""

from __future__ import annotations

import json
from pathlib import Path

from scanner.output.json_writer import JSONWriter


def test_full_scan_discovers_all_findings(crypto_scanner, sample_java_files):
    result = crypto_scanner.scan(sample_java_files)
    assert result.scan_completed is True
    assert result.files_scanned > 0
    assert len(result.findings) > 0

    names = [Path(f.source.file_path).name for f in result.findings]
    des_findings = [f for f in result.findings if f.crypto.algorithm == "DES"]
    assert len(des_findings) >= 1
    assert "BadCrypto.java" in names

    aes_findings = [
        f for f in result.findings if f.crypto.algorithm == "AES" and f.crypto.mode == "GCM"
    ]
    assert len(aes_findings) >= 1

    md5_findings = [f for f in result.findings if f.crypto.algorithm == "MD5"]
    assert len(md5_findings) >= 1

    hardcoded = [f for f in result.findings if f.metadata.is_hardcoded_key]
    assert len(hardcoded) >= 1


def test_scan_output_is_valid_json(crypto_scanner, sample_java_files, temp_workspace):
    result = crypto_scanner.scan(sample_java_files)
    output_file = temp_workspace / "scan_output.json"
    JSONWriter(output_file).write(result)
    data = json.loads(output_file.read_text())
    assert {"scan_id", "scan_start", "scanner_version", "statistics", "findings"} <= data.keys()
    assert data["findings"]
    assert {"finding_id", "source", "crypto", "metadata"} <= data["findings"][0].keys()


def test_scan_handles_parse_errors_gracefully(crypto_scanner, temp_workspace):
    # A file the shallow syntax check rejects (unbalanced braces — also what Kotlin char
    # literals like '{' look like) must neither abort the scan nor be dropped: the regex
    # path still inventories its crypto calls.
    (temp_workspace / "Broken.java").write_text(
        "package com.example;\nimport java.security.MessageDigest;\npublic class Broken {\n"
        "    MessageDigest md = MessageDigest.getInstance(\"MD5\");\n    // missing closing brace\n"
    )
    result = crypto_scanner.scan(temp_workspace)
    assert result.scan_completed is True
    assert result.statistics.files_with_errors == 0
    assert any(f.crypto.algorithm == "MD5" for f in result.findings)


def test_scan_respects_exclusion_patterns(crypto_scanner, temp_workspace):
    excluded = temp_workspace / "node_modules"
    excluded.mkdir()
    (excluded / "ShouldBeExcluded.java").write_text(
        'import javax.crypto.Cipher;\nclass ShouldBeExcluded { void t() throws Exception { Cipher.getInstance("DES"); } }\n'
    )
    included = temp_workspace / "src"
    included.mkdir()
    (included / "ShouldBeIncluded.java").write_text(
        'import javax.crypto.Cipher;\nclass ShouldBeIncluded { void t() throws Exception { Cipher.getInstance("AES"); } }\n'
    )
    result = crypto_scanner.scan(temp_workspace)
    scanned = [Path(f.source.file_path).name for f in result.findings]
    assert "ShouldBeIncluded.java" in scanned
    assert "ShouldBeExcluded.java" not in scanned
