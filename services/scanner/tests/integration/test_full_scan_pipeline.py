"""
Integration test: Full scan pipeline.
Tests end-to-end scanning from file discovery to output.
"""
import pytest
import json
from pathlib import Path


def test_full_scan_discovers_all_findings(crypto_scanner, sample_java_files, temp_workspace):
    """Test that scanner discovers all expected crypto patterns."""
    # Act: Run full scan
    result = crypto_scanner.scan(sample_java_files)
    
    # Assert: Basic scan success
    assert result.scan_completed is True
    assert result.files_scanned > 0
    assert len(result.findings) > 0
    
    # Assert: Found DES usage
    des_findings = [f for f in result.findings if f.crypto.algorithm == "DES"]
    assert len(des_findings) == 1
    assert des_findings[0].source.file_path.name == "BadCrypto.java"
    assert des_findings[0].metadata.confidence == "HIGH"
    
    # Assert: Found AES-GCM usage
    aes_findings = [f for f in result.findings 
                    if f.crypto.algorithm == "AES" and f.crypto.mode == "GCM"]
    assert len(aes_findings) == 1
    assert aes_findings[0].source.file_path.name == "GoodCrypto.java"
    
    # Assert: Found MD5 usage
    md5_findings = [f for f in result.findings if f.crypto.algorithm == "MD5"]
    assert len(md5_findings) == 1
    
    # Assert: Found hardcoded key
    hardcoded_findings = [f for f in result.findings if f.metadata.is_hardcoded_key]
    assert len(hardcoded_findings) == 1


def test_scan_output_is_valid_json(crypto_scanner, sample_java_files, temp_workspace):
    """Test that scan output is valid JSON and matches schema."""
    # Act
    result = crypto_scanner.scan(sample_java_files)
    output_file = temp_workspace / "scan_output.json"
    
    from scanner.output.json_writer import JSONWriter
    writer = JSONWriter(output_file)
    writer.write(result)
    
    # Assert: File exists
    assert output_file.exists()
    
    # Assert: Valid JSON
    with open(output_file) as f:
        data = json.load(f)
    
    # Assert: Required fields present
    assert 'scan_id' in data
    assert 'scan_start' in data
    assert 'scan_end' in data
    assert 'scanner_version' in data
    assert 'statistics' in data
    assert 'findings' in data
    
    # Assert: Findings structure
    assert len(data['findings']) > 0
    first_finding = data['findings'][0]
    assert 'finding_id' in first_finding
    assert 'source' in first_finding
    assert 'crypto' in first_finding
    assert 'metadata' in first_finding


def test_scan_handles_parse_errors_gracefully(crypto_scanner, temp_workspace):
    """Test that scanner handles broken Java files gracefully."""
    # Arrange: Create intentionally broken Java file
    broken_file = temp_workspace / "Broken.java"
    broken_file.write_text("""
package com.example;
public class Broken {
    // Incomplete class - missing closing brace
""")
    
    # Act: Scan should not crash
    result = crypto_scanner.scan(temp_workspace)
    
    # Assert: Scan completed despite error
    assert result.scan_completed is True
    # Broken file should be logged but not crash scanner
    assert result.statistics.files_with_errors >= 1


def test_scan_respects_exclusion_patterns(crypto_scanner, temp_workspace, scanner_config):
    """Test that excluded directories are not scanned."""
    # Arrange: Create files in excluded directory
    excluded_dir = temp_workspace / "node_modules"
    excluded_dir.mkdir()
    (excluded_dir / "ShouldBeExcluded.java").write_text("""
package com.example;
import javax.crypto.Cipher;
public class ShouldBeExcluded {
    void test() throws Exception {
        Cipher c = Cipher.getInstance("DES");
    }
}
""")
    
    # Arrange: Create file in included directory
    included_dir = temp_workspace / "src"
    included_dir.mkdir()
    (included_dir / "ShouldBeIncluded.java").write_text("""
package com.example;
import javax.crypto.Cipher;
public class ShouldBeIncluded {
    void test() throws Exception {
        Cipher c = Cipher.getInstance("AES");
    }
}
""")
    
    # Act
    result = crypto_scanner.scan(temp_workspace)
    
    # Assert: Only included file was scanned
    scanned_files = [f.source.file_path.name for f in result.findings]
    assert "ShouldBeIncluded.java" in scanned_files
    assert "ShouldBeExcluded.java" not in scanned_files