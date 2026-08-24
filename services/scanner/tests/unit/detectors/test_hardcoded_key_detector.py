from pathlib import Path

from scanner.parsers.java_parser import JavaParser


def test_hardcoded_string_key(tmp_path: Path):
    java = tmp_path / "K.java"
    java.write_text(
        'class K { void t() { new javax.crypto.spec.SecretKeySpec("abc".getBytes(), "AES"); } }\n'
    )
    findings = JavaParser(tmp_path).parse_file(java)
    assert any(f.metadata.is_hardcoded_key for f in findings)
