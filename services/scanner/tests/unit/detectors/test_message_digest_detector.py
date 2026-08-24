from pathlib import Path

from scanner.parsers.java_parser import JavaParser


def test_md5_detected(tmp_path: Path):
    java = tmp_path / "H.java"
    java.write_text('class H { void t() throws Exception { java.security.MessageDigest.getInstance("MD5"); } }\n')
    findings = JavaParser(tmp_path).parse_file(java)
    assert any(f.crypto.algorithm == "MD5" for f in findings)
