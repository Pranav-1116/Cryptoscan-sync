from pathlib import Path

from scanner.parsers.java_parser import JavaParser


def test_cipher_detector_finds_des(tmp_path: Path):
    java = tmp_path / "C.java"
    java.write_text('class C { void t() throws Exception { javax.crypto.Cipher.getInstance("DES"); } }\n')
    findings = JavaParser(tmp_path).parse_file(java)
    assert any(f.crypto.algorithm == "DES" for f in findings)
