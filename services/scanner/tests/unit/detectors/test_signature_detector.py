from pathlib import Path

from scanner.parsers.java_parser import JavaParser


def test_signature_rsa(tmp_path: Path):
    java = tmp_path / "S.java"
    java.write_text(
        'class S { void t() throws Exception { java.security.Signature.getInstance("SHA256withRSA"); } }\n'
    )
    findings = JavaParser(tmp_path).parse_file(java)
    assert any(f.crypto.algorithm == "RSA" for f in findings)
