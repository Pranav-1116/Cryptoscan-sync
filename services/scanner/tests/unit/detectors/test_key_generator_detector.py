from pathlib import Path

from scanner.parsers.java_parser import JavaParser


def test_key_generator_size(tmp_path: Path):
    java = tmp_path / "G.java"
    java.write_text(
        'class G { void t() throws Exception { javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance("AES"); kg.init(256); } }\n'
    )
    findings = JavaParser(tmp_path).parse_file(java)
    assert any(f.crypto.algorithm == "AES" and f.crypto.key_size == 256 for f in findings)
