from pathlib import Path

from scanner.core.plugin import JavaSourcePlugin
from scanner.parsers.java_ast import extract_crypto_events
from scanner.parsers.java_parser import JavaParser


def test_ast_ignores_commented_cipher(tmp_path: Path):
    java = tmp_path / "C.java"
    java.write_text(
        """
class C {
  // Cipher.getInstance("DES");
  void t() throws Exception { javax.crypto.Cipher.getInstance("AES/GCM/NoPadding"); }
}
"""
    )
    findings = JavaParser(tmp_path).parse_file(java)
    algos = {f.crypto.algorithm for f in findings}
    assert "AES" in algos
    assert "DES" not in algos


def test_ast_resolves_local_string_constant(tmp_path: Path):
    java = tmp_path / "V.java"
    java.write_text(
        """
class V {
  void t() throws Exception {
    String transform = "DES/ECB/PKCS5Padding";
    javax.crypto.Cipher.getInstance(transform);
  }
}
"""
    )
    findings = JavaParser(tmp_path).parse_file(java)
    assert any(f.crypto.algorithm == "DES" and f.crypto.mode == "ECB" for f in findings)


def test_ast_keeps_existing_literal_and_key_size(tmp_path: Path):
    java = tmp_path / "G.java"
    java.write_text(
        'class G { void t() throws Exception { javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance("AES"); kg.init(256); } }\n'
    )
    findings = JavaParser(tmp_path).parse_file(java)
    assert any(f.crypto.algorithm == "AES" and f.crypto.key_size == 256 for f in findings)


def test_ast_parse_error_does_not_abort_sibling(tmp_path: Path):
    bad = tmp_path / "Bad.java"
    bad.write_text("class Bad { void t() { /* leftover")
    good = tmp_path / "Good.java"
    good.write_text('class Good { void t() throws Exception { javax.crypto.Cipher.getInstance("AES"); } }\n')
    plugin = JavaSourcePlugin()
    findings = plugin.discover(str(tmp_path))
    assert any(getattr(f.crypto, "algorithm", None) == "AES" for f in findings)


def test_extract_events_skips_block_comments():
    source = 'class C { /* Cipher.getInstance("MD5"); */ void t() {} }'
    assert extract_crypto_events(source) == []
