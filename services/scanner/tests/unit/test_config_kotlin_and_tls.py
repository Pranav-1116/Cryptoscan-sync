from pathlib import Path

from scanner.core.scanner import Scanner
from scanner.parsers.config_crypto_parser import parse_config_file, scan_config_tree
from scanner.parsers.java_parser import parse_java_file
from scanner.parsers.kotlin_parser import parse_kotlin_file
from scanner.parsers.python_parser import parse_python_file
from scanner.registry.language_scanners import scan_file


def test_nginx_and_jwt_config(tmp_path: Path):
    nginx = tmp_path / "nginx.conf"
    nginx.write_text("ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\nssl_ciphers HIGH:!aNULL;\n")
    app = tmp_path / "application.yml"
    app.write_text("jwt.secret: super-secret-demo-key\nserver.ssl.enabled-protocols: TLSv1.1\n")
    env = tmp_path / ".env"
    env.write_text("JWT_SECRET=local-dev-token-value\n")
    findings = scan_config_tree(tmp_path, tmp_path)
    algos = {item.crypto.algorithm for item in findings}
    assert "TLS1.0" in algos
    assert "TLS1.1" in algos
    assert any(item.metadata.is_hardcoded_key for item in findings)


def test_terraform_tls_private_key(tmp_path: Path):
    tf = tmp_path / "keys.tf"
    tf.write_text(
        """
resource "tls_private_key" "leaf" {
  algorithm = "RSA"
  rsa_bits  = 1024
}
resource "aws_kms_key" "pay" {
  customer_master_key_spec = "RSA_2048"
}
"""
    )
    findings = parse_config_file(tf, tmp_path)
    rsa = next(item for item in findings if item.crypto.algorithm == "RSA" and item.crypto.key_size == 1024)
    assert rsa.crypto.purpose == "KEY_GENERATION"
    kms = next(item for item in findings if item.metadata.library == "aws-kms")
    assert kms.crypto.key_size == 2048


def test_kotlin_cipher_and_registry(tmp_path: Path):
    kt = tmp_path / "Crypto.kt"
    kt.write_text(
        """
import javax.crypto.Cipher
fun encrypt() {
    Cipher.getInstance("AES/GCM/NoPadding")
    java.security.MessageDigest.getInstance("MD5")
}
"""
    )
    findings = parse_kotlin_file(kt, tmp_path)
    assert any(item.source.language == "KOTLIN" and item.crypto.algorithm == "AES" for item in findings)
    assert any(item.crypto.algorithm == "MD5" for item in findings)
    via_registry = scan_file(kt, tmp_path)
    assert {item.crypto.algorithm for item in via_registry} >= {"AES", "MD5"}


def test_java_trust_all_and_python_weak_tls(tmp_path: Path):
    java = tmp_path / "Trust.java"
    java.write_text(
        """
import javax.net.ssl.*;
class Trust {
  void bad() {
    HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> true);
    public void checkServerTrusted(X509Certificate[] c, String a) {}
  }
}
"""
    )
    java_findings = parse_java_file(java, tmp_path)
    assert any(item.crypto.algorithm in {"TLS", "TRUST-ALL"} for item in java_findings)
    py = tmp_path / "tls.py"
    py.write_text("import ssl\nctx = ssl._create_unverified_context()\nproto = ssl.PROTOCOL_TLSv1\n")
    py_findings = parse_python_file(py, tmp_path)
    algos = {item.crypto.algorithm for item in py_findings}
    assert "TLS-UNVERIFIED" in algos
    assert "TLS1.0" in algos


def test_live_scanner_picks_up_config_and_kotlin(tmp_path: Path):
    (tmp_path / "Pay.kt").write_text('fun e() { javax.crypto.Cipher.getInstance("DES"); }\n')
    (tmp_path / "site.conf").write_text("ssl_protocols TLSv1;\n")
    result = Scanner().scan(tmp_path)
    algos = {item.crypto.algorithm for item in result.findings}
    assert "DES" in algos
    assert "TLS1.0" in algos
    assert result.statistics.total_findings >= 2


def test_parser_serialization_withholds_transient_source_text(tmp_path: Path):
    config = tmp_path / "application.yml"
    config.write_text("jwt.secret: synthetic-key-value-for-test\n")
    finding = parse_config_file(config, tmp_path)[0]
    assert finding.source.code_snippet  # still available for detector analysis
    assert "synthetic-key-value-for-test" not in finding.model_dump_json()


def test_scanner_output_never_contains_source_or_adjacent_secret(tmp_path: Path):
    (tmp_path / "application.yml").write_text(
        "jwt.secret: synthetic-key-value-for-test\n"
        "ssl_protocols TLSv1.1;\n"
        "unrelated_password: another-synthetic-value\n"
    )
    result = Scanner().scan(tmp_path)
    assert any(finding.metadata.is_hardcoded_key for finding in result.findings)
    assert any(finding.crypto.algorithm == "TLS1.1" for finding in result.findings)
    serialized = result.model_dump_json()
    assert "synthetic-key-value-for-test" not in serialized
    assert "another-synthetic-value" not in serialized
    assert all(finding.source.code_snippet is None for finding in result.findings)
