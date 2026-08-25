from scanner.core.language_detector import detect_languages_in_repo
from scanner.detectors.java.mac_detector import MacDetector
from scanner.detectors.python.secrets_misuse_detector import detect as detect_secrets_misuse
from scanner.parsers.go_parser import parse_go_file
from scanner.parsers.js_ts_parser import parse_js_ts_file
from scanner.parsers.php_parser import parse_php_file
from scanner.parsers.ruby_parser import parse_ruby_file
from scanner.parsers.rust_parser import parse_rust_file
from scanner.registry.language_scanners import scan_file


def test_go_parser_finds_md5_aes_and_weak_tls(temp_workspace):
    path = temp_workspace / "crypto.go"
    path.write_text(
        """
package main
import (
  "crypto/md5"
  "crypto/aes"
  "crypto/tls"
  "crypto/rsa"
)
func main() {
  md5.Sum(nil)
  aes.NewGCM(block)
  tls.VersionTLS10
  rsa.GenerateKey(rand.Reader, 1024)
}
"""
    )
    findings = parse_go_file(path, temp_workspace)
    algos = {f.crypto.algorithm for f in findings}
    assert "MD5" in algos
    assert "AES" in algos
    assert "TLS1.0" in algos
    rsa = next(f for f in findings if f.crypto.algorithm == "RSA")
    assert rsa.crypto.key_size == 1024


def test_php_parser_finds_openssl_and_md5(temp_workspace):
    path = temp_workspace / "crypto.php"
    path.write_text(
        """<?php
openssl_encrypt($data, 'AES-256-CBC', $key);
md5($password);
hash('sha1', $x);
password_hash($pw, PASSWORD_BCRYPT);
"""
    )
    findings = parse_php_file(path, temp_workspace)
    algos = {f.crypto.algorithm for f in findings}
    assert "AES" in algos
    assert "MD5" in algos
    assert "SHA-1" in algos
    assert "BCRYPT" in algos
    aes = next(f for f in findings if f.crypto.algorithm == "AES")
    assert aes.crypto.mode == "CBC"


def test_ruby_and_rust_parsers(temp_workspace):
    rb = temp_workspace / "crypto.rb"
    rb.write_text("Digest::MD5.hexdigest(x)\nOpenSSL::Cipher.new('AES-256-GCM')\n")
    rs = temp_workspace / "crypto.rs"
    rs.write_text("let d = Md5::digest(b\"x\");\nlet a = Aes256Gcm::new(&key);\n")
    ruby = parse_ruby_file(rb, temp_workspace)
    rust = parse_rust_file(rs, temp_workspace)
    assert {f.crypto.algorithm for f in ruby} >= {"MD5", "AES"}
    assert {f.crypto.algorithm for f in rust} >= {"MD5", "AES"}


def test_registry_and_language_detect(temp_workspace):
    go = temp_workspace / "a.go"
    go.write_text("package p\nfunc f() { md5.Sum(nil) }\n")
    found = detect_languages_in_repo(temp_workspace)
    assert "GO" in found
    findings = scan_file(go, temp_workspace)
    assert any(f.crypto.algorithm == "MD5" for f in findings)


def test_js_ts_parser_and_named_detectors(temp_workspace):
    js = temp_workspace / "crypto.js"
    js.write_text("const crypto = require('crypto');\ncrypto.createHash('md5');\n")
    findings = parse_js_ts_file(js, temp_workspace)
    assert any((f.crypto.algorithm or "").upper() in {"MD5"} for f in findings)
    py = temp_workspace / "bad.py"
    py.write_text("import random\nkey = b'1234567890abcdef'\n")
    detect_secrets_misuse(py, temp_workspace)
    assert MacDetector().name() == "java-mac"
