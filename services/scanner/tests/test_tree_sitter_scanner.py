"""Tree-sitter deep parsers — CST-based crypto API detection."""

from __future__ import annotations

from pathlib import Path

import pytest

from scanner.parsers.tree_sitter_scanner import (
    EXT_TO_LANGUAGE,
    scan_tree_sitter_file,
    tree_sitter_available,
)

pytestmark = pytest.mark.skipif(
    not tree_sitter_available(), reason="tree-sitter wheels not installed"
)


def _scan(tmp_path: Path, name: str, source: str):
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    return scan_tree_sitter_file(path, tmp_path)


def _algo_set(findings) -> set[str]:
    return {f.crypto.algorithm for f in findings if f.crypto and f.crypto.algorithm}


def test_java_cipher_getinstance(tmp_path):
    findings = _scan(
        tmp_path,
        "Weak.java",
        """
import javax.crypto.Cipher;
class Weak {
  byte[] run() throws Exception {
    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    Cipher d = Cipher.getInstance("DES/ECB/PKCS5Padding");
    return c.doFinal(new byte[0]);
  }
}
""",
    )
    algos = _algo_set(findings)
    assert "AES" in algos and "DES" in algos
    aes = next(f for f in findings if f.crypto.algorithm == "AES")
    assert aes.crypto.mode == "GCM"
    assert aes.metadata.library == "javax.crypto"
    assert aes.scanner_id == "tree-sitter-scanner-v1.0"
    des = next(f for f in findings if f.crypto.algorithm == "DES")
    assert des.crypto.mode == "ECB"
    assert des.source.language == "JAVA"  # flows into evidence as a normal finding


def test_java_message_digest(tmp_path):
    findings = _scan(
        tmp_path,
        "Digest.java",
        """
import java.security.MessageDigest;
class Digest {
  byte[] go() throws Exception {
    return MessageDigest.getInstance("MD5").digest(new byte[0]);
  }
}
""",
    )
    assert "MD5" in _algo_set(findings)


def test_python_hashlib_and_pycryptodome(tmp_path):
    findings = _scan(
        tmp_path,
        "crypto.py",
        """
import hashlib
from Crypto.Cipher import AES, ARC4

def go():
    h = hashlib.new("md5")
    h2 = hashlib.md5()
    h3 = hashlib.sha256()
    cipher = AES.new(b"0"*32, AES.MODE_GCM)
    weak = ARC4.new(b"key")
    return h, h2, h3, cipher, weak
""",
    )
    algos = _algo_set(findings)
    assert "MD5" in algos          # hashlib.new("md5")
    assert "SHA-256" in algos      # hashlib.sha256()
    assert "AES" in algos          # AES.new
    assert "RC4" in algos          # ARC4.new
    aes = next(f for f in findings if f.crypto.algorithm == "AES")
    assert aes.crypto.mode == "GCM"
    assert aes.metadata.library == "pycryptodome"


def test_csharp_creates(tmp_path):
    findings = _scan(
        tmp_path,
        "Crypto.cs",
        """
using System.Security.Cryptography;
class Crypto {
  void go() {
    var aes = Aes.Create();
    var sha1 = SHA1.Create();
    var rsa = RSA.Create(2048);
    var hmac = new HMACSHA256();
  }
}
""",
    )
    algos = _algo_set(findings)
    assert "AES" in algos
    assert "SHA-1" in algos
    assert "RSA" in algos
    rsa = next(f for f in findings if f.crypto.algorithm == "RSA")
    assert rsa.crypto.key_size == 2048
    assert "HmacSHA256" in algos  # object creation
    assert rsa.metadata.library == "System.Security.Cryptography"


def test_go_packages(tmp_path):
    findings = _scan(
        tmp_path,
        "crypto.go",
        """
package main
import (
  "crypto/aes"
  "crypto/md5"
  "crypto/rsa"
)
func go() {
  block, _ := aes.NewCipher([]byte("0123456789abcdef"))
  h := md5.New()
  key, _ := rsa.GenerateKey(nil, 2048)
  _ = block; _ = h; _ = key
}
""",
    )
    algos = _algo_set(findings)
    assert "AES" in algos
    assert "MD5" in algos
    assert "RSA" in algos
    rsa = next(f for f in findings if f.crypto.algorithm == "RSA")
    assert rsa.crypto.key_size == 2048


def test_javascript_node_crypto(tmp_path):
    findings = _scan(
        tmp_path,
        "crypto.js",
        """
const crypto = require("crypto");
const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
const md5 = crypto.createHash("md5");
const hmac = crypto.createHmac("sha256", secret);
""",
    )
    algos = _algo_set(findings)
    assert "AES" in algos
    assert "MD5" in algos
    cipher = next(f for f in findings if f.crypto.algorithm == "AES")
    assert cipher.crypto.key_size == 256
    assert cipher.crypto.mode == "GCM"


def test_rust_aes_and_sha(tmp_path):
    findings = _scan(
        tmp_path,
        "crypto.rs",
        """
use aes_gcm::{Aes256Gcm, KeyInit};
use sha2::{Sha256, Digest};

fn go() {
    let cipher = Aes256Gcm::new_from_slice(b"0123456789abcdef0123456789abcdef").unwrap();
    let mut hasher = Sha256::new();
    hasher.update(b"data");
}
""",
    )
    algos = _algo_set(findings)
    assert "AES" in algos
    assert "SHA-256" in algos or "SHA256" in algos
    aes = next(f for f in findings if f.crypto.algorithm == "AES")
    assert aes.crypto.mode == "GCM"


def test_ruby_openssl(tmp_path):
    findings = _scan(
        tmp_path,
        "crypto.rb",
        """
require "openssl"
require "digest"
cipher = OpenSSL::Cipher.new("aes-256-gcm")
digest = Digest::MD5.hexdigest("data")
""",
    )
    algos = _algo_set(findings)
    assert "AES" in algos
    assert "MD5" in algos
    aes = next(f for f in findings if f.crypto.algorithm == "AES")
    assert aes.crypto.key_size == 256 and aes.crypto.mode == "GCM"


def test_php_openssl_functions(tmp_path):
    findings = _scan(
        tmp_path,
        "crypto.php",
        """
<?php
$enc = openssl_encrypt($data, "aes-256-gcm", $key);
$h = hash("md5", $data);
$mac = hash_hmac("sha256", $data, $key);
""",
    )
    algos = _algo_set(findings)
    assert "AES" in algos
    assert "MD5" in algos
    assert "SHA-256" in algos or "SHA256" in algos


def test_deterministic_and_no_double_count(tmp_path):
    source = 'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");\n'
    findings = _scan(tmp_path, "One.java", "class One { void go() throws Exception { " + source + " } }")
    aes = [f for f in findings if f.crypto.algorithm == "AES"]
    assert len(aes) == 1


def test_language_map_covers_catalog():
    # Every catalog language has a grammar mapping and call node types
    from scanner.parsers.tree_sitter_scanner import (
        CALL_NODE_TYPES,
        CATALOG,
        LANGUAGE_GRAMMAR,
    )

    for lang in CATALOG:
        assert lang in LANGUAGE_GRAMMAR, lang
        assert lang in CALL_NODE_TYPES, lang
        assert lang in EXT_TO_LANGUAGE.values() or lang in ("javascript", "typescript")


def test_plain_code_no_false_positives(tmp_path):
    findings = _scan(
        tmp_path,
        "Plain.java",
        """
class Plain {
  int add(int a, int b) { return a + b; }
  String greet() { return "hello"; }
}
""",
    )
    assert findings == []
