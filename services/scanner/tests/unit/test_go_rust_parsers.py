"""Go + Rust parser coverage — pinned against representative crypto code.

These tests freeze the languages' detection contracts: weak primitives
(MD5/SHA-1/DES/RC4), key-size extraction, TLS floor versions and the
2026-09 rust fixes (openssl::sha::* coverage, per-algorithm ring digest
labeling, Rsa::generate bits).
"""

from __future__ import annotations

from pathlib import Path

from scanner.parsers.go_parser import parse_go_file
from scanner.parsers.rust_parser import parse_rust_file


def _scan(parser, name: str, code: str) -> list:
    with tempfile_directory() as td:
        path = Path(td) / name
        path.write_text(code)
        return parser(path, Path(td))


def tempfile_directory():
    import tempfile

    return tempfile.TemporaryDirectory()


def _summary(findings) -> set[tuple]:
    return {(f.crypto.api_type, f.crypto.algorithm, f.source.line_number)
            for f in findings}


GO_CODE = """package main

import (
\t"crypto/aes"
\t"crypto/des"
\t"crypto/md5"
\t"crypto/rc4"
\t"crypto/rsa"
\t"crypto/sha1"
\t"crypto/sha256"
\t"crypto/tls"
)

func main() {
\t_ = md5.New()
\t_ = sha1.New()
\t_ = des.NewCipher(nil)
\t_, _ = rc4.NewCipher(nil)
\t_ = rsa.GenerateKey(nil, 1024)
\t_ = aes.NewCipher(nil)
\t_ = sha256.New()
\t_ = tls.Config{MinVersion: tls.VersionTLS11}
}
"""


def test_go_weak_and_strong_primitives():
    got = _summary(_scan(parse_go_file, "main.go", GO_CODE))
    # weak primitives are named exactly
    assert ("MESSAGE_DIGEST", "MD5", 15) in got
    assert ("MESSAGE_DIGEST", "SHA-1", 16) in got
    assert ("CIPHER_INSTANCE", "DES", 17) in got
    assert ("CIPHER_INSTANCE", "RC4", 18) in got
    # modern primitives still inventoried
    assert ("CIPHER_INSTANCE", "AES", 20) in got
    assert ("MESSAGE_DIGEST", "SHA-256", 21) in got
    # legacy TLS floor surfaced
    assert any(api == "KEY_AGREEMENT" and "TLS1.1" in str(alg)
               for api, alg, _ in got)


def test_go_rsa_key_size_extracted():
    findings = _scan(parse_go_file, "main.go", GO_CODE)
    rsa = [f for f in findings if f.crypto.algorithm == "RSA"
           and f.crypto.api_type == "KEY_PAIR_GENERATOR"]
    assert rsa, "rsa.GenerateKey must be detected"
    assert rsa[0].crypto.key_size == 1024  # the quantum-relevant fact


RUST_CODE = """use aes::Aes128;
use des::Des;
use md-5::Md5;
use openssl::rsa::Rsa;
use openssl::sha::sha1;
use ring::digest::SHA1;
use ring::digest::SHA256;
use rc4::Rc4;

fn main() {
    let _ = Rsa::generate(2048);
    let _h = sha1(b"x");
    let _a = SHA1.digest(b"y");
    let _b = SHA256.digest(b"z");
}
"""


def test_rust_openssl_sha_and_ring_labels():
    got = _summary(_scan(parse_rust_file, "m.rs", RUST_CODE))
    # the 2026-09 gap: openssl::sha::sha1 was previously invisible
    assert ("MESSAGE_DIGEST", "SHA-1", 5) in got
    # ring digests carry their OWN algorithm now (SHA-1 was mislabeled SHA-256)
    assert ("MESSAGE_DIGEST", "SHA-1", 6) in got
    assert ("MESSAGE_DIGEST", "SHA-256", 7) in got
    assert not any(alg == "SHA-256" and line == 6
                   for api, alg, line in got if api == "MESSAGE_DIGEST")


def test_rust_crates_and_rsa_bits():
    got = _summary(_scan(parse_rust_file, "m.rs", RUST_CODE))
    assert ("CIPHER_INSTANCE", "AES", 1) in got
    assert ("CIPHER_INSTANCE", "DES", 2) in got
    assert ("CIPHER_INSTANCE", "RC4", 8) in got
    assert any(api == "KEY_PAIR_GENERATOR" and alg == "RSA"
               for api, alg, _ in got)
    findings = _scan(parse_rust_file, "m.rs", RUST_CODE)
    rsa_bits = [f.crypto.key_size for f in findings
                if f.crypto.key_size is not None]
    assert 2048 in rsa_bits  # Rsa::generate(2048)


def test_rust_clean_file_is_silent():
    got = _scan(parse_rust_file, "clean.rs",
                "fn main() { println!(\"no crypto here\"); }\n")
    assert got == []
