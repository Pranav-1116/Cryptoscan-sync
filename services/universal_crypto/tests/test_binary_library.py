"""§7 binary detection + §6/§8 library fingerprinting."""

from __future__ import annotations

from universal_crypto.binary_engine import (
    BinaryArtifact,
    BinaryCryptoDetector,
    BinaryParser,
    CRYPTO_CONSTANTS,
)
from universal_crypto.library_fingerprints import LibraryFingerprinter


def test_binary_never_certainty_from_string_alone():
    detector = BinaryCryptoDetector()
    # a binary whose ONLY signal is the string "OpenSSL" must be
    # POSSIBLE_CRYPTO, never CONFIRMED (string match = weak evidence)
    artifact = BinaryArtifact(format="elf", path="x.so", strings=["OpenSSL 3.0.0"])
    analysis = detector.analyze(artifact)
    openssl = next(d for d in analysis["detections"] if d["algorithm"] == "OpenSSL")
    assert openssl["verdict"] == "POSSIBLE_CRYPTO"
    assert "STRING_MATCH" in openssl["levels"]


def test_binary_symbol_import_and_constant_confirms():
    detector = BinaryCryptoDetector()
    artifact = BinaryArtifact(
        format="elf", path="libcrypto.so",
        symbols=["EVP_sha256", "EVP_aes_256_gcm"],
        imports=["EVP_DigestInit_ex"],
        constants=[CRYPTO_CONSTANTS["AES"]],
    )
    analysis = detector.analyze(artifact)
    aes = next(d for d in analysis["detections"] if d["algorithm"] == "AES")
    assert aes["best_level"] >= 0.9
    assert aes["verdict"] == "CONFIRMED_IMPLEMENTATION"


def test_tls_record_bytes_are_fingerprint_evidence():
    detector = BinaryCryptoDetector()
    artifact = BinaryArtifact(format="pe", path="svc.exe",
                              constants=[b"\x16\x03\x03"])
    analysis = detector.analyze(artifact)
    assert any(d["algorithm"] == "TLS" and d["best_level"] == 1.0
               for d in analysis["detections"])


def test_elf_parser_extracts_symbols_and_strings():
    import sys
    # parse a real ELF (the interpreter itself) — deterministic artifact
    with open(sys.executable, "rb") as handle:
        data = handle.read()  # section header table sits near EOF
    parser = BinaryParser()
    artifact = parser.parse(data, path=sys.executable)
    assert artifact.format == "elf"
    assert artifact.symbols, "real ELF must expose symbols"


def test_elf_crypto_symbols_confirmed_when_present():
    import os
    candidates = [
        "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/lib/x86_64-linux-gnu/libcrypto.so.3",
    ]
    path = next((p for p in candidates if os.path.exists(p)), None)
    if path is None:
        import pytest
        pytest.skip("no system OpenSSL library to analyze")
    with open(path, "rb") as handle:
        data = handle.read(8 * 1024 * 1024)
    artifact = BinaryParser().parse(data, path=path)
    assert artifact.format == "elf"
    detector = BinaryCryptoDetector()
    analysis = detector.analyze(artifact)
    assert analysis["detections"], "libcrypto must produce crypto detections"
    sha = next((d for d in analysis["detections"]
                if d["algorithm"] in ("SHA-256", "SHA-1", "MD5")), None)
    assert sha is not None


def test_pe_imports_detected():
    parser = BinaryParser()
    data = b"MZ" + b"\x00" * 64 + b"CryptEncrypt\x00" + b"\x00" * 32
    artifact = parser.parse(data, path="x.dll")
    assert artifact.format == "pe"
    assert "CryptEncrypt" in artifact.imports


def test_wasm_symbols_detected():
    parser = BinaryParser()
    data = b"\x00asm" + b"\x01\x00\x00\x00" + b"EVP_sha256" + b"\x00"
    artifact = parser.parse(data, path="x.wasm")
    assert artifact.format == "wasm"
    assert "EVP_sha256" in artifact.imports


# ── §6/§8 library fingerprinting ────────────────────────────────────────────

def test_library_confirmed_with_three_evidence_classes():
    fp = LibraryFingerprinter()
    results = fp.fingerprint(
        imports=["libssl.so", "openssl/ssl.h"],
        symbols=["SSL_CTX_new", "EVP_EncryptInit_ex"],
        strings=["OpenSSL 3.0.13"],
        apis=[],
    )
    openssl = next(r for r in results if r["library"] == "OpenSSL")
    assert openssl["verdict"] == "CONFIRMED_IMPLEMENTATION"
    assert len(openssl["evidence_classes"]) >= 3
    assert openssl["version"] == "3.0.13"


def test_library_possible_with_single_class():
    fp = LibraryFingerprinter()
    results = fp.fingerprint(imports=["org.bouncycastle.jce.provider.BouncyCastleProvider"])
    bc = next(r for r in results if r["library"] == "BouncyCastle")
    assert bc["verdict"] == "POSSIBLE_CRYPTO"


def test_algorithms_exposed_vs_referenced():
    fp = LibraryFingerprinter()
    result = fp.algorithms_referenced(
        library="OpenSSL", symbols=["EVP_sha256"], apis=["EVP_EncryptInit_ex"])
    assert "SHA-256" in result["algorithms_referenced"]
    assert "AES" in result["algorithms_exposed"]
