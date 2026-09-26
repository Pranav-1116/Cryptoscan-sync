"""Android APK / DEX and iOS IPA / Mach-O packages without source."""
import io
import struct
import zipfile
from pathlib import Path

from scanner.detectors.mobile.mobile_binary_scanner import analyse_native, dex_tables, scan_mobile_package
from scanner.registry.language_scanners import scan_file


def _mutf8(s: str) -> bytes:
    b = s.encode("utf-8")
    return bytes([len(s)]) + b + b"\0"  # uleb128 length < 128 for our strings


def make_dex(strings: list[str]) -> bytes:
    """Minimal DEX: header + string_ids + type_ids (every 'L...;' string is a type) + string data."""
    header = bytearray(0x70)
    header[:8] = b"dex\n035\0"
    n = len(strings)
    string_ids_off = 0x70
    type_strings = [i for i, s in enumerate(strings) if s.startswith("L") and s.endswith(";")]
    type_ids_off = string_ids_off + 4 * n
    data_off = type_ids_off + 4 * len(type_strings)
    blobs, offs, cur = [], [], data_off
    for s in strings:
        offs.append(cur)
        blob = _mutf8(s)
        blobs.append(blob)
        cur += len(blob)
    struct.pack_into("<IIII", header, 0x38, n, string_ids_off, len(type_strings), type_ids_off)
    body = b"".join(struct.pack("<I", o) for o in offs) + b"".join(struct.pack("<I", i) for i in type_strings) + b"".join(blobs)
    return bytes(header) + body


def make_apk(tmp_path: Path, dex: bytes, so: bytes | None = None) -> Path:
    p = tmp_path / "bank-mobile.apk"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("classes.dex", dex)
        z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
        if so:
            z.writestr("lib/arm64-v8a/libnative.so", so)
    return p


def make_ipa(tmp_path: Path, binary: bytes, plist: bytes) -> Path:
    p = tmp_path / "BankApp.ipa"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("Payload/BankApp.app/BankApp", binary)
        z.writestr("Payload/BankApp.app/Info.plist", plist)
        z.writestr("Payload/BankApp.app/Assets.car", b"\x00" * 64)
    return p


def _algos(findings):
    return {f.crypto.algorithm for f in findings}


def test_dex_tables_and_apk(tmp_path):
    dex = make_dex(["Ljavax/crypto/Cipher;", "Ljava/security/MessageDigest;", "Lcom/bank/app/Login;", "AES/GCM/NoPadding", "SHA-256", "HmacSHA256", "TLSv1.2", "hello world"])
    classes, strings = dex_tables(dex)
    assert "javax/crypto/Cipher" in classes and "AES/GCM/NoPadding" in strings
    apk = make_apk(tmp_path, dex, so=b"\x7fELF" + b"\0" * 12 + b"\0EVP_aes_256_gcm\0PKCS5_PBKDF2_HMAC\0SSL_CTX_new\0")
    fs = scan_file(apk, tmp_path)
    got = _algos(fs)
    assert {"AES", "SHA-256", "HMAC", "TLS1.2", "PBKDF2", "TLS"} <= got, got
    assert all(f.source.type == "BINARY" and f.metadata.code_origin == "archive" for f in fs)
    assert any(f.source.file_path.endswith("!classes.dex") for f in fs)
    assert any(f.source.file_path.endswith("libnative.so") for f in fs)


def test_dex_without_crypto_api_is_silent(tmp_path):
    dex = make_dex(["Lcom/bank/app/Login;", "Landroid/app/Activity;", "username", "AES", "SHA-256"])  # bare names, no crypto class
    assert scan_mobile_package(make_apk(tmp_path, dex), tmp_path) == []


def test_ipa_macho_and_plist(tmp_path):
    macho = b"\xcf\xfa\xed\xfe" + b"\0" * 28 + b"\0_CCCrypt\0_kCCAlgorithm3DES\0_CC_SHA1\0_SecKeyCreateSignature\0_kSecAttrKeyTypeRSA\0$s9CryptoKit3AESO3GCMO4openWq\0$s9CryptoKit6SHA256V\0_SecRandomCopyBytes\0"
    plist = b'<plist><dict><key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/><key>NSExceptionMinimumTLSVersion</key><string>TLSv1.0</string></dict></dict></plist>'
    fs = scan_file(make_ipa(tmp_path, macho, plist), tmp_path)
    got = _algos(fs)
    assert {"3DES", "SHA-1", "RSA", "AES", "SHA-256", "CSPRNG", "TLS"} <= got, got
    libs = {f.metadata.library for f in fs}
    assert "CommonCrypto" in libs and "CryptoKit" in libs and "App-Transport-Security" in libs


def test_native_noise_is_ignored():
    # ordinary strings that look nothing like crypto symbols
    assert analyse_native(b"\x7fELF" + b"\0EC\0DH\0Hello, world\0/system/lib64/libc.so\0printf\0") == []
