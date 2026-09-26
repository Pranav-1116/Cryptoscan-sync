"""PE / .NET assembly scanner — synthetic PE files (no dotnet SDK in CI)."""
from __future__ import annotations

import struct
from pathlib import Path

from scanner.detectors.dotnet.assembly_scanner import analyse_dotnet, scan_assembly, scan_assembly_bytes

_SECT_RVA = 0x2000
_FILE_ALIGN = 0x200


def _us_heap(strings: list[str]) -> bytes:
    out = bytearray(b"\0")
    for s in strings:
        enc = s.encode("utf-16-le") + b"\0"
        n = len(enc)
        if n < 0x80:
            out += bytes([n])
        else:
            out += bytes([0x80 | (n >> 8), n & 0xFF])
        out += enc
    return bytes(out)


def _metadata(strings: list[str], user: list[str]) -> bytes:
    sheap = b"\0" + b"".join(s.encode() + b"\0" for s in strings)
    uheap = _us_heap(user)
    version = b"v4.0.30319\0\0"
    header = b"BSJB" + struct.pack("<HHII", 1, 1, 0, len(version)) + version + struct.pack("<HH", 0, 2)
    # stream headers: offset, size, name (padded to 4)
    hdrs_len = 2 * 8 + 12 + 4  # "#Strings\0" -> 9 -> pad 12 ; "#US\0" -> 4
    off = len(header) + hdrs_len
    sh = struct.pack("<II", off, len(sheap)) + b"#Strings\0\0\0\0"
    sh += struct.pack("<II", off + len(sheap), len(uheap)) + b"#US\0"
    return header + sh + sheap + uheap


def _pe(section: bytes, cli_rva: int | None, import_rva: int | None, import_size: int = 0) -> bytes:
    dos = bytearray(0x40)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    opt_size = 224
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, opt_size, 0x2102)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x10B)
    struct.pack_into("<I", opt, 92, 16)  # NumberOfRvaAndSizes
    dd = 96
    if import_rva is not None:
        struct.pack_into("<II", opt, dd + 8 * 1, import_rva, import_size)
    if cli_rva is not None:
        struct.pack_into("<II", opt, dd + 8 * 14, cli_rva, 72)
    headers_len = 0x40 + 4 + len(coff) + opt_size + 40
    raw_ptr = (headers_len + _FILE_ALIGN - 1) // _FILE_ALIGN * _FILE_ALIGN
    sect = b".text\0\0\0" + struct.pack("<IIIIIIHHI", len(section), _SECT_RVA, len(section), raw_ptr, 0, 0, 0, 0, 0x60000020)
    body = bytes(dos) + b"PE\0\0" + coff + bytes(opt) + sect
    body += b"\0" * (raw_ptr - len(body))
    return body + section


def build_dotnet_assembly(strings: list[str], user: list[str]) -> bytes:
    md = _metadata(strings, user)
    cli_off = 0
    md_off = 72
    cli = struct.pack("<IHHIIIII", 72, 2, 5, _SECT_RVA + md_off, len(md), 1, 0, 0) + b"\0" * (72 - 28)
    section = cli + md
    return _pe(section, _SECT_RVA + cli_off, None)


def build_native_dll(imports: dict[str, list[str]]) -> bytes:
    # layout: [descriptors][names][hint/name entries][thunks]
    ndesc = len(imports)
    desc_size = 20 * (ndesc + 1)
    blob = bytearray()
    names_off = desc_size
    names = bytearray()
    hn = bytearray()
    thunks = bytearray()
    descs = []
    # first pass compute sizes
    total_names = sum(len(d) + 1 for d in imports)
    hn_off = names_off + total_names
    total_hn = sum(sum(2 + len(s) + 1 + ((len(s) + 1) % 2) for s in syms) for syms in imports.values())
    thunk_off = hn_off + total_hn
    cur_hn = hn_off
    cur_thunk = thunk_off
    for dll, syms in imports.items():
        name_rva = _SECT_RVA + names_off + len(names)
        names += dll.encode() + b"\0"
        oft_rva = _SECT_RVA + cur_thunk
        for s in syms:
            hn_rva = _SECT_RVA + cur_hn
            entry = struct.pack("<H", 0) + s.encode() + b"\0"
            if len(entry) % 2:
                entry += b"\0"
            hn += entry
            cur_hn += len(entry)
            thunks += struct.pack("<I", hn_rva)
            cur_thunk += 4
        thunks += struct.pack("<I", 0)
        cur_thunk += 4
        descs.append(struct.pack("<IIIII", oft_rva, 0, 0, name_rva, oft_rva))
    descs.append(b"\0" * 20)
    blob = b"".join(descs) + bytes(names) + bytes(hn) + bytes(thunks)
    return _pe(blob, None, _SECT_RVA, desc_size)


def _algos(findings):
    return {f.crypto.algorithm for f in findings}


def test_dotnet_types_are_gated_by_namespace():
    strings = ["System.Security.Cryptography", "Aes", "SHA256", "Rfc2898DeriveBytes", "RSACryptoServiceProvider", "System.Net.Security", "SslStream"]
    found = analyse_dotnet(strings, [])
    algos = {a for _, a, *_ in found}
    assert {"AES", "SHA-256", "PBKDF2", "RSA", "TLS"} <= algos
    # same identifiers without the namespace: nothing
    assert analyse_dotnet(["Aes", "SHA256", "RSA", "MyBank.Core"], []) == []


def test_user_strings_jwt_oid_xmldsig_and_cryptoconfig():
    strings = ["System.Security.Cryptography"]
    user = ["HS256", "1.2.840.113549.1.1.11", "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", "System.Security.Cryptography.MD5CryptoServiceProvider", "Hello world", "Tls12"]
    algos = {a for _, a, *_ in analyse_dotnet(strings, user)}
    assert {"HS256", "3DES", "MD5", "TLS1.2"} <= algos
    assert any(a.startswith("SHA256") and "RSA" in a for a in algos)


def test_full_assembly_roundtrip(tmp_path: Path):
    blob = build_dotnet_assembly(["System.Security.Cryptography", "TripleDESCryptoServiceProvider", "MD5", "Org.BouncyCastle.Crypto.Engines", "RC4Engine"], ["AES/CBC/PKCS7", "RS256"])
    p = tmp_path / "vendor" / "Legacy.Payments.dll"
    p.parent.mkdir()
    p.write_bytes(blob)
    findings = scan_assembly(p, tmp_path)
    assert {"3DES", "MD5", "RC4", "AES", "RS256"} <= _algos(findings)
    assert all(f.metadata.code_origin == "archive" for f in findings)
    assert all(f.source.file_path.startswith("vendor/Legacy.Payments.dll!") for f in findings)
    assert all(f.source.line_number == 0 for f in findings)


def test_native_dll_import_table():
    blob = build_native_dll({"bcrypt.dll": ["BCryptEncrypt", "BCryptGenRandom"], "libcrypto-3.dll": ["EVP_aes_256_gcm", "PKCS5_PBKDF2_HMAC", "SSL_CTX_new", "RAND_bytes"], "kernel32.dll": ["CreateFileW"]})
    findings = scan_assembly_bytes(blob, "bin/native.dll")
    algos = _algos(findings)
    assert {"AES", "PBKDF2", "TLS", "CSPRNG"} <= algos
    assert "UNKNOWN" in algos  # BCryptEncrypt without algorithm evidence
    assert not any("CreateFileW" in f.source.file_path for f in findings)


def test_non_pe_and_truncated_inputs_are_silent(tmp_path: Path):
    assert scan_assembly_bytes(b"not a pe at all", "x.dll") == []
    assert scan_assembly_bytes(b"MZ" + b"\0" * 10, "x.dll") == []
    blob = build_dotnet_assembly(["System.Security.Cryptography", "Aes"], [])
    assert scan_assembly_bytes(blob[: len(blob) // 2], "half.dll") == []


def test_registry_dispatches_dll(tmp_path: Path):
    from scanner.registry.language_scanners import scan_file

    p = tmp_path / "App.exe"
    p.write_bytes(build_dotnet_assembly(["System.Security.Cryptography", "DESCryptoServiceProvider"], []))
    assert _algos(scan_file(p, tmp_path)) == {"DES"}
