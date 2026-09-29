"""§7 Binary crypto detection.

ELF / PE / Mach-O / WASM / firmware / shared libraries / static binaries:
extract imports, exports, symbols, strings, constants, known implementation
fingerprints and crypto tables — then score evidence levels.

Hard rule: **binary detection never claims certainty from a string match
alone.** Each artifact signal is tagged with an evidence level:

    STRING_MATCH    (weak — a string can sit in documentation data)
    SYMBOL_MATCH    (stronger — an exported/imported symbol)
    CONSTANT_MATCH  (strong — algorithm-specific tables/constants)
    FINGERPRINT     (strongest — known-implementation signature)

The §28 fusion engine turns combinations of these into confidence.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


import re
import struct
from typing import Any, Iterable, Optional

#: evidence levels (weight used by the fusion engine)
LEVEL_WEIGHT = {
    "STRING_MATCH": 0.4,
    "SYMBOL_MATCH": 0.7,
    "IMPORT_MATCH": 0.8,
    "CONSTANT_MATCH": 0.9,
    "FINGERPRINT": 1.0,
}

#: crypto constant fingerprints (first bytes of well-known tables/headers)
CRYPTO_CONSTANTS: dict[str, bytes] = {
    "AES": b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5",          # AES S-box (first 8 bytes)
    "SHA-256": b"\x6a\x09\xe6\x67\xbb\x67\xae\x85",      # SHA-256 K[0..1]
    "SHA-1": b"\x67\x45\x23\x01\xef\xcd\xab\x89",        # SHA-1 H0..H1
    "MD5": b"\x01\x23\x45\x67\x89\xab\xcd\xef",          # MD5 A..B init
    "SHA-512": b"\x6a\x09\xe6\x67\xf3\xbc\xc9\x08",      # SHA-512 H0..H1
    "ChaCha20": b"expand 32-byte k",                     # ChaCha20 constant
    "BLAKE3": b"BLAKE3",                                  # BLAKE3 IV marker (text)
}

#: known-implementation fingerprints (library signature in binary strings)
IMPLEMENTATION_FINGERPRINTS: dict[str, tuple[str, ...]] = {
    "OpenSSL": ("OpenSSL 1.", "OpenSSL 3.", "libcrypto.so", "libssl.so"),
    "LibreSSL": ("LibreSSL", "libtls"),
    "BoringSSL": ("BoringSSL", "boringssl"),
    "wolfSSL": ("wolfSSL", "wolfssl"),
    "mbedTLS": ("mbedtls_", "Mbed TLS", "mbed TLS"),
    "Botan": ("Botan", "libbotan"),
    "libsodium": ("libsodium", "sodium_"),
    "Crypto++": ("cryptopp", "CryptoPP"),
    "GnuTLS": ("gnutls", "GnuTLS"),
}

#: symbol-name → algorithm (imports/exports catalogs)
SYMBOL_ALGORITHMS: dict[str, str] = {
    "EVP_sha256": "SHA-256", "EVP_sha1": "SHA-1", "EVP_md5": "MD5",
    "EVP_aes_256_gcm": "AES-GCM", "EVP_aes_128_cbc": "AES-CBC",
    "EVP_chacha20_poly1305": "ChaCha20-Poly1305",
    "RSA_sign": "RSA", "RSA_verify": "RSA", "EVP_PKEY_keygen": "RSA",
    "ECDSA_sign": "ECDSA", "ECDSA_do_sign": "ECDSA",
    "EVP_PKEY_derive": "ECDH", "DH_generate_key": "DH",
    "EVP_DigestSign": "RSA", "EVP_DigestVerify": "RSA",
    "mbedtls_sha256": "SHA-256", "mbedtls_sha1": "SHA-1", "mbedtls_md5": "MD5",
    "mbedtls_aes_crypt_cbc": "AES-CBC", "mbedtls_aes_crypt_gcm": "AES-GCM",
    "mbedtls_rsa_pkcs1_sign": "RSA", "mbedtls_ecdsa_sign": "ECDSA",
    "mbedtls_ssl_handshake": "TLS",
    "crypto_secretbox_easy": "ChaCha20-Poly1305",
    "crypto_sign_detached": "Ed25519", "crypto_box_easy": "X25519",
    "crypto_pwhash": "Argon2",
    "sodium_init": "libsodium",
    "bcrypt": "bcrypt",
    "CRYPT_Encrypt": "RSA", "CryptEncrypt": "RSA", "BCryptEncrypt": "AES",
    "MD5Init": "MD5", "MD5Update": "MD5", "MD5Final": "MD5",
    "SHA256_Init": "SHA-256", "SHA1_Init": "SHA-1",
    "RAND_bytes": "CSPRNG", "RAND_poll": "CSPRNG",
}

#: TLS record/version bytes (fingerprint-level evidence)
_TLS_BYTES = (b"\x16\x03\x03", b"\x16\x03\x01", b"\x16\x03\x04")


class BinaryArtifact:
    """Parsed view of one binary: symbols, imports, strings, constants."""

    def __init__(
        self,
        *,
        format: str,
        path: str = "",
        symbols: Optional[Iterable[str]] = None,
        imports: Optional[Iterable[str]] = None,
        strings: Optional[Iterable[str]] = None,
        constants: Optional[Iterable[bytes]] = None,
    ) -> None:
        self.format = format
        self.path = path
        self.symbols = list(symbols or [])
        self.imports = list(imports or [])
        self.strings = list(strings or [])
        self.constants = list(constants or [])

    def all_names(self) -> list[str]:
        return self.symbols + self.imports + self.strings


class BinaryCryptoDetector:
    """§7 detection over BinaryArtifact data (parsers produce artifacts)."""

    def __init__(self) -> None:
        pass

    def analyze(self, artifact: BinaryArtifact) -> dict[str, Any]:
        """All crypto evidence for one binary, with levels."""
        findings: dict[str, dict[str, Any]] = {}

        def _add(algorithm: str, level: str, detail: str) -> None:
            entry = findings.setdefault(algorithm, {
                "algorithm": algorithm,
                "evidence": [],
                "best_level": 0.0,
                "levels": [],
            })
            entry["evidence"].append({"level": level, "detail": detail})
            entry["levels"].append(level)
            entry["best_level"] = max(entry["best_level"], LEVEL_WEIGHT[level])

        # 1. symbols & imports (SYMBOL_MATCH / IMPORT_MATCH)
        for symbol in artifact.symbols:
            alg = SYMBOL_ALGORITHMS.get(symbol)
            if alg:
                _add(alg, "SYMBOL_MATCH", f"symbol {symbol}")
        for imp in artifact.imports:
            alg = SYMBOL_ALGORITHMS.get(imp)
            if alg:
                _add(alg, "IMPORT_MATCH", f"import {imp}")

        # 2. strings → implementation signatures are STRING_MATCH evidence
        #    (weak by itself — a version banner can sit in documentation data)
        blob = "\n".join(artifact.strings)
        for name, marker in IMPLEMENTATION_FINGERPRINTS.items():
            hits = [m for m in marker if m in blob]
            if hits:
                _add(name, "STRING_MATCH", f"implementation signature {hits[0]!r}")
        for alg, constant in CRYPTO_CONSTANTS.items():
            if constant in (artifact.constants or []):
                _add(alg, "CONSTANT_MATCH", f"algorithm constant table ({constant[:8]!r})")

        # 3. TLS handshake bytes (FINGERPRINT)
        for tls_bytes in _TLS_BYTES:
            if tls_bytes in (artifact.constants or []):
                _add("TLS", "FINGERPRINT", f"TLS record bytes {tls_bytes.hex()}")
                break

        for entry in findings.values():
            entry["verdict"] = (
                "CONFIRMED_IMPLEMENTATION" if entry["best_level"] >= 0.9
                else "POSSIBLE_CRYPTO")
        return {
            "format": artifact.format,
            "path": artifact.path,
            "detections": list(findings.values()),
        }


# --------------------------------------------------------------------------- #
# minimal binary parsers — ELF / PE / Mach-O / WASM
# --------------------------------------------------------------------------- #

class BinaryParser:
    """Parse binaries into BinaryArtifacts (deterministic, stdlib-only)."""

    def parse(self, data: bytes, path: str = "") -> BinaryArtifact:
        if data[:4] == b"\x7fELF":
            return self._parse_elf(data, path)
        if data[:2] == b"MZ":
            return self._parse_pe(data, path)
        if data[:4] == b"\xfe\xed\xfa\xce" or data[:4] == b"\xfe\xed\xfa\xcf":
            return self._parse_macho(data, path)
        if data[:4] == b"\x00asm":
            return self._parse_wasm(data, path)
        return BinaryArtifact(format="raw", path=path,
                              strings=_extract_strings(data))

    # -- ELF64/ELF32 -------------------------------------------------------

    def _parse_elf(self, data: bytes, path: str) -> BinaryArtifact:
        is64 = data[4] == 2
        fmt = "<" + ("Q" if is64 else "I")
        (e_shoff,) = struct.unpack_from(fmt, data, 0x28 if is64 else 0x20)
        e_shentsize = struct.unpack_from("<H", data, 0x3A if is64 else 0x2E)[0]
        e_shnum = struct.unpack_from("<H", data, 0x3C if is64 else 0x30)[0]
        e_shstrndx = struct.unpack_from("<H", data, 0x3E if is64 else 0x32)[0]
        symbols: list[str] = []
        strings: list[str] = []
        constants: list[bytes] = []
        try:
            shstr_off = struct.unpack_from(fmt, data, e_shoff + e_shstrndx * e_shentsize + 0x18)[0]
            shstr_size = struct.unpack_from(fmt, data, e_shoff + e_shstrndx * e_shentsize + 0x20)[0]
            shstr = data[shstr_off:shstr_off + shstr_size]
        except Exception:
            shstr = b""
        for i in range(e_shnum):
            try:
                sh = e_shoff + i * e_shentsize
                name_off, sh_type = struct.unpack_from("<II", data, sh)
                offset = struct.unpack_from(fmt, data, sh + 0x18)[0]
                size = struct.unpack_from(fmt, data, sh + 0x20)[0]
                name = _cstr(shstr, name_off)
            except Exception as _handler_exc:
                logger.warning(
                    "exception_suppressed",
                    extra={"error_type": type(_handler_exc).__name__},
                )
                continue
            if name in (".symtab", ".dynsym"):  # SHT_SYMTAB=2, SHT_DYNSYM=11
                entsize = 24 if is64 else 16
                # st_name offsets point into the linked string table (sh_link)
                strbuf = b""
                try:
                    link = struct.unpack_from("<I", data, sh + 0x28)[0]
                    lsh = e_shoff + link * e_shentsize
                    str_off = struct.unpack_from(fmt, data, lsh + 0x18)[0]
                    str_size = struct.unpack_from(fmt, data, lsh + 0x20)[0]
                    strbuf = data[str_off:str_off + str_size]
                except Exception as _handler_exc:
                    logger.warning(
                        "exception_suppressed",
                        extra={"error_type": type(_handler_exc).__name__},
                    )
                    pass
                for j in range(0, min(size, len(data) - offset) - entsize + 1, entsize):
                    try:
                        st_name = struct.unpack_from("<I", data, offset + j)[0]
                        sym = _cstr(strbuf, st_name)
                        if sym:
                            symbols.append(sym)
                    except Exception as _handler_exc:
                        logger.warning(
                            "exception_suppressed",
                            extra={"error_type": type(_handler_exc).__name__},
                        )
                        pass
            elif name == ".rodata":
                strings.extend(_extract_strings(data[offset:offset + size]))
                constants.append(data[offset:offset + min(size, 64)])
            elif name == ".text" and is64:
                constants.append(data[offset:offset + min(size, 16)])
        return BinaryArtifact(format="elf", path=path, symbols=symbols,
                              strings=strings, constants=constants)

    # -- PE ----------------------------------------------------------------

    def _parse_pe(self, data: bytes, path: str) -> BinaryArtifact:
        strings = _extract_strings(data)
        imports: list[str] = []
        # scan import directory names: "CryptEncrypt", "BCryptOpenAlgorithmProvider"
        for match in re.finditer(rb"([A-Za-z][A-Za-z0-9_]{4,40})", data):
            name = match.group(1).decode("latin-1")
            if name in SYMBOL_ALGORITHMS or name.startswith(("Crypt", "BCrypt", "NCrypt")):
                imports.append(name)
        return BinaryArtifact(format="pe", path=path, imports=imports,
                              strings=strings,
                              constants=[data[0x100:0x140]] if len(data) > 0x140 else [])

    # -- Mach-O ------------------------------------------------------------

    def _parse_macho(self, data: bytes, path: str) -> BinaryArtifact:
        strings = _extract_strings(data)
        symbols: list[str] = []
        for match in re.finditer(rb"_([A-Za-z][A-Za-z0-9_]{3,60})", data):
            name = match.group(1).decode("latin-1")
            if name in SYMBOL_ALGORITHMS:
                symbols.append(name)
        return BinaryArtifact(format="macho", path=path, symbols=symbols,
                              strings=strings,
                              constants=[b"expand 32-byte k"] if b"expand 32-byte k" in data else [])

    # -- WASM --------------------------------------------------------------

    def _parse_wasm(self, data: bytes, path: str) -> BinaryArtifact:
        strings = _extract_strings(data)
        imports: list[str] = []
        for name, alg in SYMBOL_ALGORITHMS.items():
            if name.encode() in data:
                imports.append(name)
        return BinaryArtifact(format="wasm", path=path, imports=imports,
                              strings=strings)


def _extract_strings(data: bytes, min_len: int = 5) -> list[str]:
    """ASCII strings of at least min_len bytes (deterministic)."""
    out: list[str] = []
    current = bytearray()
    for byte in data:
        if 32 <= byte < 127:
            current.append(byte)
        else:
            if len(current) >= min_len:
                out.append(bytes(current).decode("ascii"))
            current = bytearray()
    if len(current) >= min_len:
        out.append(bytes(current).decode("ascii"))
    return out


def _cstr(table: bytes, offset: int) -> str:
    if offset >= len(table):
        return ""
    end = table.find(b"\x00", offset)
    if end == -1:
        end = len(table)
    return table[offset:end].decode("latin-1", errors="replace")
