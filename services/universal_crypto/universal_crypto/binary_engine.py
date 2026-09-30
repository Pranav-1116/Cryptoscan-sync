"""§7 Binary crypto detection.

ELF / PE / Mach-O / WASM / Android DEX / CPython bytecode / firmware /
shared libraries / static binaries: extract imports, exports, symbols, strings,
constants, known implementation fingerprints and crypto tables — then score
evidence levels. This engine remains metadata-only: it never disassembles or
executes bytecode.

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
    "JCA-JCE": ("javax/crypto", "javax.crypto", "java/security/MessageDigest"),
    "Python hashlib": ("hashlib", "hmac", "secrets"),
    "Python cryptography": ("cryptography", "hazmat"),
    "PyCryptodome": ("Crypto.Cipher", "Crypto.Hash", "pycryptodome"),
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
    # Python code-object names are prefixed by the DevSecOps parser; the bare
    # forms are used by this standalone universal parser.
    "sha256": "SHA-256", "sha512": "SHA-512", "sha1": "SHA-1", "md5": "MD5",
    "python:sha256": "SHA-256", "python:sha512": "SHA-512",
    "python:sha1": "SHA-1", "python:md5": "MD5",
    "RAND_bytes": "CSPRNG", "RAND_poll": "CSPRNG",
}

#: TLS record/version bytes (fingerprint-level evidence)
_TLS_BYTES = (b"\x16\x03\x03", b"\x16\x03\x01", b"\x16\x03\x04")

#: API-independent transformation strings found in Java/DEX/Python constants.
#: They remain STRING_MATCH evidence; a literal is not proof the operation runs.
_STRING_ALGORITHMS: tuple[tuple[str, str], ...] = (
    (r"AES/(?:GCM|CBC|CTR|CCM)/[A-Za-z0-9]+", "AES"),
    (r"ChaCha20-Poly1305", "ChaCha20-Poly1305"),
    (r"PBKDF2WithHmacSHA(?:1|224|256|384|512)", "PBKDF2"),
    (r"(?:SHA-?256|sha256)", "SHA-256"),
    (r"(?:SHA-?512|sha512)", "SHA-512"),
    (r"(?:SHA-?1|sha1)", "SHA-1"),
    (r"(?:MD5|md5)", "MD5"),
)


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

        # 4. Transformation/API-independent strings.  These are deliberately
        # lower confidence than imports and symbols: a class constant can be
        # documentation, a test vector, or dead code.
        for pattern, algorithm in _STRING_ALGORITHMS:
            match = re.search(pattern, blob, re.IGNORECASE)
            if match:
                _add(algorithm, "STRING_MATCH", f"transformation string {match.group(0)!r}")

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

_PYTHON_BYTECODE_MAGICS = {
    bytes.fromhex(value) for value in (
        "ee0c0d0a", "170d0d0a", "330d0d0a", "420d0d0a", "550d0d0a",
        "610d0d0a", "6f0d0d0a", "a70d0d0a", "cb0d0d0a", "f30d0d0a",
    )
}
try:  # recognize a newer interpreter's current magic without version guessing
    import importlib.util as _importlib_util
    _PYTHON_BYTECODE_MAGICS.add(_importlib_util.MAGIC_NUMBER)
except Exception:  # pragma: no cover
    pass


class BinaryParser:
    """Parse binaries into BinaryArtifacts (deterministic, stdlib-only)."""

    def parse(self, data: bytes, path: str = "") -> BinaryArtifact:
        if data[:4] == b"dex\n":
            return self._parse_dex(data, path)
        if data[:4] in _PYTHON_BYTECODE_MAGICS:
            return self._parse_python_bytecode(data, path)
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

    @staticmethod
    def _dex_uleb(data: bytes, offset: int) -> tuple[int, int]:
        value = shift = 0
        for _ in range(5):
            if offset >= len(data):
                raise ValueError("truncated DEX ULEB128")
            byte = data[offset]
            offset += 1
            value |= (byte & 0x7f) << shift
            if not byte & 0x80:
                return value, offset
            shift += 7
        raise ValueError("oversized DEX ULEB128")

    def _parse_dex(self, data: bytes, path: str) -> BinaryArtifact:
        """Read DEX string/type tables, bounded to metadata needed by crypto scans."""
        if len(data) < 0x70 or data[7] != 0:
            return BinaryArtifact(format="dex", path=path, strings=_extract_strings(data))
        string_count, string_offset = struct.unpack_from("<II", data, 0x38)
        type_count, type_offset = struct.unpack_from("<II", data, 0x40)
        if string_count > 20000 or type_count > 20000:
            return BinaryArtifact(format="dex", path=path, strings=_extract_strings(data))
        if (string_offset + string_count * 4 > len(data)
                or type_offset + type_count * 4 > len(data)):
            return BinaryArtifact(format="dex", path=path, strings=_extract_strings(data))
        strings: list[str] = []
        for index in range(string_count):
            (offset,) = struct.unpack_from("<I", data, string_offset + index * 4)
            if offset >= len(data):
                continue
            try:
                _length, position = self._dex_uleb(data, offset)
                end = data.find(b"\x00", position,
                                min(len(data), position + _length * 4 + 1))
                if end >= 0:
                    strings.append(data[position:end].decode("utf-8", "replace"))
            except (ValueError, UnicodeError):
                continue
        types: list[str] = []
        for index in range(type_count):
            (string_index,) = struct.unpack_from("<I", data, type_offset + index * 4)
            if string_index < len(strings):
                types.append(strings[string_index])
        return BinaryArtifact(format="dex", path=path, imports=types[:600],
                              symbols=types[:600], strings=strings[:6000])

    def _parse_python_bytecode(self, data: bytes, path: str) -> BinaryArtifact:
        """Read CPython code-object names/constants without executing them."""
        strings: list[str] = []
        names: list[str] = []
        try:
            import marshal
            code = marshal.loads(data[16:16 + 16 * 1024 * 1024])
            stack = [code]
            objects = 0
            while stack and objects < 1000:
                current = stack.pop()
                objects += 1
                names.extend(value for value in getattr(current, "co_names", ())
                             if isinstance(value, str))
                for value in getattr(current, "co_consts", ()):
                    if isinstance(value, str):
                        strings.append(value)
                    elif hasattr(value, "co_consts"):
                        stack.append(value)
        except Exception:  # malformed or foreign-version marshal is metadata-only failure
            pass
        return BinaryArtifact(format="python-bytecode", path=path,
                              imports=list(dict.fromkeys(names))[:600],
                              strings=list(dict.fromkeys(strings))[:6000])

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
