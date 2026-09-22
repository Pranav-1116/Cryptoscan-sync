"""End-to-end binary and firmware scanning — deterministic, stdlib-only.

Turns executables, shared libraries, archives and firmware images into the same
canonical scan result the SBOM scanner already understands, so binaries get the
whole pipeline: rendering, NTIA validation, licence policy, gate, signing, VEX,
diffing and CBOM enrichment.

What is parsed, and how deep:

* **ELF** (32/64, little/big endian) — class, machine, type (exec / PIE / shared
  / core), static-vs-dynamic, `DT_NEEDED` libraries, `RPATH`/`RUNPATH`,
  `.note.gnu.build-id`, `.comment` compiler string, dynamic symbols split into
  imports and exports, stripped detection, and **Go build info** (toolchain
  version plus the embedded module graph with exact versions).
* **PE** (incl. PE32+) — machine, subsystem, DLL imports resolved through the
  section table, .NET/CLR detection, sections.
* **Mach-O** (thin and fat) — CPU type, `LC_UUID`, platform, linked dylibs.
* **Archives and packages** — `ar` (.a / .deb), zip containers (.jar/.war/.whl/
  .nupkg/.apk) with Maven coordinates from `pom.properties` and Python metadata
  from `dist-info/METADATA`.
* **Firmware** — container-chain detection (u-boot uImage, device-tree blob,
  squashfs, JFFS2, UBIFS, cramfs, ext, gzip/xz/zstd/bzip2/lzma/lz4, tar) and
  device-tree `model`/`compatible` identity. Magic and offsets only: the
  platform does **not** unpack squashfs/JFFS2 (that needs binwalk), and claiming
  a filesystem listing it never produced would be a lie.
* **WASM**, **Java class** files, **Python bytecode**, **RPM** and **raw** blobs
  — identified and string-scanned; a format we cannot parse is reported as
  identified-but-not-parsed rather than silently passed.

Crypto evidence is graded, never asserted from one string: the engine delegates
to the universal-crypto fingerprint table and evidence-level model
(STRING_MATCH < SYMBOL_MATCH < IMPORT_MATCH < CONSTANT_MATCH < FINGERPRINT) so
there is one source of truth for crypto knowledge across the platform.

Everything is bounded: file-size cap, walk cap, string cap and per-parse
truncation, so a hostile file cannot hang a scan or exhaust memory.
"""
from __future__ import annotations

import hashlib
import math
import re
import struct
from pathlib import Path
from typing import Any, Iterable

# ----------------------------------------------------------------- bounds --- #
MAX_FILE_BYTES = 512 * 1024 * 1024          # scan a file up to 512 MiB
MAX_FILES_WALKED = 4000                     # files visited per walk
MAX_BINARIES = 750                          # binaries parsed per walk
MAX_STRINGS = 6000
MIN_STRING = 6
FIRMWARE_SCAN_LIMIT = 128 * 1024 * 1024     # container search window
SKIP_DIRS = {"proc", "sys", "dev", "run", ".git", "__pycache__", ".mypy_cache",
             ".pytest_cache", ".tox", "node_modules"}
MAX_CONSTANT_WINDOW = 96 * 1024 * 1024   # bytes of code/data searched for crypto tables
MAX_EXTRACT_BYTES = 64 * 1024 * 1024     # decompressed payload budget per container
MAX_EXTRACT_DEPTH = 2                    # containers followed inside containers
MAX_EXTRACT_FILES = 60                   # members listed/parsed per archive
MAX_MEMBER_BYTES = 16 * 1024 * 1024      # member size we are willing to parse
MAX_RPM_ENTRIES = 400                    # header index entries read

# ------------------------------------------------------------- detection ---- #
MAGICS: tuple[tuple[str, bytes], ...] = (
    ("elf", b"\x7fELF"),
    ("pe", b"MZ"),
    ("macho", b"\xfe\xed\xfa\xce"),
    ("macho64", b"\xfe\xed\xfa\xcf"),
    ("macho-be", b"\xce\xfa\xed\xfe"),
    ("macho64-be", b"\xcf\xfa\xed\xfe"),
    ("macho-fat", b"\xca\xfe\xba\xbe"),
    ("macho-fat-le", b"\xbe\xba\xfe\xca"),
    ("ar", b"!<arch>\n"),
    ("zip", b"PK\x03\x04"),
    ("wasm", b"\x00asm"),
    ("rpm", b"\xed\xab\xee\xdb"),
    ("squashfs", b"hsqs"),
    ("squashfs-be", b"sqsh"),
    ("jffs2", b"\x85\x19"),
    ("jffs2-le", b"\x19\x85"),
    ("ubi", b"UBI#"),
    ("ubifs", b"\x31\x18\x10\x06"),
    ("cramfs", b"\x28\xcd\x3d\x45"),
    ("uimage", b"\x27\x05\x19\x56"),
    ("dtb", b"\xd0\x0d\xfe\xed"),
    ("gzip", b"\x1f\x8b\x08"),
    ("xz", b"\xfd7zXZ\x00"),
    ("zstd", b"\x28\xb5\x2f\xfd"),
    ("bzip2", b"BZh"),
    ("lzma", b"\x5d\x00\x00\x00"),
    ("lz4", b"\x04\x22\x4d\x18"),
    ("cpio", b"070701"),                       # newc initramfs archive
    ("cpio", b"070702"),                       # crc variant
    ("cpio-odc", b"070707"),                   # old ASCII format: identified, not parsed
    ("java-class", b"\xca\xfe\xba\xbe"),      # ambiguous with fat Mach-O — resolved below
)
COMPRESSION_FORMATS = {"gzip", "xz", "zstd", "bzip2", "lzma", "lz4"}
FILESYSTEM_FORMATS = {"squashfs", "squashfs-be", "jffs2", "jffs2-le", "ubi", "ubifs", "cramfs", "ext"}
ARCHIVE_FORMATS = {"ar", "zip", "rpm"}
ELF_FORMATS = {"elf"}
PE_FORMATS = {"pe"}
MACHO_FORMATS = {"macho", "macho64", "macho-be", "macho64-be", "macho-fat", "macho-fat-le"}
EXECUTABLE_FORMATS = ELF_FORMATS | PE_FORMATS | MACHO_FORMATS | {"wasm"}

#: Platform crypto APIs whose *symbol names are unambiguous*: linking against
#: CommonCrypto's ``CC_SHA256`` or calling ``BCryptGenRandom`` says which primitive
#: is in use, whereas ``CCCryptorCreate`` only says that a symmetric cipher is used —
#: that stays a library marker and is never promoted to an algorithm. Hits here are
#: call sites (IMPORT/SYMBOL evidence), which is why they outrank a string match.
PLATFORM_SYMBOL_ALGORITHMS: tuple[tuple[str, str], ...] = (
    # Apple CommonCrypto
    ("CC_SHA1", "SHA-1"), ("CC_SHA224", "SHA-224"), ("CC_SHA256", "SHA-256"),
    ("CC_SHA384", "SHA-384"), ("CC_SHA512", "SHA-512"), ("CC_MD5", "MD5"),
    ("CCCryptorGCM", "AES-GCM"), ("CCCryptorGCMFinal", "AES-GCM"),
    ("CCCryptorGCMSetIV", "AES-GCM"), ("CCCryptorGCMAddIV", "AES-GCM"),
    ("CCKeyDerivationPBKDF", "PBKDF2"), ("CCCalibratePBKDF", "PBKDF2"),
    ("CCRandomGenerateBytes", "CSPRNG"), ("CCRandomCopyBytes", "CSPRNG"),
    # Apple Security.framework / SecureTransport
    ("SSLCreateContext", "TLS"), ("SSLHandshake", "TLS"), ("SSLSetIOFuncs", "TLS"),
    ("SecKeyCreateRandomKey", "CSPRNG"),
    # Windows CNG / CryptoAPI
    ("BCryptGenRandom", "CSPRNG"), ("CryptGenRandom", "CSPRNG"), ("RtlGenRandom", "CSPRNG"),
    ("BCryptOpenAlgorithmProvider", "CNG-provider"),
    # kernel/libc randomness
    ("getrandom", "CSPRNG"), ("getentropy", "CSPRNG"), ("arc4random_buf", "CSPRNG"),
    # OpenSSL entry points the shared symbol table does not list
    ("AES_set_encrypt_key", "AES"), ("AES_encrypt", "AES"), ("AES_cbc_encrypt", "AES"),
    ("ChaCha20_ctr32", "ChaCha20"), ("Poly1305_Update", "Poly1305"),
    ("SHA256_Update", "SHA-256"), ("SHA512_Update", "SHA-512"), ("SHA1_Update", "SHA-1"),
    ("MD5_Update", "MD5"), ("HMAC_Update", "HMAC-SHA256"), ("RAND_bytes", "CSPRNG"),
    ("PKCS5_PBKDF2_HMAC", "PBKDF2"), ("crypto_scrypt", "scrypt"),
)


def _platform_symbol_algorithms(imports: Iterable[str],
                                exports: Iterable[str]) -> list[dict[str, Any]]:
    """Algorithm rows for unambiguous platform API calls (imports outrank symbols)."""
    rows: dict[str, dict[str, Any]] = {}
    import_names = list(imports)
    export_names = list(exports)

    def _hit(names: list[str], symbol: str) -> str | None:
        return next((name for name in names
                     if name == symbol or name.startswith(symbol + "_")), None)

    for symbol, algorithm in PLATFORM_SYMBOL_ALGORITHMS:
        found = _hit(import_names, symbol)
        level, detail = ("IMPORT", "import") if found else (None, "")
        if found is None:
            found = _hit(export_names, symbol)
            level, detail = ("SYMBOL", "symbol") if found else (None, "")
        if found is None:
            continue
        row = rows.setdefault(algorithm, {"name": algorithm,
                                          "confidence": 0.8 if level == "IMPORT" else 0.7,
                                          "strongest_evidence": level, "sources": [],
                                          "verdict": "POSSIBLE_CRYPTO"})
        if len(row["sources"]) < 3:
            row["sources"].append(f"{detail} {found} (platform API)")
        if level == "IMPORT":
            row["confidence"] = max(row["confidence"], 0.8)
            row["strongest_evidence"] = "IMPORT"
    return list(rows.values())


#: Cipher transformation strings and TLS suite names, graded at the STRING level.
#: These are the forms a name shows up in when it is *used* rather than exported:
#: "AES/GCM/NoPadding" in a Java constant pool, "RSA/ECB/PKCS1Padding" in a config,
#: "TLS_AES_256_GCM_SHA384" in a handshake table. The upstream engine detects
#: algorithms from symbols and constants, so this pass covers the string layer and
#: nothing else — every hit is reported as STRING_MATCH, never as a symbol claim.
TRANSFORMATION_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\bAES/(GCM|CBC|CTR|ECB|CCM|OFB|CFB|KW|Wrap)", "AES"),
    (r"\b(TLS|SSL)_(AES|CHACHA20|3DES|RC4|CAMELLIA|ARIA|SM4)", "AES"),
    (r"\bDESede|\bDES/|\bDES-EDE3|\b3DES\b|\bTripleDES\b", "3DES"),
    (r"\bRSA/|\bRSA_PKCS1|\bRSASSA-PSS\b|\bRSA-OAEP\b", "RSA"),
    (r"\bECIES\b|\bECDH_|\bECDHE\b|\bECDSA\b|\bEC/", "ECDH"),
    (r"\bX25519\b|\bcurve25519\b", "X25519"),
    (r"\bEd25519\b|\bEd448\b", "Ed25519"),
    (r"\bChaCha20(-Poly1305)?\b", "ChaCha20"),
    (r"\bPoly1305\b", "Poly1305"),
    (r"\bHMAC[-_]?SHA(1|224|256|384|512)?\b|\bHMACSHA", "HMAC-SHA256"),
    (r"\bSHA-?(1|224|256|384|512)\b|\bSHA3-?(224|256|384|512)\b", "SHA-256"),
    (r"\b(MD5)\b|\bMD5/", "MD5"),
    (r"\bPBKDF2(WithHMAC)?\b", "PBKDF2"),
    (r"\bBlowfish\b|\bBF/", "Blowfish"),
    (r"\bRC2\b|\bRC4\b|\bARCFOUR\b", "RC4"),
    (r"\bCamellia\b", "Camellia"),
    (r"\bSM4\b", "SM4"),
    (r"\bSM2\b", "SM2"),
    (r"\bSM3\b", "SM3"),
    (r"\bARIA\b", "ARIA"),
    (r"\bML-?KEM\b|\bML-?DSA\b|\bSLH-?DSA\b", "ML-KEM"),
    (r"\bDSA/(SHA|NONE)", "DSA"),
    (r"\bDH/(PKCS|NONE)|\bDiffieHellman\b", "DH"),
)


def _transformation_algorithms(strings: Iterable[str]) -> list[dict[str, Any]]:
    """Algorithm names read out of transformation/TLS-suite strings."""
    rows: dict[str, dict[str, Any]] = {}
    for text in strings:
        if len(text) < 3 or len(text) > 400:
            continue
        for pattern, algorithm in TRANSFORMATION_PATTERNS:
            match = re.search(pattern, text)
            if not match:
                continue
            row = rows.setdefault(algorithm, {"name": algorithm, "confidence": 0.4,
                                              "strongest_evidence": "STRING", "sources": [],
                                              "verdict": "POSSIBLE_CRYPTO"})
            if len(row["sources"]) < 3:
                row["sources"].append(f"transformation string {match.group(0)!r}")
    return list(rows.values())


#: packer/obfuscator signatures. A packed binary hides its strings and its symbol
#: table, so crypto detection inside one is structurally incomplete — that is a
#: finding, not a footnote.
PACKER_SIGNATURES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("UPX", ("UPX!", "UPX0", "UPX1", "$Info: This file is packed")),
    ("ASPack", (".aspack", ".adata", "ASPack")),
    ("MPRESS", (".MPRESS1", ".MPRESS2")),
    ("Themida/WinLicense", (".themida", ".winlice", "Themida")),
    ("PECompact", ("PECompact2", "pec1", "pec2")),
    ("Petite", (".petite", "petite")),
    ("Enigma Protector", (".enigma1", ".enigma2")),
    ("VMProtect", (".vmp0", ".vmp1", ".vmp2")),
    ("PyInstaller", ("MEI\x0c\x0b\x0a\x0b\x0e", "pyi-", "PyInstaller")),
    ("Electron/asar", ("app.asar", "ELECTRON_RUN_AS_NODE")),
    ("Google Play Protect", ("SEALED_BUNDLE",)),
)
ELF_MACHINES = {
    0x03: "x86", 0x08: "MIPS", 0x14: "PowerPC", 0x15: "PowerPC64", 0x16: "S390",
    0x28: "ARM", 0x2A: "SuperH", 0x32: "IA-64", 0x3E: "x86-64", 0xB7: "AArch64",
    0xF3: "RISC-V", 0x102: "LoongArch",
}
ELF_TYPES = {0: "none", 1: "relocatable", 2: "executable", 3: "shared", 4: "core"}
PE_MACHINES = {0x014C: "x86", 0x8664: "x86-64", 0x01C0: "ARM", 0xAA64: "AArch64",
               0x0200: "IA-64", 0x01C4: "ARMv7", 0x0166: "MIPS"}
PE_SUBSYSTEMS = {
    1: "native", 2: "windows-gui", 3: "console", 5: "os2-console", 7: "posix-console",
    9: "windows-ce", 10: "efi-application", 11: "efi-boot-service-driver",
    12: "efi-runtime-driver", 13: "efi-rom", 14: "xbox", 16: "windows-boot-application",
}
#: version-info strings worth lifting into the SBOM (Microsoft's own vocabulary)
VERSION_INFO_KEYS = {
    "CompanyName": "vendor", "ProductName": "product", "FileDescription": "description",
    "FileVersion": "version", "ProductVersion": "product_version",
    "OriginalFilename": "original_filename", "InternalName": "internal_name",
    "LegalCopyright": "copyright", "Comments": "comments",
}
MACHO_CPUS = {7: "x86", 0x01000007: "x86-64", 12: "ARM", 0x0100000C: "AArch64",
              18: "PowerPC", 0x01000012: "PowerPC64"}
MACHO_PLATFORMS = {1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS", 6: "macCatalyst"}
#: dylib-ish load commands (LC_REQ_DYLD sets the high bit)
MACHO_DYLIB_COMMANDS = {0x0C: "load", 0x18: "weak", 0x1F: "reexport", 0x20: "lazy",
                        0x23: "upward", 0x80000018: "weak", 0x8000001F: "reexport",
                        0x80000023: "upward"}
#: code-signature superblob entry types
MACHO_CS_TYPES = {0: "CodeDirectory", 1: "Info.plist", 2: "Requirements", 5: "Entitlements",
                  7: "DEREntitlements", 0x10000: "Signature", 0x10001: "Requirements"}
#: hardened-runtime and debugging code-signature flags we care about
MACHO_CS_FLAGS = {0x2: "adhoc", 0x10000: "hardened-runtime", 0x20000: "library-validation",
                  0x40000: "runtime-checks"}
#: entitlements that change what the process is allowed to do
MACHO_NOTABLE_ENTITLEMENTS = ("com.apple.security.get-task-allow",
                              "com.apple.security.cs.disable-library-validation",
                              "com.apple.security.cs.allow-unsigned-executable-memory",
                              "com.apple.security.cs.allow-dyld-environment-variables",
                              "com.apple.security.cs.allow-jit",
                              "com.apple.security.cs.disable-executable-page-protection",
                              "com.apple.private.security.no-sandbox",
                              "task_for_pid-allow")

# ------------------------------------------------------- crypto knowledge --- #
#: library version strings embedded by the libraries themselves
VERSION_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("OpenSSL", r"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)", "OpenSSL"),
    ("LibreSSL", r"LibreSSL\s+(\d+\.\d+\.\d+)", "LibreSSL"),
    ("mbedTLS", r"Mbed TLS\s+(\d+\.\d+\.\d+)", "ARM"),
    ("wolfSSL", r"wolfSSL\s+(\d+\.\d+\.\d+)", "wolfSSL"),
    ("GnuTLS", r"GnuTLS\s+(\d+\.\d+\.\d+)", "GnuTLS"),
    ("libsodium", r"libsodium\s+(\d+\.\d+\.\d+)", "libsodium"),
    ("Botan", r"Botan\s+(\d+\.\d+\.\d+)", "Botan"),
    ("NSS", r"NSS\s+(\d+\.\d+(?:\.\d+)?)", "Mozilla"),
    ("libgcrypt", r"libgcrypt\s+(\d+\.\d+\.\d+)", "GnuPG"),
    ("Node.js", r"node\.js/v(\d+\.\d+\.\d+)", "OpenJS Foundation"),
)
#: markers for libraries whose version is not embedded as a plain string
LIBRARY_MARKERS: dict[str, tuple[str, ...]] = {
    "BoringSSL": ("BoringSSL", "boringssl", "openSSLIsBoringSSL"),
    "BouncyCastle": ("org/bouncycastle", "BouncyCastleProvider", "bcprov"),
    "Crypto++": ("CryptoPP", "cryptopp"),
    "Apple CommonCrypto": ("CCCryptorCreate", "CC_SHA256", "CCKeyDerivationPBKDF"),
    "Apple Security.framework": ("SecKeyEncrypt", "SecTrustEvaluate", "SSLCreateContext"),
    ".NET cryptography": ("System.Security.Cryptography",),
    "JCA-JCE": ("javax/crypto", "java/security/MessageDigest"),
    "WebCrypto": ("crypto.subtle", "SubtleCrypto"),
    "RustCrypto": ("ed25519-dalek", "aes-gcm", "rustls"),
    "PKCS#11": ("C_GetFunctionList", "pkcs11"),
    "libsodium": ("crypto_secretbox_easy", "crypto_sign_detached", "sodium_init"),
    "mbedTLS": ("mbedtls_ssl_init", "mbedtls_aes_crypt_cbc"),
    "wolfSSL": ("wolfSSL_CTX_new", "wolfSSL_Init"),
    "OpenSSL": ("EVP_EncryptInit_ex", "EVP_DigestInit_ex", "SSL_CTX_new"),
}
#: Post-quantum algorithms, as patterns so the *full designation* is reported:
#: a binary that mentions ML-KEM-768 says which parameter set it carries, and
#: reporting the bare "ML-KEM" would throw that away.
PQC_PATTERNS: tuple[str, ...] = (
    r"ml[_-]?kem(?:[_-]?\d{3,4})?", r"kyber(?:[_-]?\d{3,4})?",
    r"ml[_-]?dsa(?:[_-]?\d{3,4})?", r"dilithium[0-9]?",
    r"slh[_-]?dsa(?:[_-]?\d+[sf]?)?", r"sphincs\+?(?:[_-]?\d+[sf]?)?",
    r"falcon(?:[_-]?\d{3,4})?", r"frodokem(?:[_-]?\d+)?", r"sntrup\d+",
    r"\bhqc\b", r"\bbike\b",
)
#: X25519/Ed25519 are classical ECC on a modern curve: excellent today, broken
#: by Shor's algorithm tomorrow. They belong on the migration list, not the PQC one.
ECC_PATTERNS: tuple[str, ...] = (
    r"x25519", r"x448", r"ed25519", r"ed448", r"ecdsa", r"ecdh",
    r"secp256r1|prime256v1|p-256", r"secp384r1|p-384", r"secp521r1|p-521", r"brainpool",
)
_TOKEN_END = r"(?![a-z0-9])"
QUANTUM_VULNERABLE_ALGORITHMS = ("RSA", "ECDSA", "ECDH", "DH", "DSA", "SHA-1", "MD5",
                                 "3DES", "DES", "RC4", "RC2", "X25519", "ED25519",
                                 "X448", "ED448")
EOL_VERSIONS: dict[str, tuple[tuple[int, int], ...]] = {
    "OpenSSL": ((0, 9), (1, 0), (1, 1)),          # 3.x is the supported line
    "Node.js": ((12, 0), (14, 0), (16, 0)),       # 18/20/22 are supported
}


# ------------------------------------------------------------- utilities ---- #
def sha256_file(path: Path, *, limit: int = MAX_FILE_BYTES) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            if size >= limit:
                break
    return digest.hexdigest(), size


def entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte — tells packed/encrypted blobs from code."""
    if not data:
        return 0.0
    window = data[:65536]
    counts = [0] * 256
    for byte in window:
        counts[byte] += 1
    total = len(window)
    return -sum((c / total) * math.log2(c / total) for c in counts if c)


def extract_strings(data: bytes, *, min_len: int = MIN_STRING, limit: int = MAX_STRINGS) -> list[str]:
    """Printable ASCII runs — the substrate every marker match reads."""
    out: list[str] = []
    current: list[str] = []
    for byte in data:
        if 32 <= byte < 127:
            current.append(chr(byte))
            continue
        if len(current) >= min_len:
            out.append("".join(current))
            if len(out) >= limit:
                return out
        current = []
    if len(current) >= min_len and len(out) < limit:
        out.append("".join(current))
    return out


def identify(data: bytes, name: str = "") -> dict[str, str]:
    """Format from magic bytes — never from the file extension."""
    head = data[:32]
    if head.startswith(b"\xca\xfe\xba\xbe"):
        count = struct.unpack_from(">I", data, 4)[0] if len(data) >= 8 else 0
        if 1 <= count <= 20:
            return {"format": "macho-fat", "arch": "universal"}
        return {"format": "java-class", "arch": "bytecode"}
    for fmt, magic in MAGICS:
        if not head.startswith(magic):
            continue
        if fmt == "pe":
            # "MZ" alone is weak: require the PE signature at e_lfanew
            if len(data) >= 0x40:
                offset = struct.unpack_from("<I", data, 0x3C)[0]
                if offset + 4 <= len(data) and data[offset:offset + 4] == b"PE\x00\x00":
                    return {"format": "pe", "arch": ""}
            continue
        if fmt == "macho-fat-le":
            return {"format": "macho-fat", "arch": "universal"}
        return {"format": fmt, "arch": ""}
    if len(data) > 0x43A and data[0x438:0x43A] == b"\x53\xef":
        return {"format": "ext", "arch": ""}
    if len(data) > 265 and data[257:262] == b"ustar":
        return {"format": "ustar", "arch": ""}
    return {"format": "raw", "arch": ""}


def _cstr(table: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(table):
        return ""
    end = table.find(b"\x00", offset)
    if end < 0:
        return ""
    return table[offset:end].decode("utf-8", "replace")


class _Reader:
    """Bounds-checked view over a byte buffer; every read can fail safely."""

    def __init__(self, data: bytes):
        self.data = data

    def take(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise ValueError("out of bounds")
        return self.data[offset:offset + size]

    def unpack(self, fmt: str, offset: int) -> tuple:
        return struct.unpack_from(fmt, self.data, offset)


# ------------------------------------------------------------------ ELF ----- #
def parse_elf(data: bytes) -> dict[str, Any]:
    """ELF header, dynamic deps, build id, compiler, symbols, Go build info."""
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    is64 = data[4] == 2
    little = data[5] == 1
    end = "<" if little else ">"
    word = "Q" if is64 else "I"
    reader = _Reader(data)
    out: dict[str, Any] = {
        "format": "elf", "bits": 64 if is64 else 32,
        "endianness": "little" if little else "big",
        "os_abi": {0: "System V", 3: "Linux", 6: "Solaris", 9: "FreeBSD"}.get(data[7], str(data[7])),
        "libraries": [], "imports": [], "exports": [], "rpath": [],
    }
    out["type"] = ELF_TYPES.get(reader.unpack(end + "H", 16)[0], "unknown")
    machine = reader.unpack(end + "H", 18)[0]
    out["machine"] = ELF_MACHINES.get(machine, "unknown")
    out["arch"] = f"{out['machine']}{'-64' if is64 else ''}"

    e_shoff = reader.unpack(end + word, 0x28 if is64 else 0x20)[0]
    e_shentsize = reader.unpack(end + "H", 0x3A if is64 else 0x2E)[0]
    e_shnum = reader.unpack(end + "H", 0x3C if is64 else 0x30)[0]
    e_shstrndx = reader.unpack(end + "H", 0x3E if is64 else 0x32)[0]
    e_phnum = reader.unpack(end + "H", 0x38 if is64 else 0x2C)[0]

    sections: list[dict[str, Any]] = []
    shstr = b""
    if 0 < e_shnum < 20000 and e_shoff and e_shstrndx < e_shnum:
        try:
            base = e_shoff + e_shstrndx * e_shentsize
            shstr = reader.take(reader.unpack(end + word, base + 0x18)[0],
                                reader.unpack(end + word, base + 0x20)[0])
        except Exception:  # noqa: BLE001 — a broken section header table is reported, not fatal
            shstr = b""
    for index in range(min(e_shnum, 20000)):
        try:
            base = e_shoff + index * e_shentsize
            name_off = reader.unpack(end + "I", base)[0]
            sections.append({
                "name": _cstr(shstr, name_off),
                "type": reader.unpack(end + "I", base + 4)[0],
                "offset": reader.unpack(end + word, base + 0x18)[0],
                "size": reader.unpack(end + word, base + 0x20)[0],
                "link": reader.unpack(end + "I", base + 0x28)[0],
            })
        except Exception:  # noqa: BLE001
            continue
    by_name = {s["name"]: s for s in sections if s["name"]}
    # the section names are the cheapest view of what a binary still carries:
    # .symtab (not stripped), .note.gnu.property (CET), .gnu.version_r (floors)
    out["sections"] = sorted(by_name)[:64]
    out["section_count"] = len(sections)
    out["stripped"] = ".symtab" not in by_name
    out["dynamically_linked"] = ".dynamic" in by_name or ".dynsym" in by_name
    out["pie"] = out["type"] == "shared" and (".interp" in by_name or e_phnum > 0)
    out["static"] = out["type"] == "executable" and not out["dynamically_linked"]
    if out["type"] == "shared" and ".interp" not in by_name:
        out["type"] = "shared-library"

    comment = by_name.get(".comment")
    if comment:
        try:
            text = reader.take(comment["offset"], min(comment["size"], 4096)).decode("utf-8", "replace")
            compilers = [part.strip() for part in text.split("\x00") if part.strip()]
            if compilers:
                out["compiler"] = compilers[:8]
        except Exception:  # noqa: BLE001
            pass

    build_id = by_name.get(".note.gnu.build-id")
    if build_id:
        try:
            note = reader.take(build_id["offset"], min(build_id["size"], 512))
            name_size, desc_size = struct.unpack_from(end + "II", note, 0)
            descriptor = note[12 + ((name_size + 3) // 4) * 4:][:desc_size]
            out["build_id"] = descriptor.hex()
        except Exception:  # noqa: BLE001
            pass

    _elf_dynamic(reader, sections, by_name, end, word, out)
    _elf_symbols(reader, sections, by_name, end, word, out)
    _elf_program_headers(reader, data, is64, end, out)
    _elf_version_requirements(reader, sections, by_name, end, out)
    _elf_properties(data, by_name, out)
    _elf_hardening(reader, data, by_name, out, end)
    constants = _crypto_constants(data, sections, by_name)
    if constants["found"]:
        out["crypto_constants"] = constants["found"]
        out["_constant_blobs"] = constants["blobs"]
    packed = detect_packer(sections)
    if packed:
        out["packer"] = packed
    go = parse_go_buildinfo(data, by_name, reader)
    if go:
        out["go"] = go
    return out


def _elf_program_headers(reader: _Reader, data: bytes, is64: bool, end: str,
                         out: dict[str, Any]) -> None:
    """Segments worth knowing: interpreter, GNU_STACK (NX), GNU_RELRO."""
    phoff = reader.unpack(end + ("Q" if is64 else "I"), 0x20 if is64 else 0x1C)[0]
    phentsize = reader.unpack(end + "H", 0x36 if is64 else 0x2A)[0]
    phnum = reader.unpack(end + "H", 0x38 if is64 else 0x2C)[0]
    if not (0 < phnum < 512) or not phoff or not phentsize:
        return
    segments: list[str] = []
    for index in range(phnum):
        base = phoff + index * phentsize
        try:
            p_type = reader.unpack(end + "I", base)[0]
        except Exception:  # noqa: BLE001
            break
        if p_type == 1:                                   # PT_LOAD
            segments.append("load")
        elif p_type == 2:
            segments.append("dynamic")
        elif p_type == 3:                                 # PT_INTERP
            segments.append("interpreter")
            offset, size = (reader.unpack(end + "QQ", base + 8) if is64
                            else reader.unpack(end + "II", base + 4))
            try:
                text = reader.take(offset, min(size, 256)).split(b"\x00")[0]
                out["interpreter"] = text.decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                pass
        elif p_type == 0x6474E551:                        # PT_GNU_STACK
            segments.append("gnu_stack")
            flags = (reader.unpack(end + "I", base + 4)[0] if is64
                     else reader.unpack(end + "I", base + 24)[0])
            out["executable_stack"] = bool(flags & 0x1)
        elif p_type == 0x6474E552:                        # PT_GNU_RELRO
            segments.append("gnu_relro")
    if segments:
        out["segments"] = segments


def _elf_version_requirements(reader: _Reader, sections: list[dict[str, Any]],
                              by_name: dict[str, Any], end: str, out: dict[str, Any]) -> None:
    """`.gnu.version_r`: which symbol versions each library must provide.

    ``libcrypto.so.3`` requiring ``OPENSSL_3.0.0`` is a real version floor even
    when no banner string survives — that is evidence, not a guess.
    """
    section = by_name.get(".gnu.version_r")
    dynstr = by_name.get(".dynstr")
    if not section or not dynstr:
        return
    try:
        strtab = reader.take(dynstr["offset"], dynstr["size"])
    except Exception:  # noqa: BLE001
        return
    requirements: dict[str, list[str]] = {}
    offset = section["offset"]
    end_of_section = section["offset"] + section["size"]
    seen_files: set[int] = set()
    while offset + 16 <= end_of_section and len(seen_files) < 64:
        try:
            _version, count, file_offset, aux_offset, next_offset = reader.unpack(
                end + "HHIII", offset)
        except Exception:  # noqa: BLE001
            break
        seen_files.add(offset)
        library = _cstr(strtab, file_offset)
        aux = offset + aux_offset
        names: list[str] = []
        for _ in range(min(count, 64)):
            try:
                _hash, _flags, _other, name_offset, aux_next = reader.unpack(
                    end + "IHHII", aux)
            except Exception:  # noqa: BLE001
                break
            version = _cstr(strtab, name_offset)
            if version:
                names.append(version)
            if not aux_next:
                break
            aux += aux_next
        if library and names:
            requirements.setdefault(library, [])
            for name in names:
                if name not in requirements[library]:
                    requirements[library].append(name)
        if not next_offset:
            break
        offset += next_offset
    if requirements:
        out["symbol_versions"] = {lib: sorted(set(names))
                                  for lib, names in requirements.items()}


def _elf_properties(data: bytes, by_name: dict[str, Any], out: dict[str, Any]) -> None:
    """`.note.gnu.property`: CET (IBT/SHSTK) and other build-time protections."""
    section = by_name.get(".note.gnu.property")
    if not section:
        return
    try:
        note = data[section["offset"]:section["offset"] + min(section["size"], 4096)]
    except Exception:  # noqa: BLE001 — a malformed note is skipped
        return
    position = 0
    features: list[str] = []
    while position + 12 <= len(note):
        name_size, desc_size, note_type = struct.unpack_from("<III", note, position)
        name = note[position + 12:position + 12 + name_size].rstrip(b"\x00")
        desc_start = position + 12 + ((name_size + 3) // 4) * 4
        descriptor = note[desc_start:desc_start + desc_size]
        if name == b"GNU" and note_type == 5 and len(descriptor) >= 16:
            # NT_GNU_PROPERTY_TYPE_0: (type, datasz, data) per property
            inner = 0
            while inner + 8 <= len(descriptor):
                prop_type, prop_size = struct.unpack_from("<II", descriptor, inner)
                prop_data = descriptor[inner + 8:inner + 8 + prop_size]
                if prop_type == 0xC0000002 and len(prop_data) >= 4:   # X86_FEATURE_1_AND
                    bits = struct.unpack_from("<I", prop_data, 0)[0]
                    if bits & 0x1:
                        features.append("IBT")
                    if bits & 0x2:
                        features.append("SHSTK")
                elif prop_type == 0xC0000000:
                    if len(prop_data) >= 4:
                        features.append(f"stack-align-{struct.unpack_from('<I', prop_data, 0)[0]}")
                inner += 8 + prop_size + ((8 - prop_size % 8) % 8)
        position = desc_start + desc_size + ((4 - desc_size % 4) % 4)
    if features:
        out["cpu_features"] = sorted(set(features))


def _elf_hardening(reader: _Reader, data: bytes, by_name: dict[str, Any],
                   out: dict[str, Any], end: str) -> None:
    """Summarise the exploit-mitigation posture actually present in the file."""
    imports = set(out.get("imports") or [])
    exports = set(out.get("exports") or [])
    segments = set(out.get("segments") or [])
    hardening: dict[str, Any] = {
        "pie": bool(out.get("pie")),
        "nx": (not out.get("executable_stack")) if "gnu_stack" in segments else None,
        "relro": "gnu_relro" in segments,
        "canary": "__stack_chk_fail" in imports or "__stack_chk_fail" in exports,
        "fortified": any(name.endswith("_chk") for name in imports),
        "bind_now": False,
    }
    dynamic = by_name.get(".dynamic")
    if dynamic:
        for index in range(min(dynamic["size"] // 16, 4096)):
            try:
                tag, value = reader.unpack(end + "QQ", dynamic["offset"] + index * 16)
            except Exception:  # noqa: BLE001
                break
            if tag == 0:
                break
            if tag == 24:                      # DT_BIND_NOW
                hardening["bind_now"] = True
            elif tag == 30 and value & 8:      # DT_FLAGS: DF_BIND_NOW
                hardening["bind_now"] = True
            elif tag == 0x6FFFFFFB and value & 1:   # DT_FLAGS_1: DF_1_NOW
                hardening["bind_now"] = True
    hardening["full_relro"] = bool(hardening["relro"] and hardening["bind_now"])
    out["hardening"] = hardening


def _crypto_constants(data: bytes, sections: list[dict[str, Any]],
                      by_name: dict[str, Any]) -> dict[str, Any]:
    """Look for known crypto constant tables in code and read-only data.

    The universal-crypto detector can only raise evidence to CONSTANT_MATCH when
    it is handed the exact constant blob, so this scans the loadable content for
    each known table and passes through the ones that are really there. Finding
    the AES S-box or the SHA-256 K table is implementation evidence (0.9), which
    is much stronger than a symbol name or a banner string — and it also works on
    stripped, statically linked binaries that have no symbols at all.
    """
    from universal_crypto.binary_engine import CRYPTO_CONSTANTS

    blobs: list[bytes] = []
    found: list[dict[str, Any]] = []
    budget = MAX_CONSTANT_WINDOW
    windows: list[tuple[str, bytes]] = []
    for section in sections:
        name = str(section.get("name") or "")
        if name not in (".text", ".rodata", ".data", ".data.rel.ro", ".init", ".plt",
                        ".rodata.1", ".data.rel.ro.local"):
            continue
        size = min(int(section.get("size") or 0), budget)
        if size <= 0:
            continue
        try:
            windows.append((name, data[section["offset"]:section["offset"] + size]))
            budget -= size
        except Exception:  # noqa: BLE001
            continue
        if budget <= 0:
            break
    for algorithm, constant in CRYPTO_CONSTANTS.items():
        for section_name, window in windows:
            index = window.find(constant)
            if index < 0:
                continue
            blobs.append(constant)
            found.append({
                "algorithm": algorithm,
                "section": section_name,
                "offset": int(index),
                "signature": constant[:8].hex(),
                "evidence": "constant table present in the file",
            })
            break
    return {"blobs": blobs, "found": found}


def detect_packer(sections: Iterable[dict[str, Any]] | Iterable[str],
                  text: str = "") -> dict[str, Any] | None:
    """Recognise a known packer from section names or embedded markers.

    Packing matters for a crypto scanner specifically: a packed binary carries
    neither readable strings nor a symbol table, so "no crypto found" inside one
    means "nothing was visible", which the caller must not read as clean.
    """
    names = {str(section.get("name") if isinstance(section, dict) else section or "")
             for section in sections}
    haystack = " ".join(sorted(names))
    for packer, markers in PACKER_SIGNATURES:
        hits = [marker for marker in markers if marker in haystack]
        if not hits and text:
            hits = [marker for marker in markers if marker in text]
        if hits:
            return {"name": packer, "markers": sorted(set(hits))[:4],
                    "note": ("packed/obfuscated content hides strings and symbols, so string-level "
                             "crypto detection is structurally incomplete here")}
    return None


def _elf_dynamic(reader: _Reader, sections: list[dict[str, Any]], by_name: dict[str, Any],
                 end: str, word: str, out: dict[str, Any]) -> None:
    dynamic = by_name.get(".dynamic")
    dynstr = by_name.get(".dynstr")
    if not dynamic or not dynstr:
        return
    try:
        strtab = reader.take(dynstr["offset"], dynstr["size"])
    except Exception:  # noqa: BLE001
        return
    entry = 16 if word == "Q" else 8
    for index in range(min(dynamic["size"] // entry, 4096)):
        try:
            tag, value = reader.unpack(end + word + word, dynamic["offset"] + index * entry)
        except Exception:  # noqa: BLE001
            break
        if tag == 0:
            break
        if tag in (1, 14, 15, 29):        # NEEDED / SONAME / RPATH / RUNPATH
            name = _cstr(strtab, value)
            if not name:
                continue
            if tag == 1 and name not in out["libraries"]:
                out["libraries"].append(name)
            elif tag == 14:
                out["soname"] = name
            elif name not in out["rpath"]:
                out["rpath"].append(name)


def _elf_symbols(reader: _Reader, sections: list[dict[str, Any]], by_name: dict[str, Any],
                 end: str, word: str, out: dict[str, Any]) -> None:
    section = by_name.get(".dynsym") or by_name.get(".symtab")
    if not section:
        return
    strtab = b""
    try:
        linked = sections[section["link"]] if section["link"] < len(sections) else None
        if linked:
            strtab = reader.take(linked["offset"], linked["size"])
    except Exception:  # noqa: BLE001
        strtab = b""
    if not strtab:
        return
    entry = 24 if word == "Q" else 16
    imports: list[str] = []
    exports: list[str] = []
    for index in range(min(section["size"] // entry, 60000)):
        try:
            base = section["offset"] + index * entry
            st_name = reader.unpack(end + "I", base)[0]
            st_info = reader.data[base + 4]
            st_shndx = reader.unpack(end + "H", base + 6)[0]
        except Exception:  # noqa: BLE001
            break
        name = _cstr(strtab, st_name)
        if not name:
            continue
        if st_shndx == 0:
            imports.append(name)
        elif (st_info >> 4) in (1, 2):
            exports.append(name)
    out["imports"] = imports[:3000]
    out["exports"] = exports[:3000]
    out["import_count"] = len(imports)
    out["export_count"] = len(exports)


#: Go's module blob is a block of tab-separated key/value lines that begins with
#: the toolchain (``go\tgo1.21.5``) and carries the module path and every
#: dependency with its exact version and checksum.
_GO_MODINFO_RE = re.compile(rb"go\tgo1\.[\x20-\x7e\t\n]{8,60000}")
_GO_VERSION_RE = re.compile(rb"go1\.\d+(?:\.\d+)?(?:[a-z0-9]+)?")


def parse_go_buildinfo(data: bytes, by_name: dict[str, Any], reader: _Reader) -> dict[str, Any] | None:
    """Go toolchain + module graph from a binary's build info.

    Header format (Go 1.18+, ``runtime/debug.buildInfoHeader``): magic
    0xFFFFFFF1 (inline) or 0xFFFFFFF0 (pointer form), an 18-byte version string
    at offset 4, the pointer size at offset 22, then padding to 32 bytes.

    The toolchain version is read from that header (reliable). The module graph
    is read from the NUL-terminated modinfo blob wherever it sits in the file,
    because in the pointer form the graph is *not* inside the header — guessing
    offsets there would be exactly the kind of invention this platform avoids.
    """
    section = by_name.get(".go.buildinfo")
    offset = section["offset"] if section else None
    window = data
    if offset is None:
        # Section table stripped or patched: Go's own debug/buildinfo falls back to
        # scanning for the header magic, so this does too (bounded to 64 MiB).
        window = data[:64 * 1024 * 1024]
        for magic in (b"\xff\xff\xff\xf1", b"\xff\xff\xff\xf0"):
            index = window.find(magic)
            while 0 <= index:
                candidate = window[index:index + 22]
                if candidate[4:6] == b"go" and candidate[6:7].isdigit():
                    offset = index
                    break
                index = window.find(magic, index + 1)
            if offset is not None:
                break
    if offset is None:
        return None
    try:
        header = reader.take(offset, 64)
    except Exception:  # noqa: BLE001
        return None
    if header[:4] not in (b"\xff\xff\xff\xf1", b"\xff\xff\xff\xf0"):
        return None
    version = header[4:22].split(b"\x00")[0].decode("ascii", "replace").strip()
    pointer_size = header[22] if len(header) > 22 else 8
    out: dict[str, Any] = {"go_version": version or None, "pointer_size": pointer_size,
                           "inline_modinfo": header[:4] == b"\xff\xff\xff\xf1"}

    blob = None
    if out["inline_modinfo"]:
        try:
            span = (section["size"] if section else 60000) - 32
            span = min(max(span, 256), 40000, max(len(data) - offset - 32, 0))
            blob = _find_modinfo(reader.take(offset + 32, span))
        except Exception:  # noqa: BLE001
            blob = None
    if blob is None:
        # pointer form: the module graph is not where the header points, so find
        # the block by its own structure anywhere in the file — it must carry the
        # toolchain line, which keeps a random "path\t" string out of the result
        blob = _find_modinfo(data[:FIRMWARE_SCAN_LIMIT])
    if blob is None:
        out["dependencies"] = []
        out["modinfo"] = "not located (pointer-form build info carries it outside the section)"
        return out

    text = blob.decode("utf-8", "replace")
    dependencies: list[dict[str, Any]] = []
    module: str | None = None
    main_version: str | None = None
    replacements: list[dict[str, Any]] = []
    for line in text.split("\n"):
        if not line.strip():
            continue
        fields = [field.strip() for field in line.split("\t")]
        key = fields[0]
        if key == "go" and len(fields) >= 2:
            out.setdefault("toolchain", fields[1])
        elif key == "path" and len(fields) >= 2 and not module:
            module = fields[1]
        elif key == "mod" and len(fields) >= 2:
            module = module or fields[1]
            if len(fields) >= 3 and fields[2]:
                main_version = fields[2]
        elif key == "dep" and len(fields) >= 3:
            dependencies.append({
                "name": fields[1], "version": fields[2] or None, "kind": "dep",
                "sum": fields[3] or None if len(fields) > 3 else None,
            })
        elif key == "build" and len(fields) >= 2:
            out.setdefault("build_flags", []).append(fields[1])
        elif key == "=>" and len(fields) >= 3:
            replacements.append({"to": fields[1], "version": fields[2] or None})
        elif len(fields) >= 2 and re.match(r"^v\d", fields[1]) and "/" in fields[0]:
            # defensive: a dependency line whose key field was mangled
            dependencies.append({"name": fields[0], "version": fields[1], "kind": "dep",
                                 "sum": fields[2] if len(fields) > 2 else None})
    out["module"] = module
    if main_version:
        out["module_version"] = main_version
    if replacements:
        out["replacements"] = replacements
    out["dependencies"] = dependencies
    out["dependency_count"] = len(dependencies)
    return out


def _find_modinfo(window: bytes) -> bytes | None:
    """Locate the Go module graph block inside a buffer.

    The block is self-describing: tab-separated ``key<TAB>value`` lines that
    include the toolchain (``go\tgo1.21.5``) and the module path. Anything that
    does not carry the toolchain line is not build info, so it is rejected rather
    than reported as a dependency list.
    """
    for match in _GO_MODINFO_RE.finditer(window):
        candidate = match.group(0).split(b"\x00")[0]
        if b"path\t" in candidate or b"mod\t" in candidate:
            return candidate
    return None

# ------------------------------------------------------------------- PE ----- #
def parse_pe(data: bytes) -> dict[str, Any]:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("not a PE file")
    reader = _Reader(data)
    e_lfanew = reader.unpack("<I", 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("missing PE signature")
    coff = e_lfanew + 4
    machine, section_count = reader.unpack("<HH", coff)
    timestamp = reader.unpack("<I", coff + 4)[0]
    optional_size = reader.unpack("<H", coff + 16)[0]
    characteristics = reader.unpack("<H", coff + 18)[0]
    optional = coff + 20
    magic = reader.unpack("<H", optional)[0]
    is64 = magic == 0x20B
    out: dict[str, Any] = {
        "format": "pe", "bits": 64 if is64 else 32,
        "machine": PE_MACHINES.get(machine, f"0x{machine:04x}"),
        "arch": PE_MACHINES.get(machine, "unknown"),
        "type": "dll" if characteristics & 0x2000 else "executable",
        "libraries": [], "imports": [], "exports": [],
    }
    if timestamp:
        from datetime import datetime, timezone

        out["coff_timestamp"] = timestamp
        try:
            out["built"] = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
        except Exception:  # noqa: BLE001 — an absurd timestamp is just not shown
            pass
    try:
        subsystem = reader.unpack("<H", optional + 68)[0]
        out["subsystem"] = PE_SUBSYSTEMS.get(subsystem, str(subsystem))
        if subsystem in (10, 11, 12, 13):
            out["uefi"] = True
            out["type"] = "efi-image"
    except Exception:  # noqa: BLE001
        pass
    try:
        dll_characteristics = reader.unpack("<H", optional + 70)[0]
    except Exception:  # noqa: BLE001 — an image too short for the field is just not scored
        dll_characteristics = 0
    hardening: dict[str, Any] = {"dll_characteristics": hex(dll_characteristics)}
    for bit, (label, expected) in PE_DLL_CHARACTERISTICS.items():
        hardening[label] = bool(dll_characteristics & bit) if expected else not bool(
            dll_characteristics & bit)
    out["hardening"] = hardening

    number_of_dirs = reader.unpack("<I", optional + (108 if is64 else 92))[0]
    directory_base = optional + (112 if is64 else 96)

    sections: list[tuple[int, int, int, int, str]] = []
    table = optional + optional_size
    for index in range(min(section_count, 96)):
        base = table + index * 40
        try:
            name = data[base:base + 8].rstrip(b"\x00").decode("ascii", "replace")
            virtual_size, virtual_address, raw_size, raw_offset = reader.unpack("<IIII", base + 8)
        except Exception:  # noqa: BLE001
            continue
        sections.append((virtual_address, virtual_size, raw_offset, raw_size, name))
        if name:
            out.setdefault("sections", []).append(name)

    def rva_to_offset(rva: int) -> int | None:
        for virtual_address, virtual_size, raw_offset, raw_size, _name in sections:
            span = max(virtual_size, raw_size)
            if virtual_address <= rva < virtual_address + span:
                return raw_offset + (rva - virtual_address)
        return None

    directories: list[tuple[int, int]] = []
    for index in range(min(number_of_dirs, 16)):
        try:
            directories.append(reader.unpack("<II", directory_base + index * 8))
        except Exception:  # noqa: BLE001
            directories.append((0, 0))
    if len(directories) > 1:
        import_rva, import_size = directories[1]
        out["libraries"] = _pe_imports(reader, import_rva, import_size, rva_to_offset)
    if len(directories) > 13:
        delay_rva, delay_size = directories[13]
        delayed = _pe_delay_imports(reader, delay_rva, delay_size, rva_to_offset)
        if delayed:
            out["delay_imports"] = delayed
            for dll in delayed:
                if dll not in out["libraries"]:
                    out["libraries"].append(dll)
    if len(directories) > 2:
        resource_rva, resource_size = directories[2]
        resources = _pe_resources(reader, resource_rva, resource_size, rva_to_offset)
        if resources:
            out["resources"] = resources
            for key in ("version", "vendor", "product", "description"):
                if resources.get(key):
                    out.setdefault("version_info", {})[key] = resources[key]
    if len(directories) > 6:
        debug_rva, debug_size = directories[6]
        debug = _pe_debug_directory(reader, debug_rva, debug_size, rva_to_offset)
        if debug:
            out["debug"] = debug
    if len(directories) > 4:
        cert_offset, cert_size = directories[4]
        if cert_offset and cert_size:
            out["signature"] = _pe_certificate(reader, cert_offset, cert_size)
        else:
            out["signature"] = {"present": False,
                                "note": "no Authenticode certificate table — unsigned or stripped"}
    if len(directories) > 14:
        clr_rva, clr_size = directories[14]
        if clr_rva and clr_size:
            clr_offset = rva_to_offset(clr_rva)
            out["dotnet"] = True
            out["framework"] = ".NET"
            if clr_offset is not None:
                metadata = _pe_dotnet_metadata(reader, clr_offset, rva_to_offset)
                if metadata:
                    out["dotnet"] = metadata
                    version_label = (metadata.get("framework_version")
                                     or metadata.get("runtime_version") or "")
                    out["framework"] = f".NET {version_label}".strip()
    if len(directories) > 10:
        load_config_rva, load_config_size = directories[10]
        if load_config_rva and load_config_size:
            load_config = _pe_load_config(reader, load_config_rva, load_config_size, rva_to_offset,
                                          is64)
            if load_config:
                out["load_config"] = load_config
                hardening["gs"] = bool(load_config.get("security_cookie"))
                if load_config.get("guard_flags") is not None:
                    # GUARD_CF says the image was *compiled* with CFG; the guard flags
                    # say whether the check function is actually wired up
                    hardening["cfg_instrumented"] = bool(
                        load_config["guard_flags"] & PE_GUARD_CF_INSTRUMENTED)
    rich = _pe_rich_header(data)
    if rich:
        out["linker"] = rich
    out["imports"] = [f"{dll}!" for dll in out["libraries"]]
    return out


def _pe_load_config(reader: _Reader, rva: int, size: int, rva_to_offset,
                    is64: bool) -> dict[str, Any]:
    """IMAGE_LOAD_CONFIG_DIRECTORY: /GS cookie, CFG guard flags, SafeSEH table.

    The mitigation *policy* lives in DllCharacteristics; the load config says
    whether the mechanism is actually initialised (a security cookie pointer that
    is not null, CFG instrumented), which is the difference between "built with
    /GS" and "the stack cookie is live in this image".
    """
    offset = rva_to_offset(rva)
    if offset is None:
        return {}
    try:
        out: dict[str, Any] = {}
        declared = reader.unpack("<I", offset)[0]
        out["declared_size"] = declared
        if is64:
            cookie = reader.unpack("<Q", offset + 0x40)[0]
            seh_table = reader.unpack("<Q", offset + 0x58)[0]
            guard_flags = reader.unpack("<I", offset + 0x70)[0]
        else:
            cookie = reader.unpack("<I", offset + 0x3C)[0]
            seh_table = reader.unpack("<I", offset + 0x40)[0]
            guard_flags = reader.unpack("<I", offset + 0x48)[0]
        out["security_cookie"] = hex(cookie) if cookie else None
        out["safe_seh_table"] = hex(seh_table) if seh_table else None
        out["guard_flags"] = guard_flags
        return out
    except Exception:  # noqa: BLE001 — a truncated load config is simply not scored
        return {}


def _pe_delay_imports(reader: _Reader, rva: int, size: int, rva_to_offset) -> list[str]:
    """Delay-loaded DLLs are dependencies too — a crypto DLL can hide here."""
    if not rva or not size:
        return []
    offset = rva_to_offset(rva)
    if offset is None:
        return []
    names: list[str] = []
    for index in range(64):
        try:
            _attrs, name_rva = reader.unpack("<II", offset + index * 32)
        except Exception:  # noqa: BLE001
            break
        if not name_rva:
            break
        name_offset = rva_to_offset(name_rva)
        if name_offset is None:
            continue
        end = reader.data.find(b"\x00", name_offset, name_offset + 256)
        if end < 0:
            continue
        name = reader.data[name_offset:end].decode("ascii", "replace")
        if name and name not in names:
            names.append(name)
    return names


def _pe_resources(reader: _Reader, rva: int, size: int, rva_to_offset) -> dict[str, Any]:
    """Version information out of the resource tree (RT_VERSION / id 1)."""
    if not rva or not size:
        return {}
    root = rva_to_offset(rva)
    if root is None:
        return {}

    def _entries(directory_offset: int) -> list[tuple[int, int]]:
        try:
            _chars, _ts, _major, _minor, named, ids = reader.unpack("<IIHHHH", directory_offset)
        except Exception:  # noqa: BLE001
            return []
        found: list[tuple[int, int]] = []
        for index in range(min(named + ids, 256)):
            try:
                name, child = reader.unpack("<II", directory_offset + 16 + index * 8)
            except Exception:  # noqa: BLE001
                break
            found.append((name & 0x7FFFFFFF, child))
        return found

    def _child_offset(child: int) -> int:
        """Resource entries point at another directory (high bit set) or at data."""
        return root + (child & 0x7FFFFFFF) if child & 0x80000000 else root + child

    data_entry: int | None = None
    for resource_type, type_child in _entries(root):
        if resource_type != 16:                       # RT_VERSION
            continue
        for _name, name_child in _entries(_child_offset(type_child)):
            for _lang, lang_child in _entries(_child_offset(name_child)):
                data_entry = _child_offset(lang_child)
                break
            if data_entry:
                break
        if data_entry:
            break
    if data_entry is None:
        return {}
    try:
        data_rva, data_size, _codepage, _reserved = reader.unpack("<IIII", data_entry)
    except Exception:  # noqa: BLE001
        return {}
    offset = rva_to_offset(data_rva)
    if offset is None:
        return {}
    return _parse_version_info(reader.data[offset:offset + min(data_size, 65536)])


def _vi_align4(value: int) -> int:
    return value + ((4 - value % 4) % 4)


def _vi_block(blob: bytes, position: int) -> tuple[int, int, int, int, str] | None:
    """One VS_VERSIONINFO block: (start, length, value_length, value_start, key).

    Keys are UTF-16LE NUL-terminated and 4-byte aligned; ``value_length`` is
    counted in bytes for fixed/Var blocks and in UTF-16 code units for String
    entries, so the caller decides how to interpret it.
    """
    if position + 6 > len(blob):
        return None
    try:
        length, value_length, _block_type = struct.unpack_from("<HHH", blob, position)
    except Exception:  # noqa: BLE001
        return None
    if length <= 0 or position + length > len(blob):
        return None
    # the key is a NUL-terminated UTF-16LE string; walk code units so an odd
    # byte offset can never shift the value that follows it
    cursor = position + 6
    while cursor + 1 < len(blob) and blob[cursor:cursor + 2] != b"\x00\x00":
        cursor += 2
    if cursor + 1 >= len(blob):
        return None
    key = blob[position + 6:cursor].decode("utf-16-le", "replace").strip("\x00")
    value_start = _vi_align4(cursor + 2)
    return position, length, value_length, value_start, key


def _vi_children_start(block: tuple, *, value_in_bytes: bool) -> int:
    _position, _length, value_length, value_start, _key = block
    size = value_length if value_in_bytes else value_length * 2
    return _vi_align4(value_start + size)


def _parse_version_info(blob: bytes) -> dict[str, Any]:
    """VS_VERSIONINFO: fixed file info, StringFileInfo pairs and VarFileInfo.

    The real structure is three levels deep (root → StringFileInfo → StringTable →
    String), so the walk descends instead of stopping at the first block.
    """
    out: dict[str, Any] = {}
    root = _vi_block(blob, 0)
    if root is None or root[4] != "VS_VERSION_INFO":
        return out
    _start, root_length, _root_value_length, fixed_start, _key = root
    if fixed_start + 52 <= len(blob) and struct.unpack_from("<I", blob, fixed_start)[0] == 0xFEEF04BD:
        fields = struct.unpack_from("<13I", blob, fixed_start)
        out["file_version"] = (f"{fields[2] >> 16}.{fields[2] & 0xFFFF}."
                               f"{fields[3] >> 16}.{fields[3] & 0xFFFF}")
        out["product_version"] = (f"{fields[4] >> 16}.{fields[4] & 0xFFFF}."
                                  f"{fields[5] >> 16}.{fields[5] & 0xFFFF}")
        out["file_flags"] = fields[6]
        out["file_type"] = {1: "application", 2: "dll", 3: "driver"}.get(fields[9], fields[9])

    strings: dict[str, str] = {}
    position = _vi_children_start(root, value_in_bytes=True)
    root_end = root[0] + root_length
    while position + 6 <= root_end:
        block = _vi_block(blob, position)
        if block is None:
            break
        _bstart, blength, _bvalue_length, _bvalue_start, key = block
        if key == "StringFileInfo":
            table_position = _vi_children_start(block, value_in_bytes=True)
            table_end = block[0] + blength
            while table_position + 6 <= table_end:
                table = _vi_block(blob, table_position)
                if table is None:
                    break
                _tstart, tlength, _tv, _tvs, table_key = table
                if table_key:
                    out.setdefault("translations", []).append(table_key)
                entry_position = _vi_children_start(table, value_in_bytes=True)
                entry_end = table[0] + tlength
                while entry_position + 6 <= entry_end:
                    entry = _vi_block(blob, entry_position)
                    if entry is None:
                        break
                    _estart, elength, evalue_length, evalue_start, name = entry
                    value = blob[evalue_start:evalue_start + evalue_length * 2] \
                        .decode("utf-16-le", "replace").strip("\x00")
                    if name and value:
                        strings[name] = value
                    entry_position = _vi_align4(entry[0] + elength)
                table_position = _vi_align4(table[0] + tlength)
        elif key == "VarFileInfo":
            var_position = _vi_children_start(block, value_in_bytes=True)
            var_end = block[0] + blength
            while var_position + 6 <= var_end:
                var = _vi_block(blob, var_position)
                if var is None:
                    break
                _vstart, vlength, vvalue_length, vvalue_start, var_key = var
                if var_key == "Translation" and vvalue_length >= 2:
                    pairs = []
                    for index in range(min(vvalue_length // 4, 16)):
                        language, codepage = struct.unpack_from("<HH", blob, vvalue_start + index * 4)
                        pairs.append({"language": language, "codepage": codepage})
                    if pairs:
                        out["translation"] = pairs
                var_position = _vi_align4(var[0] + vlength)
        position = _vi_align4(block[0] + blength)

    if strings:
        out["strings"] = strings
    for source_key, target in VERSION_INFO_KEYS.items():
        if target in out or target == "version":
            continue
        if strings.get(source_key):
            out[target] = strings[source_key]
    if strings.get("FileVersion") and not out.get("version"):
        out["version"] = strings["FileVersion"]
    if strings.get("ProductVersion") and not out.get("product_version"):
        out["product_version"] = strings["ProductVersion"]
    return out


def _pe_debug_directory(reader: _Reader, rva: int, size: int, rva_to_offset) -> dict[str, Any]:
    """CodeView debug entries: the PDB path and its build identity.

    A PDB path leaks the build machine's directory layout, and the GUID/age pair
    is the key Microsoft's symbol server uses — both are useful provenance, and
    neither is a guess.
    """
    if not rva or not size:
        return {}
    offset = rva_to_offset(rva)
    if offset is None:
        return {}
    out: dict[str, Any] = {}
    for index in range(min(size // 28, 16)):
        try:
            _chars, _ts, _major, _minor, entry_type, entry_size, entry_rva, entry_offset = (
                reader.unpack("<IIHHIIII", offset + index * 28))
        except Exception:  # noqa: BLE001
            break
        if entry_type != 2:                       # IMAGE_DEBUG_TYPE_CODEVIEW
            continue
        start = rva_to_offset(entry_rva) if entry_rva else entry_offset
        if start is None:
            continue
        try:
            blob = reader.data[start:start + min(entry_size, 4096)]
        except Exception:  # noqa: BLE001
            continue
        if blob[:4] == b"RSDS":
            raw = blob[24:].split(b"\x00")[0]
            out["pdb"] = raw.decode("utf-8", "replace")
            out["pdb_guid"] = blob[4:20].hex()
            out["pdb_age"] = struct.unpack_from("<I", blob, 20)[0]
        elif blob[:4] == b"NB10":
            out["pdb"] = blob[16:].split(b"\x00")[0].decode("utf-8", "replace")
        break
    return out


def _pe_certificate(reader: _Reader, offset: int, size: int) -> dict[str, Any]:
    """Authenticode presence — reported, never asserted as valid.

    Verifying a PKCS#7 signature needs a trust store and an ASN.1 parser; this
    scanner does not have one, so it says exactly that instead of printing
    "signed and verified".
    """
    try:
        length, revision, cert_type = reader.unpack("<IHH", offset)
    except Exception:  # noqa: BLE001
        return {"present": True, "note": "certificate table present but unreadable"}
    entries = 0
    position = offset
    end = offset + max(size, 0)
    while position + 8 <= end and entries < 32:
        try:
            entry_length = reader.unpack("<I", position)[0]
        except Exception:  # noqa: BLE001
            break
        if entry_length <= 0:
            break
        entries += 1
        position += entry_length + ((8 - entry_length % 8) % 8)
    return {
        "present": True,
        "entries": entries or 1,
        "size": int(length),
        "revision": {0x100: "1.0", 0x200: "2.0"}.get(revision, str(revision)),
        "type": {1: "x509", 2: "pkcs7"}.get(cert_type, str(cert_type)),
        "note": ("Authenticode signature present; this scanner reports presence and size "
                 "only — validity and chain are NOT verified here"),
    }


def _pe_dotnet_metadata(reader: _Reader, clr_offset: int, rva_to_offset) -> dict[str, Any]:
    """CLR header → metadata version string (e.g. v4.0.30319) and flags."""
    try:
        (_cb, major, minor, meta_rva, meta_size, flags,
         _entry) = reader.unpack("<IHHIIII", clr_offset)
    except Exception:  # noqa: BLE001
        return {}
    out: dict[str, Any] = {"runtime_version": f"v{major}.{minor}",
                           "flags": hex(flags), "metadata_size": int(meta_size)}
    offset = rva_to_offset(meta_rva)
    if offset is None:
        return out
    try:
        if reader.data[offset:offset + 4] != b"BSJB":
            return out
        version_length = reader.unpack("<I", offset + 12)[0]
        raw = reader.take(offset + 16, min(version_length, 128)).split(b"\x00")[0]
        out["framework_version"] = raw.decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        pass
    return out


def _pe_rich_header(data: bytes) -> dict[str, Any] | None:
    """The Rich header names the linker build that produced the file.

    It is XOR-obfuscated with a key stored after the ``Rich`` marker; the
    ``DanS`` marker ends the block. Microsoft tooling uses it to attribute
    binaries to a toolchain, and so can we — no guessing involved.
    """
    rich = data.find(b"Rich", 0x80, 0x1000)
    if rich < 0 or rich + 8 > len(data):
        return None
    key = struct.unpack_from("<I", data, rich + 4)[0]
    dan = data.rfind(b"DanS", 0x80, rich)
    if dan < 0:
        return None
    entries: list[dict[str, int]] = []
    position = dan + 4
    while position + 8 <= rich and len(entries) < 32:
        low, high = struct.unpack_from("<II", data, position)
        low ^= key
        high ^= key
        if low or high:
            entries.append({"product_id": high >> 16, "build": high & 0xFFFF, "count": low})
        position += 8
    if not entries:
        return None
    return {"entries": entries,
            "note": "linker product id/build pairs (Rich header) — attribution evidence only"}


def _pe_imports(reader: _Reader, rva: int, size: int, rva_to_offset) -> list[str]:
    if not rva:
        return []
    offset = rva_to_offset(rva)
    if offset is None:
        return []
    libraries: list[str] = []
    for index in range(128):
        try:
            name_rva = reader.unpack("<I", offset + index * 20 + 12)[0]
        except Exception:  # noqa: BLE001
            break
        if not name_rva:
            break
        name_offset = rva_to_offset(name_rva)
        if name_offset is None:
            continue
        end = reader.data.find(b"\x00", name_offset, name_offset + 256)
        if end < 0:
            continue
        name = reader.data[name_offset:end].decode("ascii", "replace")
        if name and name not in libraries:
            libraries.append(name)
    return libraries


# --------------------------------------------------------------- Mach-O ----- #
def parse_macho(data: bytes) -> dict[str, Any]:
    if len(data) < 8:
        raise ValueError("too short")
    if struct.unpack_from(">I", data, 0)[0] in (0xCAFEBABE, 0xBEBAFECA):
        count = struct.unpack_from(">I", data, 4)[0] if struct.unpack_from(">I", data, 0)[0] == 0xCAFEBABE else 0
        if not (0 < count <= 20):
            raise ValueError("not a fat Mach-O")
        architectures: list[dict[str, Any]] = []
        for index in range(min(count, 20)):
            try:
                cpu, sub, offset, size = struct.unpack_from(">IIII", data, 8 + index * 20)
            except Exception:  # noqa: BLE001
                break
            architectures.append({"cpu": MACHO_CPUS.get(cpu, hex(cpu)),
                                  "subtype": sub, "size": size, "offset": offset})
        out: dict[str, Any] = {"format": "macho", "type": "universal",
                               "architectures": architectures, "libraries": [],
                               "slices": [row["cpu"] for row in architectures]}
        # parse the slice the host would pick first, but keep every slice listed
        preferred = next((row for row in architectures
                          if row["cpu"] in ("AArch64", "x86-64")), None) \
            or (architectures[0] if architectures else None)
        if preferred and preferred["offset"]:
            sliced = data[preferred["offset"]:preferred["offset"] + preferred["size"]]
            try:
                thin = _parse_macho_thin(sliced)
                out.update({k: v for k, v in thin.items() if k not in ("format", "type")})
                out["type"] = "universal"
                out["architectures"] = architectures
                out["slices"] = [row["cpu"] for row in architectures]
                out["parsed_slice"] = preferred["cpu"]
            except Exception:  # noqa: BLE001
                pass
        return out
    return _parse_macho_thin(data)


def _macho_version(value: int) -> str:
    """Mach-O packs a version into 32 bits as X.Y.Z (16/8/8)."""
    return f"{value >> 16}.{(value >> 8) & 0xFF}.{value & 0xFF}"


def _macho_symbols(data: bytes, end: str, is64: bool, symoff: int, nsyms: int, stroff: int,
                   strsize: int, dysymtab: tuple[int, ...] | None,
                   limit: int = 4000) -> tuple[list[str], list[str], int]:
    """External symbols from LC_SYMTAB (optionally classified by LC_DYSYMTAB).

    A Mach-O import table names the frameworks and functions the binary calls —
    ``_CCCryptorCreate`` (CommonCrypto), ``_SecKeyEncrypt`` (Security) or a
    statically linked ``_EVP_EncryptInit_ex`` — which is exactly the evidence
    level the crypto engine grades highest short of a constant table.
    """
    if not symoff or not nsyms or stroff + strsize > len(data) or symoff >= len(data):
        return [], [], 0
    entry = 16 if is64 else 12
    defined_range: range = range(0)
    undefined_range: range = range(0)
    if dysymtab and len(dysymtab) >= 6:
        iextdef, nextdef, iundef, nundef = dysymtab[2], dysymtab[3], dysymtab[4], dysymtab[5]
        defined_range = range(iextdef, min(iextdef + nextdef, nsyms))
        undefined_range = range(iundef, min(iundef + nundef, nsyms))
    imports: list[str] = []
    exports: list[str] = []
    seen = 0
    for index in range(min(nsyms, limit)):
        base = symoff + index * entry
        if base + entry > len(data):
            break
        try:
            strx, n_type = struct.unpack_from(end + "IB", data, base)
        except Exception:  # noqa: BLE001
            break
        if not strx or stroff + strx >= len(data):
            continue
        raw = data[stroff + strx:stroff + strx + 512].split(b"\x00")[0]
        if not raw or len(raw) > 256:
            continue
        name = raw.decode("utf-8", "replace")
        # dyld prefixes C symbols with an underscore; the C identifier is what the
        # fingerprint and algorithm tables are keyed on, so report it without it
        if name.startswith("_") and not name.startswith("__"):
            name = name[1:]
        seen += 1
        external = bool(n_type & 0x01)          # N_EXT
        undefined = (n_type & 0x0E) == 0        # N_UNDF
        if not external:
            continue
        if dysymtab and len(dysymtab) >= 6:
            if index in undefined_range:
                imports.append(name)
            elif index in defined_range:
                exports.append(name)
            continue
        (imports if undefined else exports).append(name)
    return imports[:2000], exports[:2000], seen


def _macho_code_signature(data: bytes, end: str, offset: int, size: int) -> dict[str, Any]:
    """Code-signature superblob: signing identity, entitlements, hash algorithm.

    Presence, identifier and entitlements are facts in the file; whether the
    signature *validates*, whether the certificate chains to Apple and whether
    the binary is notarised are NOT verified here and the result says so.
    """
    out: dict[str, Any] = {"present": False}
    if offset <= 0 or size <= 0 or offset + size > len(data):
        return out
    blob = data[offset:offset + size]
    if len(blob) < 12 or struct.unpack_from(">I", blob, 0)[0] != 0xFADE0CC0:
        return out
    out["present"] = True
    out["size"] = size
    count = struct.unpack_from(">I", blob, 8)[0]
    entries: dict[int, tuple[int, int]] = {}
    for index in range(min(count, 32)):
        try:
            blob_type, blob_offset = struct.unpack_from(">II", blob, 12 + index * 8)
        except Exception:  # noqa: BLE001
            break
        next_offset = size
        if index + 1 < count:
            try:
                next_offset = struct.unpack_from(">I", blob, 12 + (index + 1) * 8 + 4)[0]
            except Exception:  # noqa: BLE001
                pass
        entries[blob_type] = (blob_offset, max(next_offset - blob_offset, 0))
    out["blobs"] = sorted({MACHO_CS_TYPES.get(key, hex(key)) for key in entries})
    directory = entries.get(0)
    if directory:
        block = blob[directory[0]:directory[0] + directory[1]]
        if len(block) >= 44 and struct.unpack_from(">I", block, 0)[0] == 0xFADE0C02:
            version = struct.unpack_from(">I", block, 8)[0]
            flags = struct.unpack_from(">I", block, 12)[0]
            ident_offset = struct.unpack_from(">I", block, 20)[0]
            hash_type = block[37] if len(block) > 37 else 0
            out["identifier"] = _cstr(block, ident_offset).strip("\x00")
            out["flags"] = [name for bit, name in MACHO_CS_FLAGS.items() if flags & bit]
            out["flags_raw"] = hex(flags)
            out["hash_type"] = {1: "sha1", 2: "sha256", 3: "sha256-truncated",
                                4: "sha384"}.get(hash_type, str(hash_type))
            out["version"] = hex(version)
            if version >= 0x20200:
                team_offset = struct.unpack_from(">I", block, 48)[0]
                if team_offset:
                    out["team_id"] = _cstr(block, team_offset).strip("\x00")
            out["hardened_runtime"] = bool(flags & 0x10000)
    entitlements = entries.get(5) or entries.get(7)
    if entitlements:
        block = blob[entitlements[0]:entitlements[0] + entitlements[1]]
        if len(block) > 8 and struct.unpack_from(">I", block, 0)[0] == 0xFADE7171:
            xml = block[8:].decode("utf-8", "replace")
            keys = re.findall(r"<key>([^<]{1,120})</key>", xml)
            out["entitlements"] = sorted(set(keys))[:80]
            out["entitlement_count"] = len(keys)
            notable = [key for key in out["entitlements"] if key in MACHO_NOTABLE_ENTITLEMENTS]
            if notable:
                out["notable_entitlements"] = notable
    out["note"] = ("code signature present; this scanner reports the signing identifier, "
                   "team and entitlements only — signature validity, certificate chain and "
                   "notarisation are NOT verified here")
    return out


def _parse_macho_thin(data: bytes) -> dict[str, Any]:
    """One Mach-O slice: load commands, linked dylibs (with their versions),
    symbol table, code signature and hardening flags."""
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic == 0xFEEDFACE:
        end, is64 = "<", False
    elif magic == 0xFEEDFACF:
        end, is64 = "<", True
    elif magic == 0xCEFAEDFE:
        end, is64 = ">", False
    elif magic == 0xCFFAEDFE:
        end, is64 = ">", True
    else:
        raise ValueError("unsupported Mach-O magic")
    cpu, _sub, filetype, ncmds = struct.unpack_from(end + "IIII", data, 4)[:4]
    flags = struct.unpack_from(end + "I", data, 24)[0]
    out: dict[str, Any] = {
        "format": "macho", "bits": 64 if is64 else 32,
        "arch": MACHO_CPUS.get(cpu, hex(cpu)),
        "type": {1: "object", 2: "executable", 6: "dylib", 8: "bundle", 9: "dylib-stub",
                 11: "kext"}.get(filetype, "other"),
        "libraries": [], "imports": [], "exports": [], "rpath": [], "sections": [],
        "dylib_versions": {},
        "hardening": {"pie": bool(flags & 0x200000), "stack_exec": bool(flags & 0x20000),
                      "heap_exec": not bool(flags & 0x1000000)},
    }
    symtab: tuple[int, int, int, int] | None = None
    dysymtab: tuple[int, ...] | None = None
    signature_offset = signature_size = 0
    position = 32 if is64 else 28
    for _ in range(min(ncmds, 8192)):
        try:
            cmd, cmdsize = struct.unpack_from(end + "II", data, position)
        except Exception:  # noqa: BLE001
            break
        if cmdsize <= 0 or position + cmdsize > len(data):
            break
        try:
            if cmd in MACHO_DYLIB_COMMANDS or cmd == 0x0D:            # dylibs + own id
                name_offset, _ts, current, compat = struct.unpack_from(end + "IIII", data,
                                                                      position + 8)
                name = _cstr(data[position:position + cmdsize], name_offset)
                if name:
                    kind = "id" if cmd == 0x0D else MACHO_DYLIB_COMMANDS[cmd]
                    out["dylib_versions"][name] = {"current": _macho_version(current),
                                                   "compat": _macho_version(compat),
                                                   "kind": kind}
                    if kind != "id" and name not in out["libraries"]:
                        out["libraries"].append(name)
                    if kind == "id":
                        out["install_name"] = name
            elif cmd == 0x1B:                                        # LC_UUID
                out["uuid"] = data[position + 8:position + 24].hex()
            elif cmd in (0x24, 0x25, 0x2F, 0x30):                     # version-min commands
                platform, minos, sdk = struct.unpack_from(end + "III", data, position + 8)
                out.setdefault("platform", MACHO_PLATFORMS.get(
                    {0x24: 1, 0x25: 2, 0x2F: 3, 0x30: 4}.get(cmd, platform), str(platform)))
                out["minimum_os"] = _macho_version(minos)
                out["sdk"] = _macho_version(sdk)
                out["platform_source"] = "LC_VERSION_MIN"
            elif cmd == 0x32:                                         # LC_BUILD_VERSION
                platform, minos, sdk, _ntools = struct.unpack_from(end + "IIII", data,
                                                                   position + 8)
                out["platform"] = MACHO_PLATFORMS.get(platform, str(platform))
                out["minimum_os"] = _macho_version(minos)
                out["sdk"] = _macho_version(sdk)
                out["platform_source"] = "LC_BUILD_VERSION"
            elif cmd == 0x1C:                                         # LC_RPATH
                name_offset = struct.unpack_from(end + "I", data, position + 8)[0]
                rpath = _cstr(data[position:position + cmdsize], name_offset)
                if rpath and rpath not in out["rpath"]:
                    out["rpath"].append(rpath)
            elif cmd in (0x01, 0x19):                                 # LC_SEGMENT(_64)
                segname = _cstr(data[position + 8:position + 24], 0)
                if is64:
                    nsects = struct.unpack_from(end + "I", data, position + 64)[0]
                    section_base = position + 72
                    section_size = 80
                else:
                    nsects = struct.unpack_from(end + "I", data, position + 48)[0]
                    section_base = position + 56
                    section_size = 68
                for index in range(min(nsects, 64)):
                    base = section_base + index * section_size
                    if base + 16 > len(data):
                        break
                    sectname = _cstr(data[base:base + 16], 0)
                    if sectname:
                        out["sections"].append(f"{segname},{sectname}")
            elif cmd == 0x02:                                         # LC_SYMTAB
                symtab = struct.unpack_from(end + "IIII", data, position + 8)
            elif cmd == 0x0B:                                         # LC_DYSYMTAB
                dysymtab = struct.unpack_from(end + "IIIIII", data, position + 8)
            elif cmd == 0x1D:                                         # LC_CODE_SIGNATURE
                signature_offset, signature_size = struct.unpack_from(end + "II", data,
                                                                     position + 8)
            elif cmd in (0x21, 0x2C):                                 # encryption info
                _cryptoff, _cryptsize, cryptid = struct.unpack_from(end + "III", data,
                                                                    position + 8)
                if cryptid:
                    out["encrypted"] = True
                    out["encryption_id"] = cryptid
            elif cmd == 0x80000028:                                   # LC_MAIN
                out["entry_offset"] = struct.unpack_from(end + "Q", data, position + 8)[0]
        except Exception:  # noqa: BLE001 — a malformed command must not lose the file
            pass
        position += cmdsize

    if symtab:
        imports, exports, sampled = _macho_symbols(data, end, is64, *symtab, dysymtab)
        out["imports"] = imports
        out["exports"] = exports
        out["symbols_sampled"] = sampled
        out["stripped"] = not exports
    out["library_count"] = len(out["libraries"])
    if any(name.endswith(".so") or ".dylib" in name for name in out["libraries"]):
        out.setdefault("dependency_kind", "dynamic")
    if signature_offset:
        signature = _macho_code_signature(data, end, signature_offset, signature_size)
        if signature.get("present"):
            out["signature"] = signature
            if signature.get("hardened_runtime"):
                out["hardening"]["hardened_runtime"] = True
        else:
            out["signature"] = {"present": False,
                                "note": "no code-signature superblob found"}
    else:
        out["signature"] = {"present": False,
                            "note": "no LC_CODE_SIGNATURE — unsigned, or the signature was "
                                    "stripped"}
    return out


# ------------------------------------------------------------- archives ----- #
def parse_ar(data: bytes) -> dict[str, Any]:
    """ar archives (.a static libraries, .deb packages), including GNU long names."""
    members: list[dict[str, Any]] = []
    long_names = b""
    symbols = 0
    position = 8
    is_deb = data[8:20].startswith(b"debian-binary")
    while position + 60 <= len(data) and len(members) < 20000:
        try:
            header = data[position:position + 60]
            raw_name = header[0:16].decode("ascii", "replace").strip()
            size = int(header[48:58].decode("ascii", "replace").strip() or 0)
        except ValueError:
            break
        if size < 0 or position + 60 + size > len(data):
            break
        payload = data[position + 60:position + 60 + size]
        if raw_name == "//":                       # GNU long-name table
            long_names = payload
        elif raw_name in ("/", "/SYM64/"):         # symbol index — not a member
            symbols += 1
        else:
            name = raw_name.rstrip("/")
            if raw_name.startswith("/") and raw_name[1:].isdigit():
                offset = int(raw_name[1:])
                end = long_names.find(b"/\n", offset)
                if end < 0:
                    end = long_names.find(b"\x00", offset)
                name = long_names[offset:end if end > 0 else offset + 64].decode("utf-8", "replace")
            elif raw_name.endswith("/"):
                name = raw_name[:-1]
            if name:
                members.append({"name": name.strip(), "size": size})
        position += 60 + size + (size % 2)
    return {"format": "ar", "members": members[:2000], "member_count": len(members),
            "type": "deb" if is_deb else "static-library", "symbol_table_entries": symbols,
            "libraries": [], "imports": []}


def _zip_local_entries(data: bytes, limit: int = 2000):
    """Walk local file headers (name + payload) without loading a zip library."""
    position = 0
    for _ in range(limit):
        position = data.find(b"PK\x03\x04", position)
        if position < 0:
            return
        try:
            (_version, _flags, method, _time, _date, _crc,
             compressed, _uncompressed, name_length, extra_length) = struct.unpack_from(
                "<HHHHHIIIHH", data, position + 4)
            name = data[position + 30:position + 30 + name_length].decode("utf-8", "replace")
            start = position + 30 + name_length + extra_length
        except Exception:  # noqa: BLE001
            return
        yield {"name": name, "method": method,
               "payload": data[start:start + min(max(compressed, 0), 1 << 20)]}
        position = start + max(compressed, 0)


def _zip_member(data: bytes, suffix: str) -> bytes | None:
    import zlib

    for entry in _zip_local_entries(data, limit=4000):
        if not entry["name"].endswith(suffix):
            continue
        try:
            if entry["method"] == 0:
                return entry["payload"]
            if entry["method"] == 8:
                return zlib.decompress(entry["payload"], -15)
        except Exception:  # noqa: BLE001 — a corrupt member is skipped, not guessed
            return None
        return None
    return None


def parse_zip(data: bytes, name: str = "") -> dict[str, Any]:
    """Zip containers: jars, wheels, nupkgs, APKs — with their metadata."""
    entries = [entry["name"] for entry in _zip_local_entries(data)]
    lower = name.lower()
    out: dict[str, Any] = {"format": "zip", "entry_count": len(entries),
                           "entries": entries[:300], "libraries": [], "imports": []}
    if lower.endswith((".jar", ".war", ".ear")) or "META-INF/MANIFEST.MF" in entries:
        out["type"] = "java-archive"
        out["java"] = _java_metadata(data, entries)
        if any(entry.startswith("org/bouncycastle") for entry in entries):
            out["libraries"].append("BouncyCastle")
    elif lower.endswith(".whl") or any(entry.endswith(".dist-info/METADATA") for entry in entries):
        out["type"] = "python-wheel"
        out["python"] = _python_metadata(data, entries)
    elif lower.endswith(".nupkg") or any(entry.endswith(".nuspec") for entry in entries):
        out["type"] = "nuget-package"
        out["dotnet"] = True
    elif lower.endswith(".apk") or "AndroidManifest.xml" in entries:
        out["type"] = "android-package"
    else:
        out["type"] = "archive"
    return out


def _java_metadata(data: bytes, entries: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    declared = _zip_member(data, "pom.properties")
    if declared:
        fields = {}
        for line in declared.decode("utf-8", "replace").splitlines():
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                fields[key.strip()] = value.strip()
        if fields.get("artifactId"):
            out["artifact"] = fields["artifactId"]
            out["group"] = fields.get("groupId")
            out["version"] = fields.get("version")
    manifest = _zip_member(data, "MANIFEST.MF")
    if manifest:
        for line in manifest.decode("utf-8", "replace").splitlines():
            lower = line.lower()
            if lower.startswith(("implementation-version:", "bundle-version:")) and not out.get("version"):
                out["version"] = line.split(":", 1)[1].strip()
            elif lower.startswith("main-class:"):
                out["main_class"] = line.split(":", 1)[1].strip()
    out["class_count"] = sum(1 for entry in entries if entry.endswith(".class"))
    return out


def _python_metadata(data: bytes, entries: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    metadata = _zip_member(data, "METADATA")
    if metadata:
        for line in metadata.decode("utf-8", "replace").splitlines():
            lower = line.lower()
            if lower.startswith("name:") and "name" not in out:
                out["name"] = line.split(":", 1)[1].strip()
            elif lower.startswith("version:") and "version" not in out:
                out["version"] = line.split(":", 1)[1].strip()
            elif lower.startswith("license:") and "license" not in out:
                out["license"] = line.split(":", 1)[1].strip()
            elif lower.startswith("requires-dist:"):
                out.setdefault("requires", []).append(line.split(":", 1)[1].strip())
    out["native_extensions"] = [entry for entry in entries if entry.endswith((".so", ".pyd", ".dylib"))][:50]
    return out


def parse_java_class(data: bytes) -> dict[str, Any]:
    """Java class constant pool — where crypto providers and algorithms sit.

    A class file is not just a blob: the constant pool names every class it
    references (``javax/crypto/Cipher``, ``org/bouncycastle/...``) and usually
    the transformation strings it passes around (``AES/GCM/NoPadding``). Reading
    it turns a class file from "not parsed" into real evidence.
    """
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        raise ValueError("not a Java class file")
    reader = _Reader(data)
    minor, major = reader.unpack(">HH", 4)
    count = reader.unpack(">H", 8)[0]
    out: dict[str, Any] = {"format": "java-class", "libraries": [], "imports": [], "exports": [],
                           "java": {"class_version": f"{major}.{minor}"}}
    java = out["java"]
    position = 10
    strings: list[str] = []
    classes: list[str] = []
    methods: list[str] = []
    index = 1
    while index < count and index < 3000:
        if position >= len(data):
            break
        tag = data[position]
        position += 1
        try:
            if tag == 1:                                    # CONSTANT_Utf8
                length = reader.unpack(">H", position)[0]
                position += 2
                text = reader.take(position, length).decode("utf-8", "replace")
                position += length
                strings.append(text)
            elif tag in (3, 4):                             # Integer / Float
                position += 4
            elif tag in (5, 6):                             # Long / Double (two slots)
                position += 8
                index += 1
            elif tag == 7:                                  # Class
                name_index = reader.unpack(">H", position)[0]
                classes.append(_utf8_at(strings, name_index))
                position += 2
            elif tag == 8:                                  # String
                position += 2
            elif tag in (9, 10, 11):                        # Field/Method/InterfaceMethodref
                _cls, name_and_type = reader.unpack(">HH", position)
                methods.append(_utf8_at(strings, name_and_type))
                position += 4
            elif tag == 12:                                 # NameAndType
                name_index, _descriptor = reader.unpack(">HH", position)
                methods.append(_utf8_at(strings, name_index))
                position += 4
            elif tag == 15:                                 # MethodHandle
                position += 3
            elif tag == 16:                                 # MethodType
                position += 2
            elif tag in (17, 18):                           # Dynamic / InvokeDynamic
                position += 4
            elif tag in (19, 20):                           # Module / Package
                name_index = reader.unpack(">H", position)[0]
                classes.append(_utf8_at(strings, name_index))
                position += 2
            else:
                java["constant_pool_truncated_at"] = index
                break
        except Exception:  # noqa: BLE001 — stop at the first structurally bad entry
            java["constant_pool_truncated_at"] = index
            break
        index += 1
    java["constant_pool_entries"] = index - 1
    java["classes"] = sorted({name for name in classes if name})[:300]
    java["member_names"] = sorted({name for name in methods if name})[:200]
    java["strings"] = [text for text in strings if len(text) >= 3][:400]
    # crypto-relevant class names become the evidence the fingerprint table reads
    crypto_classes = [name for name in classes
                      if any(token in name.lower() for token in (
                          "crypto", "cipher", "bouncycastle", "bcprov", "openssl",
                          "keypair", "keygenerator", "mac", "messagedigest", "signature",
                          "security", "sodium", "conscrypt"))]
    java["crypto_classes"] = sorted(set(crypto_classes))[:60]
    out["imports"] = java["crypto_classes"]
    if any("bouncycastle" in name.lower() or "bcprov" in name.lower() for name in crypto_classes):
        out["libraries"].append("BouncyCastle")
    return out


def _utf8_at(strings: list[str], index: int) -> str:
    """Constant-pool indices are 1-based; 0 means "none"."""
    if index <= 0 or index > len(strings):
        return ""
    return strings[index - 1]


def parse_wasm(data: bytes) -> dict[str, Any]:
    """WASM import/export names — crypto markers live in the import section."""
    out: dict[str, Any] = {"format": "wasm", "libraries": [], "imports": [], "exports": []}
    position = 8
    while position < len(data):
        try:
            section_id = data[position]
            position += 1
            size = 0
            shift = 0
            while position < len(data):
                byte = data[position]
                position += 1
                size |= (byte & 0x7F) << shift
                shift += 7
                if not byte & 0x80:
                    break
        except Exception:  # noqa: BLE001
            break
        end = position + size
        if section_id == 2:
            out["imports"] = extract_strings(data[position:end], min_len=3, limit=400)
        elif section_id == 7:
            out["exports"] = extract_strings(data[position:end], min_len=3, limit=400)
        if end <= position:
            break
        position = end
    return out


# ------------------------------------------------------------------ RPM ----- #
RPM_TAGS = {
    1000: "name", 1001: "version", 1002: "release", 1004: "summary", 1005: "description",
    1010: "distribution", 1011: "vendor", 1014: "license", 1015: "packager",
    1016: "group", 1020: "url", 1021: "os", 1022: "arch", 1044: "source_rpm",
    1046: "archive_size", 1047: "providename", 1049: "requirename", 1050: "requireversion",
    1124: "payload_format", 1125: "payload_compressor", 1126: "payload_flags",
    5011: "payload_digest", 5092: "payload_digest_algo",
}
#: RPM signature-header tags: whether the package is signed, and with what
RPM_SIGNATURE_TAGS = {
    267: "dsa", 268: "rsa", 269: "sha1", 273: "sha256",
    1002: "pgp", 1004: "md5", 1005: "gpg", 1006: "pgp",
}
#: digest tags hold raw bytes; these are the digest sizes we understand
RPM_DIGEST_SIZES = {"sha1": 20, "sha256": 32, "md5": 16}
RPM_LEAD_MAGIC = b"\xed\xab\xee\xdb"
RPM_HEADER_MAGIC = b"\x8e\xad\xe8\x01"
_RPM_TYPE_SIZES = {0: 0, 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 1, 9: 1}


def parse_rpm(data: bytes) -> dict[str, Any]:
    """RPM package metadata (name/version/vendor/licence/requires/provides).

    The payload itself is a compressed cpio archive; the header is where the
    package identity lives, and reading it turns "identified, not parsed" into a
    component with a version and a licence.
    """
    if not data.startswith(RPM_LEAD_MAGIC):
        raise ValueError("not an RPM package")
    reader = _Reader(data)
    position = 96                                   # lead
    out: dict[str, Any] = {"format": "rpm", "libraries": [], "imports": [], "exports": []}
    for region in ("signature", "header"):
        if position + 16 > len(data):
            break
        magic = data[position:position + 4]
        if magic != RPM_HEADER_MAGIC:
            offset = data.find(RPM_HEADER_MAGIC, position, position + 4096)
            if offset < 0:
                break
            position = offset
        index_count, store_size = reader.unpack(">II", position + 8)
        table = position + 16
        store = table + index_count * 16
        if index_count > 20000 or store + store_size > len(data):
            raise ValueError("RPM header out of bounds")
        entries: dict[int, dict[str, Any]] = {}
        for index in range(min(index_count, MAX_RPM_ENTRIES)):
            try:
                tag, dtype, offset, count = reader.unpack(">IIII", table + index * 16)
            except Exception:  # noqa: BLE001
                break
            entries[tag] = {"type": dtype, "offset": offset, "count": count}
        payload = data[store:store + store_size]
        if region == "signature":
            # the signature header says whether the package is signed at all, and
            # which digests it carries — a package with no signature has no
            # provenance, and that is a fact worth reporting
            signature: dict[str, Any] = {"kinds": [], "digests": {}}
            for tag, label in RPM_SIGNATURE_TAGS.items():
                entry = entries.get(tag)
                if not entry:
                    continue
                if label not in signature["kinds"]:
                    signature["kinds"].append(label)
                size = RPM_DIGEST_SIZES.get(label)
                # digest tags are RPM_BIN_TYPE (7) or RPM_STRING_TYPE (8)
                if size and entry.get("type") in (7, 8) and entry.get("count") == size:
                    raw = payload[entry["offset"]:entry["offset"] + size]
                    if len(raw) == size:
                        signature["digests"][label] = raw.hex()
            # a digest tag is integrity metadata, not a signature: only RSA/DSA/PGP
            # entries say the package was signed by someone
            signature["present"] = any(kind in ("rsa", "dsa", "pgp", "gpg")
                                       for kind in signature["kinds"])
            if signature["digests"]:
                signature["digest_algorithms"] = sorted(signature["digests"])
            out["signature"] = signature
            out["signed"] = bool(signature.get("present"))
        if region == "header":
            out["header_entries"] = len(entries)
            for tag, label in RPM_TAGS.items():
                entry = entries.get(tag)
                if not entry:
                    continue
                values = _rpm_values(payload, entry)
                if not values:
                    continue
                if label in ("providename", "requirename", "requireversion"):
                    out.setdefault(label, [])
                    out[label].extend(values[:200])
                else:
                    out[label] = values[0] if len(values) == 1 else values
            out["libraries"] = sorted({name.split("(")[0] for name in out.get("requirename") or []})
            out["imports"] = [f"{name}" for name in (out.get("requirename") or [])][:200]
            if out.get("payload_compressor"):
                out["payload_compression"] = str(out["payload_compressor"])
            out["payload_offset"] = store + store_size + ((8 - store_size % 8) % 8)
        position = store + store_size + ((8 - store_size % 8) % 8)
    if not out.get("name"):
        out["parse_note"] = "RPM header read but the NAME tag was absent"
    return out


def _rpm_values(payload: bytes, entry: dict[str, Any]) -> list[str]:
    """Decode one RPM header entry (string, string array or int array)."""
    offset, count, dtype = entry["offset"], entry["count"], entry["type"]
    if dtype in (6, 8, 9):                       # string / i18nstring
        out: list[str] = []
        position = offset
        for _ in range(min(count, 64)):
            end = payload.find(b"\x00", position)
            if end < 0:
                break
            out.append(payload[position:end].decode("utf-8", "replace"))
            position = end + 1
        return [value for value in out if value]
    if dtype == 7:                               # string array (NUL separated)
        text = payload[offset:offset + 8192]
        return [part.decode("utf-8", "replace") for part in text.split(b"\x00")[:count] if part]
    if dtype in (3, 4, 5):                       # int16/int32/int64
        size = _RPM_TYPE_SIZES.get(dtype, 4)
        values: list[str] = []
        for index in range(min(count, 32)):
            start = offset + index * size
            chunk = payload[start:start + size]
            if len(chunk) < size:
                break
            values.append(str(int.from_bytes(chunk, "big", signed=False)))
        return values
    return []


# ------------------------------------------------------------- firmware ----- #
def parse_firmware(data: bytes) -> dict[str, Any]:
    """Firmware container chain + device-tree identity (detected, not unpacked)."""
    out: dict[str, Any] = {"format": "firmware", "containers": [], "libraries": [],
                           "imports": [], "embedded_filesystems": [], "embedded_archives": []}
    if len(data) > FIRMWARE_SCAN_LIMIT:
        out["note"] = f"container search bounded to the first {FIRMWARE_SCAN_LIMIT // (1024 * 1024)} MiB"
    window = data[:FIRMWARE_SCAN_LIMIT]
    position = 0
    seen: set[str] = set()
    while position < len(window) and len(out["containers"]) < 16:
        best: tuple[int, str, bytes] | None = None
        for fmt, magic in MAGICS:
            if fmt in ("pe", "elf", "zip", "ar", "rpm"):
                continue
            index = window.find(magic, position)
            if index < 0:
                continue
            if best is None or index < best[0]:
                best = (index, fmt, magic)
        if best is None:
            break
        index, fmt, magic = best
        container: dict[str, Any] = {"format": fmt, "offset": index}
        if fmt == "dtb":
            tree = _parse_dtb(window, index)
            if tree:
                out["device_tree"] = tree
                container.update({k: v for k, v in tree.items() if k in ("model", "compatible")})
        if fmt in FILESYSTEM_FORMATS:
            out["embedded_filesystems"].append({"format": fmt, "offset": index,
                                                "offset_hex": hex(index)})
        elif fmt in COMPRESSION_FORMATS:
            out["embedded_archives"].append({"format": fmt, "offset": index, "offset_hex": hex(index)})
        key = f"{fmt}@{index}"
        if key not in seen:
            seen.add(key)
            out["containers"].append(container)
        position = index + max(len(magic), 1)
    out["container_count"] = len(out["containers"])
    out["entropy"] = round(entropy(data), 3)
    out["packed_or_encrypted"] = out["entropy"] > 7.2
    return out


#: IMAGE_DLLCHARACTERISTICS_* — the PE equivalent of ELF's hardening bits
PE_DLL_CHARACTERISTICS = {
    0x0020: ("high_entropy_va", True), 0x0040: ("aslr", True),
    0x0080: ("force_integrity", True), 0x0100: ("dep", True),
    0x0200: ("isolation", False), 0x0400: ("seh", False),
    0x0800: ("bind", False), 0x1000: ("appcontainer", True),
    0x2000: ("wdm_driver", True), 0x4000: ("cfg", True),
    0x8000: ("terminal_server_aware", True),
}
#: LOAD_CONFIG GuardFlags bit that says Control Flow Guard is actually instrumented
PE_GUARD_CF_INSTRUMENTED = 0x100

#: legacy U-Boot image header (64 bytes, big-endian) field values
UIMAGE_OS: dict[int, str] = {0: "invalid", 1: "openbsd", 2: "netbsd", 3: "freebsd", 4: "4.4bsd",
                             5: "linux", 6: "svr4", 7: "esix", 8: "solaris", 9: "irix",
                             10: "sco", 11: "hpux", 12: "openrtos", 13: "arm-trusted-firmware",
                             14: "tee", 15: "optee", 16: "efi", 17: "vxworks"}
UIMAGE_ARCH: dict[int, str] = {1: "alpha", 2: "arm", 3: "i386", 4: "ia64", 5: "mips",
                               6: "mips64", 7: "powerpc", 8: "s390", 9: "sh", 10: "sparc",
                               11: "sparc64", 12: "m68k", 13: "nios", 14: "microblaze",
                               15: "nios2", 16: "blackfin", 17: "avr32", 18: "st200",
                               19: "sandbox", 20: "nds32", 21: "openrisc", 22: "arm64",
                               23: "arc", 24: "x86-64", 25: "xtensa", 26: "riscv"}
UIMAGE_TYPE: dict[int, str] = {1: "standalone", 2: "kernel", 3: "ramdisk", 4: "multi-image",
                               5: "firmware", 6: "script", 7: "filesystem", 8: "binary",
                               9: "flat-device-tree", 10: "kwbimage", 11: "imximage",
                               12: "ubl", 13: "omapimage", 14: "kernel-self",
                               15: "script-self", 16: "filesystem-self", 17: "flatdt-self"}
UIMAGE_COMPRESSION: dict[int, str] = {0: "none", 1: "gzip", 2: "bzip2", 3: "lzma", 4: "lzo",
                                      5: "lz4", 6: "zstd"}
#: verifying the payload CRC means reading the whole image; past this it is skipped
#: (and said so) rather than being reported as verified
UIMAGE_CRC_LIMIT = 64 * 1024 * 1024


def parse_uimage(data: bytes) -> dict[str, Any]:
    """Legacy U-Boot (uImage) header: what the image is, and whether it is intact.

    The header carries the OS, architecture, image type, compression, load/entry
    addresses and the image name, plus two CRCs. Both CRCs are *checked* when they
    are present and the image is small enough — a verified checksum is a fact about
    the file, and a mismatch means the firmware was modified or truncated.
    """
    import zlib

    if len(data) < 64 or data[:4] != b"\x27\x05\x19\x56":
        raise ValueError("not a legacy uImage")
    # magic, header CRC, timestamp, size, load, entry, data CRC — 7 u32 — then the
    # four one-byte identity fields, then the 32-byte name
    (_magic, hcrc, timestamp, size, load, entry, dcrc, os_id, arch_id, type_id,
     comp_id) = struct.unpack_from(">7I4B", data, 0)
    name = data[32:64].split(b"\x00")[0].decode("utf-8", "replace").strip()
    out: dict[str, Any] = {
        "format": "uimage",
        "uimage": {
            "name": name or None,
            "os": UIMAGE_OS.get(os_id, f"os-{os_id}"),
            "arch": UIMAGE_ARCH.get(arch_id, f"arch-{arch_id}"),
            "image_type": UIMAGE_TYPE.get(type_id, f"type-{type_id}"),
            "compression": UIMAGE_COMPRESSION.get(comp_id, f"comp-{comp_id}"),
            "load_address": hex(load),
            "entry_point": hex(entry),
            "payload_size": size,
            "payload_offset": 64,
            "header_crc": hex(hcrc),
            "data_crc": hex(dcrc) if dcrc else None,
        },
    }
    if timestamp and timestamp < 0x80000000:      # 0 and clearly bogus values are skipped
        from datetime import datetime, timezone

        out["uimage"]["built"] = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
    # header CRC: computed over the header with the hcrc field treated as zero
    header = bytearray(data[:64])
    header[4:8] = b"\x00\x00\x00\x00"
    expected = zlib.crc32(bytes(header)) & 0xFFFFFFFF
    out["uimage"]["header_crc_verified"] = bool(hcrc) and expected == hcrc
    if hcrc and expected != hcrc:
        out["uimage"]["header_crc_expected"] = hex(expected)
    payload = data[64:64 + size] if size else b""
    if dcrc:
        if size <= UIMAGE_CRC_LIMIT and len(payload) == size:
            out["uimage"]["data_crc_verified"] = (zlib.crc32(payload) & 0xFFFFFFFF) == dcrc
        else:
            out["uimage"]["data_crc_checked"] = False
            out["uimage"]["note"] = ("payload CRC not checked: image exceeds the "
                                     f"{UIMAGE_CRC_LIMIT // (1024 * 1024)} MiB verification cap "
                                     "or the payload is truncated")
    if size and len(payload) < size:
        out["uimage"]["truncated"] = True
    out["arch"] = out["uimage"]["arch"]
    return out


def _parse_dtb(data: bytes, offset: int) -> dict[str, Any] | None:
    """Device-tree strings block: `model` and `compatible` name the hardware."""
    try:
        total = struct.unpack_from(">I", data, offset + 4)[0]
        off_strings = struct.unpack_from(">I", data, offset + 12)[0]
        blob = data[offset + off_strings:offset + min(off_strings + 65536, total, len(data) - offset)]
        chunks = [chunk.decode("utf-8", "replace") for chunk in blob.split(b"\x00")]
        model = None
        compatible: list[str] = []
        for index, chunk in enumerate(chunks):
            if chunk == "model" and index + 1 < len(chunks):
                model = chunks[index + 1] or model
            elif chunk == "compatible":
                for follow in chunks[index + 1:index + 6]:
                    if follow and follow != "compatible" and "," in follow:
                        compatible.append(follow)
        out: dict[str, Any] = {"size": total}
        if model:
            out["model"] = model
        if compatible:
            out["compatible"] = sorted(set(compatible))[:12]
        return out
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------- extraction ------- #
#: containers this scanner can actually open, and with what (stdlib only).
#: squashfs/JFFS2/UBIFS/cramfs/zstd/lz4 are deliberately absent: pretending to
#: look inside them would be the one thing worse than saying "not extracted".
OPENABLE_COMPRESSION = {"gzip": "gzip", "xz": "lzma", "lzma": "lzma", "bzip2": "bz2"}
REFUSED_COMPRESSION = {"zstd": "no stdlib zstd decoder", "lz4": "no stdlib lz4 decoder"}


def _bounded_gzip(data: bytes, limit: int) -> bytes:
    import zlib

    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = decompressor.decompress(data, limit)
    return out


def _bounded_lzma(data: bytes, limit: int) -> bytes:
    import lzma

    decompressor = lzma.LZMADecompressor()
    return decompressor.decompress(data, limit)


def _bounded_bz2(data: bytes, limit: int) -> bytes:
    import bz2

    decompressor = bz2.BZ2Decompressor()
    return decompressor.decompress(data, limit)


def decompress_payload(data: bytes, fmt: str, *, limit: int = MAX_EXTRACT_BYTES) -> bytes | None:
    """Decompress one level, bounded — a zip bomb must not exhaust the scanner."""
    try:
        if fmt == "gzip":
            return _bounded_gzip(data, limit)
        if fmt in ("xz", "lzma"):
            return _bounded_lzma(data, limit)
        if fmt == "bzip2":
            return _bounded_bz2(data, limit)
    except Exception:  # noqa: BLE001 — a corrupt stream is reported by the caller
        return None
    return None


def parse_cpio(data: bytes, *, limit: int = MAX_EXTRACT_FILES) -> dict[str, Any]:
    """newc/crc cpio archives — the usual payload of an initramfs."""
    magic = data[:6]
    if magic not in (b"070701", b"070702"):
        raise ValueError("not a newc cpio archive")
    members: list[dict[str, Any]] = []
    offset = 0
    while offset + 110 <= len(data) and len(members) < limit:
        header = data[offset:offset + 110]
        if header[:6] not in (b"070701", b"070702"):
            break
        try:
            fields = [int(header[6 + index * 8:6 + (index + 1) * 8], 16) for index in range(13)]
        except ValueError:
            break
        _ino, _mode, _uid, _gid, _nlink, _mtime, filesize = fields[:7]
        name_size = fields[11]
        name_start = offset + 110
        name = data[name_start:name_start + max(name_size - 1, 0)].decode("utf-8", "replace")
        data_start = name_start + name_size
        data_start += (4 - data_start % 4) % 4
        if name == "TRAILER!!!":
            members.append({"name": name, "size": 0, "trailer": True})
            break
        members.append({"name": name.lstrip("./") or name, "size": filesize,
                        "is_dir": bool(fields[1] & 0o170000) and (fields[1] & 0o170000) == 0o040000,
                        "is_symlink": (fields[1] & 0o170000) == 0o120000})
        offset = data_start + filesize
        offset += (4 - offset % 4) % 4
    return {"format": "cpio", "members": members[:limit], "member_count": len(members)}


def _tar_members(data: bytes, *, limit: int = MAX_EXTRACT_FILES) -> list[dict[str, Any]]:
    import io
    import tarfile

    members: list[dict[str, Any]] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            for info in archive:
                if len(members) >= limit:
                    break
                members.append({"name": info.name.lstrip("./"), "size": int(info.size),
                                "is_dir": bool(info.isdir()), "is_symlink": bool(info.issym() or info.islnk())})
    except Exception:  # noqa: BLE001 — a truncated archive yields what was read
        pass
    return members


def _tar_member_bytes(data: bytes, wanted: tuple[str, ...], *,
                      limit: int = MAX_MEMBER_BYTES) -> list[tuple[str, bytes]]:
    import io
    import tarfile

    found: list[tuple[str, bytes]] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            for info in archive:
                if len(found) >= 12 or info.size > limit or not info.isfile():
                    continue
                if wanted and not any(info.name.endswith(suffix) for suffix in wanted):
                    continue
                handle = archive.extractfile(info)
                if handle is None:
                    continue
                found.append((info.name.lstrip("./"), handle.read(limit)))
    except Exception:  # noqa: BLE001
        pass
    return found


def parse_cpio_members(data: bytes, wanted: tuple[str, ...] = (), *,
                       limit: int = MAX_EXTRACT_FILES) -> list[tuple[str, bytes]]:
    """Read cpio member payloads (initramfs contents), bounded."""
    if data[:6] not in (b"070701", b"070702"):
        return []
    out: list[tuple[str, bytes]] = []
    offset = 0
    while offset + 110 <= len(data) and len(out) < 12:
        header = data[offset:offset + 110]
        if header[:6] not in (b"070701", b"070702"):
            break
        try:
            fields = [int(header[6 + index * 8:6 + (index + 1) * 8], 16) for index in range(13)]
        except ValueError:
            break
        filesize = fields[6]
        name_size = fields[11]
        name_start = offset + 110
        name = data[name_start:name_start + max(name_size - 1, 0)].decode("utf-8", "replace")
        data_start = name_start + name_size
        data_start += (4 - data_start % 4) % 4
        if name == "TRAILER!!!":
            break
        if filesize and filesize <= MAX_MEMBER_BYTES and (
                not wanted or any(name.endswith(suffix) for suffix in wanted)):
            out.append((name.lstrip("./"), data[data_start:data_start + filesize]))
        offset = data_start + filesize
        offset += (4 - offset % 4) % 4
    return out


def explore_container(data: bytes, fmt: str, *, depth: int, prefix: str,
                      parsed: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Follow a container and scan what is inside it.

    Depth-bounded, size-bounded, and it never claims more than it did: what was
    opened is listed under ``opened``, what was refused is listed with the reason,
    and every member that was parsed carries ``derived_from`` provenance.
    """
    summary: dict[str, Any] = {"format": fmt, "depth": depth, "opened": [], "members": [],
                               "members_listed": 0, "parsed": 0, "refused": []}
    payload: bytes | None = None
    if fmt in OPENABLE_COMPRESSION:
        payload = decompress_payload(data, fmt)
        if payload is None:
            summary["refused"].append({"format": fmt, "reason": "stream could not be decompressed"})
            return summary
        summary["opened"].append(f"{fmt} → {len(payload)} B")
    elif fmt in REFUSED_COMPRESSION:
        summary["refused"].append({"format": fmt, "reason": REFUSED_COMPRESSION[fmt]})
        return summary
    elif fmt in ("ustar", "cpio"):
        payload = data
    elif fmt == "ar":
        payload = None
    elif fmt == "zip":
        payload = None
    else:
        return None

    inner_format = ""
    members: list[dict[str, Any]] = []
    if payload is not None:
        inner = identify(payload, "")
        inner_format = inner["format"]
        if inner_format == "ustar":
            members = _tar_members(payload)
        elif inner_format == "cpio":
            members = parse_cpio(payload)["members"]
        elif inner_format == "raw" and payload[:6] in (b"070701", b"070702"):
            inner_format = "cpio"
            members = parse_cpio(payload)["members"]
    elif fmt == "ar":
        archive = parse_ar(data)
        members = archive.get("members") or []
        inner_format = archive.get("type") or "ar"
    elif fmt == "zip":
        members = [{"name": name} for name in (_zip_members(data))[:MAX_EXTRACT_FILES]]
        inner_format = "zip"

    summary["inner_format"] = inner_format
    summary["members_listed"] = len(members)
    summary["members"] = members[:40]

    # .deb: the control file carries the package identity, data.tar the contents
    payloads: list[tuple[str, bytes]] = []
    if fmt == "ar" and payload is None:
        # a signed .deb carries a `_gpgorigin` member (dpkg-sig / debsigs); most
        # .debs are unsigned because the signature lives in the archive metadata
        member_names = [str(entry.get("name") or "") for entry in (parse_ar(data).get("members") or [])]
        summary["package_signed"] = any(name.startswith("_gpgorigin") or name.startswith("_gpgbuilder")
                                        for name in member_names)
        if summary["package_signed"]:
            summary["opened"].append("detached package signature present (_gpgorigin)")
        for name, member in _ar_member_bytes(data, ("control.tar", "control.tar.gz", "control.tar.xz")):
            control = _decompressed_member(name, member)
            if not control:
                continue
            for member_name, control_bytes in _tar_member_bytes(control, ("control", "control/")):
                package = _parse_deb_control(control_bytes)
                if package:
                    summary["package"] = package
                    summary["opened"].append(
                        f"deb control read: {package['name']} {package.get('version') or ''}".strip())
            payloads.extend(_tar_member_bytes(control, ("",)))
        for name, member in _ar_member_bytes(data, ("data.tar", "data.tar.gz", "data.tar.xz")):
            data_tar = _decompressed_member(name, member)
            if data_tar:
                summary["data_members"] = _tar_members(data_tar)
    elif inner_format == "cpio":
        payloads = parse_cpio_members(payload or b"")
    elif inner_format == "ustar" and payload:
        payloads = _tar_member_bytes(payload, ("",))

    _parse_member_payloads(payloads[:12], depth=depth, prefix=prefix, parsed=parsed,
                           summary=summary)
    return summary


def _parse_member_payloads(payloads: list[tuple[str, bytes]], *, depth: int, prefix: str,
                           parsed: list[dict[str, Any]], summary: dict[str, Any]) -> None:
    """Parse the members that are real files in a known format, bounded.

    A member that is not a format this scanner understands is deliberately absent
    from the result rather than reported as an empty component — the member list
    already says it was there.
    """
    for name, member in payloads:
        if depth >= MAX_EXTRACT_DEPTH:
            summary["refused"].append({"member": name, "reason": "depth limit reached"})
            break
        if len(member) > MAX_MEMBER_BYTES:
            summary["refused"].append({"member": name, "reason": "member exceeds the parse budget"})
            continue
        if identify(member, name)["format"] == "raw":
            continue
        record = parse_bytes(member, name=Path(name).name)
        # a member gets the same treatment as a top-level file, constant tables
        # included — otherwise an implementation inside an archive looks weaker
        # than the identical file scanned directly
        constant_blobs = record.pop("_constant_blobs", [])
        record["name"] = record.get("name") or Path(name).name
        record["file_name"] = Path(name).name
        record["path"] = f"{prefix}!{name}"
        record["sha256"] = hashlib.sha256(member).hexdigest()
        record["size"] = len(member)
        strings = extract_strings(member)
        record["strings_sampled"] = len(strings)
        record["derived_from"] = prefix
        record["depth"] = depth + 1
        record["packer"] = record.get("packer") or detect_packer([], "\n".join(strings[:800]))
        record["crypto_constants"] = record.get("crypto_constants") or []
        record["crypto"] = crypto_evidence(member, strings, imports=record.get("imports") or [],
                                           exports=record.get("exports") or [],
                                           constants=constant_blobs)
        record["findings"] = []
        summary["opened"].append(f"parsed {record['path']} ({record['format']})")
        summary["parsed"] += 1
        parsed.append(record)


def _parse_deb_control(text: bytes) -> dict[str, Any]:
    """A Debian control file is a package identity — name, version, depends."""
    out: dict[str, Any] = {}
    current = ""
    for line in text.decode("utf-8", "replace").splitlines():
        if line.startswith((" ", "\t")) and current:
            out[current] += "\n" + line.strip()
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        current = key.strip().lower()
        out[current] = value.strip()
    if not out.get("package"):
        return {}
    dependencies = []
    for field in ("depends", "pre-depends", "recommends"):
        for item in (out.get(field) or "").split(","):
            name = item.strip().split(" ")[0].split("(")[0].strip()
            if name:
                dependencies.append(name)
    return {
        "name": out["package"],
        "version": out.get("version"),
        "architecture": out.get("architecture"),
        "maintainer": out.get("maintainer"),
        "section": out.get("section"),
        "homepage": out.get("homepage"),
        "depends": dependencies[:60],
        "description": (out.get("description") or "").split("\n")[0][:200],
    }


def _decompressed_member(name: str, data: bytes) -> bytes | None:
    if name.endswith(".gz"):
        return decompress_payload(data, "gzip")
    if name.endswith(".xz"):
        return decompress_payload(data, "xz")
    if name.endswith(".bz2"):
        return decompress_payload(data, "bzip2")
    return data


def _ar_member_bytes(data: bytes, wanted: tuple[str, ...]) -> list[tuple[str, bytes]]:
    found: list[tuple[str, bytes]] = []
    long_names = b""
    position = 8
    while position + 60 <= len(data) and len(found) < 16:
        try:
            header = data[position:position + 60]
            raw_name = header[0:16].decode("ascii", "replace").strip()
            size = int(header[48:58].decode("ascii", "replace").strip() or 0)
        except ValueError:
            break
        if size <= 0 or position + 60 + size > len(data):
            break
        payload = data[position + 60:position + 60 + size]
        if raw_name == "//":
            long_names = payload
        elif raw_name not in ("/", "/SYM64/"):
            name = raw_name.rstrip("/")
            if raw_name.startswith("/") and raw_name[1:].isdigit():
                offset = int(raw_name[1:])
                end = long_names.find(b"/\n", offset)
                name = long_names[offset:end if end > 0 else offset + 64].decode("utf-8", "replace")
            if any(name.startswith(suffix) for suffix in wanted) and len(payload) <= MAX_MEMBER_BYTES:
                found.append((name, payload))
        position += 60 + size + (size % 2)
    return found


def _zip_members(data: bytes, limit: int = MAX_EXTRACT_FILES) -> list[str]:
    return [entry["name"] for entry in _zip_local_entries(data, limit=limit)]


# ------------------------------------------------------ crypto evidence ----- #
#: markers strong enough to assert a library from text alone (distinctive tokens)
STRONG_MARKERS: dict[str, tuple[str, ...]] = {
    "BoringSSL": ("BoringSSL", "openSSLIsBoringSSL"),
    "BouncyCastle": ("BouncyCastleProvider", "org/bouncycastle", "org.bouncycastle"),
    "Apple CommonCrypto": ("CCCryptorCreate", "CC_SHA256", "CCKeyDerivationPBKDF",
                           "kCCAlgorithmAES"),
    "Apple Security.framework": ("SecKeyEncrypt", "SecTrustEvaluate", "SecItemCopyMatching",
                                 "SSLCreateContext"),
    "Crypto++": ("CryptoPP", "cryptopp"),
    ".NET cryptography": ("System.Security.Cryptography",),
    "JCA-JCE": ("javax/crypto", "javax.crypto", "java/security/MessageDigest",
                "javax/security/auth", "KeyPairGenerator"),
    "Java SecureRandom": ("java/security/SecureRandom", "java.security.SecureRandom",
                          "SecureRandom"),
    "WebCrypto": ("SubtleCrypto", "crypto.subtle"),
    "RustCrypto": ("rustls", "ed25519-dalek", "aes_gcm::"),
    "PKCS#11": ("C_GetFunctionList", "C_Initialize"),
    "Node crypto": ("node:crypto", "createCipheriv"),
}
#: tokens matched on identifier boundaries only — "sha2" must not hit "sha256",
#: "ring::" must not hit "string::"
BOUNDARY_MARKERS: tuple[str, ...] = ("pkcs11", "bcprov", "libcrypto", "libssl", "ring::", "sha2")
_BOUNDARY = r"(?:^|[^0-9a-z]){token}(?:[^0-9a-z]|$)"


def _marker_hits(marker: str, names: list[str], text: str) -> list[str]:
    """Evidence hits for one marker, with identifier-boundary discipline.

    A plain substring match is not evidence over a binary symbol table: "sha2"
    inside "EVP_sha224" or "aes_128_cbc_hmac_sha256" reports RustCrypto in
    OpenSSL. So every marker is first matched on identifier boundaries, and a
    loose substring match is only allowed for *distinctive* markers — ones that
    carry case, punctuation or length that a coincidence will not reproduce
    ("openSSLIsBoringSSL", "C_GetFunctionList", "System.Security.Cryptography").
    """
    pattern = re.compile(_BOUNDARY.format(token=re.escape(marker)), re.IGNORECASE)
    hits = [name for name in names[:6000] if pattern.search(name)][:3]
    if hits:
        return hits
    if marker in BOUNDARY_MARKERS or not _distinctive_marker(marker):
        return []
    hits = [name for name in names[:6000] if marker in name][:3]
    if hits:
        return hits
    return [marker] if marker in text else []


def _distinctive_marker(marker: str) -> bool:
    """True when a loose substring match is unlikely to be a coincidence.

    Case, a path/dot separator or length carry enough entropy. Punctuation alone
    does not: ``ring::`` inside ``string::`` is exactly the coincidence this
    guard exists to reject.
    """
    return (any(char.isupper() for char in marker)
            or "." in marker or "/" in marker
            or len(marker) >= 10)


def _versions_from_bytes(data: bytes) -> dict[str, str]:
    """Embedded library versions, read from the raw bytes.

    The string sample is capped for memory reasons, but a version banner can sit
    anywhere in a 5 MiB shared library, so this pass searches the file itself
    (bounded to the first 64 MiB).
    """
    window = data[:64 * 1024 * 1024]
    found: dict[str, str] = {}
    for library, pattern, _vendor in VERSION_PATTERNS:
        try:
            match = re.search(pattern.encode("utf-8", "replace"), window)
        except re.error:  # noqa: PERF203 — a bad pattern is skipped, never fatal
            continue
        if match and match.groups():
            found[library] = match.group(1).decode("utf-8", "replace")
    return found


def crypto_evidence(data: bytes, strings: list[str], *, imports: Iterable[str] = (),
                    exports: Iterable[str] = (), constants: Iterable[bytes] = ()) -> dict[str, Any]:
    """Library fingerprints, graded algorithms and PQC posture for one binary.

    Delegates to the universal-crypto engine so the platform keeps ONE
    fingerprint table and ONE evidence-level model, then adds the two things
    that engine deliberately does not do: version strings read from the file
    itself, and a quantum/PQC classification derived *only* from detected
    algorithms — never from raw symbol names, which is how scanners end up
    calling ``ACCESS_DESCRIPTION_new`` a DES finding.
    """
    from universal_crypto.binary_engine import (IMPLEMENTATION_FINGERPRINTS, LEVEL_WEIGHT,
                                                BinaryArtifact, BinaryCryptoDetector)
    from universal_crypto.library_fingerprints import LibraryFingerprinter

    import_names = list(imports)
    export_names = list(exports)
    symbol_names = import_names + export_names
    text = "\n".join(strings)
    versions = _versions_from_bytes(data)

    analysis = BinaryCryptoDetector().analyze(BinaryArtifact(
        format="binary", imports=import_names, symbols=export_names,
        strings=strings[:MAX_STRINGS], constants=list(constants)))
    detections = analysis.get("detections") or []
    implementations = set(IMPLEMENTATION_FINGERPRINTS)

    # algorithms: drop implementation-name entries (those are libraries, and the
    # fingerprint pass below reports them as such) and keep the graded evidence
    algorithm_rows: list[dict[str, Any]] = []
    for row in detections:
        name = str(row.get("algorithm") or "")
        if not name or name in implementations:
            continue
        evidence = row.get("evidence") or []
        strongest = max(evidence, key=lambda item: LEVEL_WEIGHT.get(str(item.get("level")), 0),
                        default={})
        algorithm_rows.append({
            "name": name,
            "confidence": float(row.get("best_level") or 0),
            "strongest_evidence": str(strongest.get("level") or ""),
            "sources": [str(item.get("detail")) for item in evidence][:5],
            "verdict": row.get("verdict"),
        })
    # the platform layer: CommonCrypto/CNG/SecureTransport calls the shared tables
    # do not model, reported at the evidence level a call site deserves
    by_name = {row["name"]: row for row in algorithm_rows}
    for row in _platform_symbol_algorithms(import_names, export_names):
        existing = by_name.get(row["name"])
        if existing is None:
            algorithm_rows.append(row)
            by_name[row["name"]] = row
            continue
        if row["confidence"] > existing["confidence"]:
            existing["confidence"] = row["confidence"]
            existing["strongest_evidence"] = row["strongest_evidence"]
        existing["sources"] = list(dict.fromkeys(
            (existing.get("sources") or []) + [row["sources"][0]]))[:5]

    # the string layer: transformations and TLS suites the symbol tables rarely show
    by_name = {row["name"]: row for row in algorithm_rows}
    for row in _transformation_algorithms(strings):
        existing = by_name.get(row["name"])
        if existing is None:
            algorithm_rows.append(row)
            by_name[row["name"]] = row
            continue
        existing["sources"] = list(dict.fromkeys(
            (existing.get("sources") or []) + [f"{row['sources'][0]} (string layer)"]
        ))[:5]
    algorithm_rows.sort(key=lambda row: (-row["confidence"], row["name"]))

    fingerprinter = LibraryFingerprinter()
    try:
        library_rows = fingerprinter.fingerprint(
            imports=import_names, symbols=export_names, strings=strings[:MAX_STRINGS],
            dependencies=[name for name in import_names if "." in name or "-" in name])
    except Exception:  # noqa: BLE001 — an API change must not fail a scan
        library_rows = []
    for row in library_rows:
        library = str(row.get("library"))
        if not row.get("version") and versions.get(library):
            row["version"] = versions[library]
            row["evidence_classes"] = sorted(set(row.get("evidence_classes") or []) | {"version"})

    # supplementary markers the fingerprint table does not cover, with boundary rules
    for library, markers in STRONG_MARKERS.items():
        if any(str(row.get("library")) == library for row in library_rows):
            continue
        hits: list[str] = []
        for marker in markers:
            hits.extend(_marker_hits(marker, symbol_names, text))
        if not hits:
            continue
        library_rows.append({
            "library": library, "provider": None, "version": versions.get(library), "evidence_classes":
                (["marker"] if any(hit in symbol_names for hit in hits) else ["string"]),
            "verdict": "POSSIBLE_CRYPTO",
            "note": f"marker evidence: {', '.join(sorted(set(hits))[:3])}",
        })

    library_rows, suppressed = _apply_strict_markers(library_rows, symbol_names, text)
    for row in library_rows:
        row["end_of_life"] = is_end_of_life(str(row["library"]), row.get("version"))
        if not row.get("version") and str(row["library"]) in implementations:
            row.setdefault("note", "no version string embedded — CVEs cannot be matched")

    names = [row["name"] for row in algorithm_rows]
    vulnerable = [row["name"] for row in algorithm_rows
                  if _is_quantum_vulnerable(row["name"])]
    weak = [row["name"] for row in algorithm_rows if _is_weak_primitive(row["name"])]
    pqc_markers = _tokens_in_text(PQC_PATTERNS, text)
    ecc_markers = _tokens_in_text(ECC_PATTERNS, text)[:12]
    return {
        "libraries": library_rows,
        "suppressed_libraries": suppressed,
        "algorithms": names,
        "algorithm_evidence": algorithm_rows,
        "detections": detections,
        "versions_from_file": versions,
        "pqc_markers": pqc_markers,
        "ecc_markers": ecc_markers,
        "quantum_vulnerable": vulnerable,
        "weak_primitives": weak,
    }


def _is_quantum_vulnerable(algorithm: str) -> bool:
    """Shor/Grover-relevant classical primitives, matched on token boundaries."""
    upper = algorithm.upper().replace("_", "-")
    tokens = set(re.split(r"[^A-Z0-9]+", upper))
    if {"RSA", "DSA", "DH", "ECDH", "ECDSA", "X25519", "X448", "ED25519", "ED448"} & tokens:
        return True
    if upper.startswith(("RSA", "ECDSA", "ECDH", "DSA", "DH-", "X25519", "X448",
                         "ED25519", "ED448")):
        return True
    return "MD5" in tokens or "SHA1" in tokens or "SHA-1" in upper


def _is_weak_primitive(algorithm: str) -> bool:
    upper = algorithm.upper().replace("_", "-")
    tokens = set(re.split(r"[^A-Z0-9]+", upper))
    return bool({"MD5", "RC4", "DES", "3DES", "RC2"} & tokens
                or "SHA-1" in upper or "SHA1" in tokens or "MD4" in tokens)


def _apply_strict_markers(rows: list[dict[str, Any]], names: list[str],
                          text: str) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Drop library claims that rest only on a loose substring.

    The shared fingerprint table (used by other scanners over source trees)
    matches markers with plain substring search, which is fine for source where a
    marker is a real API call, but over binary symbol tables it reports
    ``RustCrypto`` because a OpenSSL symbol contains ``sha2``. This scanner
    re-verifies every single-class "marker" claim on identifier boundaries and
    reports what it dropped instead of quietly keeping or hiding it.
    """
    from universal_crypto.library_fingerprints import LIBRARIES

    markers_by_library = {str(entry["name"]): tuple(entry.get("markers") or ()) for entry in LIBRARIES}
    # this scanner curates additional marker forms (JVM internal names use `/`
    # where the engine's table writes `.`), so re-verify against both vocabularies
    for library, curated in STRONG_MARKERS.items():
        markers_by_library[library] = tuple(dict.fromkeys(
            markers_by_library.get(library, ()) + tuple(curated)))
    kept: list[dict[str, Any]] = []
    suppressed: list[dict[str, str]] = []
    for row in rows:
        classes = list(row.get("evidence_classes") or [])
        if sorted(classes) != ["marker"]:
            kept.append(row)
            continue
        library = str(row.get("library"))
        markers = markers_by_library.get(library, ())
        qualified, plain = _strict_marker_evidence(markers, names, text)
        if qualified or len(set(plain)) >= 2:
            row["marker_hits"] = sorted(set(qualified + plain))[:5]
            row["note"] = ("marker evidence qualified by module/symbol path"
                           if qualified else "two independent markers matched")
            kept.append(row)
        else:
            why = ("no marker matched" if not plain else
                   f"only one unqualified marker matched ({plain[0]!r}) — a single lexical hit "
                   "is not evidence of a library")
            suppressed.append({
                "library": library,
                "reason": (f"{why}; markers tried: {', '.join(markers[:5]) or 'none'}"),
            })
    return kept, suppressed


def _strict_marker_evidence(markers: Iterable[str], names: list[str],
                            text: str) -> tuple[list[str], list[str]]:
    """Split marker evidence into (qualified, plain) hits for one library.

    ``qualified`` means the marker appears as the head of a module path or symbol
    (``rustls::``, ``sha2/``, ``C_GetFunctionList@``) — that is real evidence.
    A bare token match can be a coincidence of naming, so two independent ones
    are required; OpenSSL's own SLH-DSA entry points are named ``..._sha2_192f``
    and would otherwise be read as a Rust ``sha2`` dependency.
    """
    qualified: list[str] = []
    plain: list[str] = []
    for marker in markers:
        if not _marker_hits(marker, names, text):
            continue
        plain.append(marker)
        for suffix in ("::", "/", "@", "!"):
            # the delimiter itself closes the token, so only the *head* of the
            # occurrence needs an identifier boundary: "javax/crypto/Cipher" is a
            # qualified hit, while "string::" must not read as "ring::"
            pattern = re.compile(r"(?:^|[^0-9a-z])" + re.escape(marker + suffix), re.IGNORECASE)
            if any(pattern.search(name) for name in names[:6000]):
                qualified.append(f"{marker}{suffix}")
                break
    return qualified, sorted(set(plain))


def version_tuple(version: str | None) -> tuple[int, ...]:
    if not version:
        return ()
    match = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", str(version))
    if not match:
        return ()
    return tuple(int(part) for part in match.groups() if part)


def _tokens_in_text(patterns: Iterable[str], text: str) -> list[str]:
    """Every algorithm designation found, reported as the text actually present.

    The patterns capture whatever parameter set is written (``ML-KEM-768``,
    ``ml_kem``, ``sntrup761``), and matches must end on a non-identifier
    character so ``BIKE`` is not found inside ``BIKES``.
    """
    found: set[str] = set()
    for pattern in patterns:
        for match in re.finditer(pattern + _TOKEN_END, text, re.IGNORECASE):
            found.add(match.group(0))
    return sorted(found)



def is_end_of_life(library: str, version: str | None) -> bool:
    """EOL only where the version number makes it provable."""
    thresholds = EOL_VERSIONS.get(library)
    parsed = version_tuple(version)
    if not thresholds or not parsed:
        return False
    return parsed[:2] in thresholds


# ------------------------------------------------------------- pipeline ----- #
def parse_bytes(data: bytes, *, name: str = "") -> dict[str, Any]:
    """Dispatch one buffer to its parser; unknown formats are identified only."""
    ident = identify(data, name)
    fmt = ident["format"]
    record: dict[str, Any] = {"format": fmt, "size": len(data),
                              "entropy": round(entropy(data), 3)}
    parser = {
        "elf": parse_elf, "pe": parse_pe, "macho": parse_macho, "macho64": parse_macho,
        "macho-be": parse_macho, "macho64-be": parse_macho, "macho-fat": parse_macho,
        "macho-fat-le": parse_macho, "ar": parse_ar, "zip": lambda blob: parse_zip(blob, name),
        "wasm": parse_wasm, "rpm": parse_rpm, "java-class": parse_java_class,
    }.get(fmt)
    if fmt == "ustar":
        record.update({"format": "ustar", "parsed": True, "libraries": [], "imports": [],
                       "exports": [], "members": _tar_members(data)})
        parser = None
    if fmt == "cpio":
        record.update(parse_cpio(data))
        record["parsed"] = True
        parser = None
    try:
        if parser is not None:
            parsed = parser(data)
            record.update(parsed)
            record["parsed"] = True
        elif fmt == "uimage":
            # the 64-byte header names the image; the generic firmware pass still
            # finds what is inside it (the compressed ramdisk at offset 64)
            record.update(parse_firmware(data))
            record.update(parse_uimage(data))
            record["format"] = "uimage"
            record["parsed"] = True
        elif fmt in ("squashfs", "squashfs-be", "jffs2", "jffs2-le", "ubi", "ubifs",
                     "cramfs", "ext", "uimage", "dtb", "gzip", "xz", "zstd", "bzip2",
                     "lzma", "lz4", "raw", "cpio-odc"):
            parsed = parse_firmware(data) if (fmt in FILESYSTEM_FORMATS or fmt in COMPRESSION_FORMATS
                                              or fmt in ("uimage", "dtb", "ustar")) else {}
            record.update(parsed)
            record["format"] = fmt
            record.setdefault("parsed", fmt in ("uimage", "dtb", "ustar"))
            record["parse_note"] = _unparsed_note(fmt)
        else:
            record["parsed"] = False
            record["parse_note"] = f"unrecognised container format: {fmt}"
    except Exception as exc:  # noqa: BLE001 — a malformed file is reported, never fatal
        record["parsed"] = False
        record["parse_error"] = f"{type(exc).__name__}: {exc}"
    return record


def _unparsed_note(fmt: str) -> str:
    if fmt == "cpio-odc":
        return ("old ASCII cpio (odc) identified; this scanner unpacks newc/crc archives — "
                "repack it with `cpio -H newc` to inventory the contents")
    if fmt in FILESYSTEM_FORMATS:
        return ("filesystem image identified; contents are NOT extracted (squashfs/JFFS2/UBIFS "
                "need binwalk). Scan the mounted or extracted tree to inventory its packages")
    if fmt == "raw":
        return "no known container format; only string-level evidence is available"
    return f"{fmt} identified; container not unpacked"


def scan_file(path: Path, *, root: Path | None = None) -> dict[str, Any] | None:
    """Scan one file if it is a recognisable binary/archive/firmware image."""
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size == 0 or size > MAX_FILE_BYTES:
        return None
    try:
        digest, _ = sha256_file(path)
        with path.open("rb") as handle:
            data = handle.read(min(size, MAX_FILE_BYTES))
    except OSError:
        return None
    ident = identify(data, path.name)
    if ident["format"] == "raw":
        # a raw blob (trimmed firmware, memory dump, vendor blob without magic)
        # is only interesting when it carries crypto evidence — a version banner,
        # a library marker or a strong implementation marker. Anything else is
        # noise and is skipped rather than reported as an unnamed "binary"
        strings = extract_strings(data, limit=800)
        text = "\n".join(strings)
        interesting = any(marker in text for _lib, markers in LIBRARY_MARKERS.items()
                          for marker in markers)
        interesting = interesting or any(marker in text
                                        for markers in STRONG_MARKERS.values()
                                        for marker in markers)
        if not interesting:
            interesting = any(re.search(pattern, text, re.MULTILINE)
                              for _lib, pattern, _vendor in VERSION_PATTERNS)
        if not interesting:
            return None
    record = parse_bytes(data, name=path.name)
    record["path"] = str(path if root is None else path.relative_to(root))
    # parsers that read an identity out of the file itself (an RPM package name)
    # keep it; the file's own name is always available as `file_name`
    record["name"] = record.get("name") or path.name
    record["file_name"] = path.name
    record["sha256"] = digest
    record["size"] = size
    strings = extract_strings(data)
    declared = (record.get("java") or {}).get("strings") or []
    if declared:                       # a class file's string table is its constant pool
        strings = [text for text in declared if text not in strings] + strings
    record["strings_sampled"] = len(strings)
    record.setdefault("packer", None)
    record["packer"] = record["packer"] or detect_packer([], "\n".join(strings[:800]))
    constant_blobs = record.pop("_constant_blobs", [])
    crypto = crypto_evidence(data, strings, imports=record.get("imports") or [],
                             exports=record.get("exports") or [],
                             constants=constant_blobs)
    record["crypto"] = crypto
    embedded_records: list[dict[str, Any]] = []
    containers = follow_containers(data, record, parsed=embedded_records,
                                   prefix=str(record["path"]))
    if containers:
        record["containers_followed"] = containers
    if embedded_records:
        record["embedded"] = embedded_records
        for derived in embedded_records:
            derived.pop("_constant_blobs", None)
    record["findings"] = _binary_findings(record)
    return record


def follow_containers(data: bytes, record: dict[str, Any], *, parsed: list[dict[str, Any]],
                      prefix: str) -> list[dict[str, Any]]:
    """Open whatever the record's own container chain says can be opened."""
    fmt = str(record.get("format") or "")
    results: list[dict[str, Any]] = []
    if fmt in COMPRESSION_FORMATS or fmt in ("ar", "ustar", "zip", "cpio"):
        summary = explore_container(data, fmt, depth=0, prefix=prefix, parsed=parsed)
        if summary:
            results.append(summary)
        return results
    if fmt == "rpm":
        compression = str(record.get("payload_compression") or "").lower()
        offset = int(record.get("payload_offset") or 0)
        if compression in OPENABLE_COMPRESSION and 0 < offset < len(data):
            payload = decompress_payload(data[offset:], compression)
            if payload and payload[:6] in (b"070701", b"070702"):
                summary: dict[str, Any] = {"format": f"rpm/{compression}", "depth": 0,
                                           "inner_format": "cpio", "opened": [], "members": [],
                                           "refused": [], "parsed": 0}
                members = parse_cpio(payload)["members"]
                summary["members_listed"] = len(members)
                summary["members"] = members[:40]
                summary["opened"].append(f"cpio payload listed ({len(members)} members)")
                _parse_member_payloads(parse_cpio_members(payload), depth=0, prefix=prefix,
                                       parsed=parsed, summary=summary)
                results.append(summary)
            elif payload:
                summary = {"format": f"rpm/{compression}", "depth": 0, "inner_format":
                           identify(payload, "")["format"], "opened": [], "members": [],
                           "refused": [], "parsed": 0}
                results.append(summary)
        elif compression:
            results.append({"format": f"rpm/{compression}", "depth": 0, "opened": [], "members": [],
                            "parsed": 0,
                            "refused": [{"format": compression,
                                         "reason": REFUSED_COMPRESSION.get(compression,
                                                                           "payload not followed")}]})
        return results
    if fmt in ("uimage", "dtb", "ext", "gzip", "xz", "bzip2", "lzma") or fmt in FILESYSTEM_FORMATS:
        for container in record.get("containers") or []:
            container_format = str(container.get("format") or "")
            if container_format not in COMPRESSION_FORMATS:
                continue
            offset = int(container.get("offset") or 0)
            if offset <= 0 or offset >= len(data):
                continue
            # the compression stream starts at the offset the container search found
            summary = explore_container(data[offset:], container_format, depth=0,
                                        prefix=f"{prefix}@{offset}", parsed=parsed)
            if summary:
                summary["offset"] = offset
                summary["container"] = container_format
                results.append(summary)
    return results


def _binary_findings(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Per-file findings — each one cites the evidence that produced it."""
    findings: list[dict[str, Any]] = []
    path = record.get("path") or record.get("name")
    crypto = record.get("crypto") or {}

    for library in crypto.get("libraries") or []:
        name, version = library.get("library"), library.get("version")
        classes = ", ".join(library.get("evidence_classes") or []) or "marker"
        if library.get("end_of_life"):
            findings.append({
                "code": "BIN-EOL-CRYPTO", "severity": "HIGH",
                "title": f"{name} {version} is end-of-life",
                "detail": (f"{name} {version} in {path} is no longer maintained upstream and no longer "
                           f"receives security fixes (evidence: {classes})"),
                "path": path, "library": name, "version": version,
            })
        elif not version:
            findings.append({
                "code": "BIN-CRYPTO-NO-VERSION", "severity": "MEDIUM",
                "title": f"{name} detected without a version",
                "detail": (f"{name} evidence found in {path} but no version string, so no CVE can be "
                           f"matched against it (evidence: {classes})"),
                "path": path, "library": name, "version": None,
            })

    if crypto.get("quantum_vulnerable"):
        strong = [row["name"] for row in (crypto.get("algorithm_evidence") or [])
                  if row["name"] in crypto["quantum_vulnerable"] and row["confidence"] >= 0.7]
        findings.append({
            "code": "BIN-QUANTUM-VULNERABLE",
            "severity": "MEDIUM" if strong else "LOW",
            "title": "quantum-vulnerable primitives detected",
            "detail": ("detected " + ", ".join(sorted(crypto["quantum_vulnerable"])[:8])
                       + (" (symbol-level evidence)" if strong else " (string-level evidence only)")
                       + " — these need migration planning (harvest-now-decrypt-later)"),
            "path": path, "algorithms": sorted(crypto["quantum_vulnerable"])[:20],
        })
    if crypto.get("weak_primitives"):
        findings.append({
            "code": "BIN-WEAK-PRIMITIVE-PRESENT", "severity": "HIGH",
            "title": "weak primitives present in the binary",
            "detail": ("detected " + ", ".join(sorted(crypto["weak_primitives"])[:8])
                       + " — confirm whether they are reachable before remediation"),
            "path": path,
        })
    if crypto.get("pqc_markers"):
        detail = "references " + ", ".join(crypto["pqc_markers"][:8])
        classical = sorted(set(crypto.get("quantum_vulnerable") or [])
                           | set(crypto.get("ecc_markers") or []))
        if classical:
            detail += (" — note the binary ALSO references classical primitives that quantum "
                       "computers break (" + ", ".join(classical[:5]) + ")")
        findings.append({
            "code": "BIN-PQC-CAPABLE", "severity": "INFO",
            "title": "post-quantum markers present", "detail": detail, "path": path,
        })
    if crypto.get("ecc_markers") and not crypto.get("pqc_markers"):
        findings.append({
            "code": "BIN-ECC-NO-PQC", "severity": "LOW",
            "title": "classical elliptic-curve crypto without PQC",
            "detail": ("references " + ", ".join(crypto["ecc_markers"][:6])
                       + " with no post-quantum marker — migration candidate for "
                         "harvest-now-decrypt-later exposure"),
            "path": path,
        })
    if record.get("packed_or_encrypted") and not record.get("packer"):
        findings.append({
            "code": "BIN-HIGH-ENTROPY", "severity": "MEDIUM",
            "title": "high-entropy content (packed or encrypted)",
            "detail": (f"entropy {record.get('entropy')} suggests compression/encryption and no known "
                       "packer matched, so string-level crypto detection may be incomplete"),
            "path": path,
        })
    if record.get("static") and record.get("crypto", {}).get("libraries"):
        findings.append({
            "code": "BIN-STATIC-CRYPTO", "severity": "INFO",
            "title": "statically linked with crypto",
            "detail": ("crypto implementation is linked into the binary (no dynamic dependency to "
                       "fingerprint) — version detection relies on embedded version strings"),
            "path": path,
        })
    if record.get("embedded_filesystems"):
        detected = ", ".join(sorted({str(row.get("format")) for row in record["embedded_filesystems"]}))
        followed = ", ".join(sorted({str(row.get("format")) for row in
                                     (record.get("containers_followed") or [])}))
        findings.append({
            "code": "BIN-FIRMWARE-NOT-EXTRACTED", "severity": "LOW",
            "title": "filesystem inside the image was not extracted",
            "detail": (f"detected {detected} filesystem(s) inside the image; their contents are NOT "
                       "unpacked by this scanner (that needs binwalk/squashfs-tools). "
                       + (f"What could be opened was followed ({followed}); "
                          if followed else "")
                       + "anything inside the unopened filesystems is out of scope for this report"),
            "path": path, "containers": detected,
        })
    hardening = record.get("hardening") or {}
    if record.get("executable_stack") or hardening.get("stack_exec"):
        findings.append({
            "code": "BIN-EXECUTABLE-STACK", "severity": "HIGH",
            "title": ("GNU_STACK segment is executable (NX disabled)"
                      if record.get("executable_stack")
                      else "MH_ALLOW_STACK_EXECUTION is set (executable stack)"),
            "detail": "the binary asks for an executable stack, which makes injected code runnable",
            "path": path,
        })
    if hardening and hardening.get("nx") is True and record.get("dynamically_linked") and not hardening.get("relro"):
        findings.append({
            "code": "BIN-NO-RELRO", "severity": "LOW",
            "title": "no RELRO segment",
            "detail": ("GOT entries stay writable after load; full RELRO needs PT_GNU_RELRO "
                       "(and BIND_NOW for the full form)"),
            "path": path,
        })
    elif hardening.get("relro") and not hardening.get("full_relro") and record.get("dynamically_linked"):
        findings.append({
            "code": "BIN-PARTIAL-RELRO", "severity": "INFO",
            "title": "partial RELRO only",
            "detail": "PT_GNU_RELRO present but no BIND_NOW — the GOT is still lazily writable",
            "path": path,
        })
    if (hardening and record.get("type") == "executable" and hardening.get("nx") is not None
            and not hardening.get("canary")):
        findings.append({
            "code": "BIN-NO-STACK-CANARY", "severity": "LOW",
            "title": "no stack canary",
            "detail": "no __stack_chk_fail reference — stack-smashing protection is not compiled in",
            "path": path,
        })
    packer = record.get("packer")
    if packer:
        findings.append({
            "code": "BIN-PACKED", "severity": "MEDIUM",
            "title": f"packed or obfuscated ({packer['name']})",
            "detail": str(packer.get("note") or "packed content"),
            "path": path, "markers": packer.get("markers"),
        })
    if record.get("encrypted"):
        findings.append({
            "code": "BIN-ENCRYPTED", "severity": "HIGH",
            "title": "binary is encrypted (Mach-O cryptid set)",
            "detail": ("the load command marks the segment as encrypted, so its strings and "
                       "symbols are not readable from the file — crypto evidence for this "
                       "binary is structurally incomplete"),
            "path": path,
        })
    if record.get("format") == "macho":
        signature = record.get("signature") or {}
        if signature.get("present") is False:
            findings.append({
                "code": "BIN-UNSIGNED-MACHO", "severity": "INFO",
                "title": "no Mach-O code signature",
                "detail": str(signature.get("note") or "no LC_CODE_SIGNATURE"),
                "path": path,
            })
        for entitlement in signature.get("notable_entitlements") or []:
            severity = "MEDIUM" if entitlement in (
                "com.apple.security.get-task-allow",
                "com.apple.security.cs.allow-unsigned-executable-memory",
                "com.apple.security.cs.disable-library-validation",
                "task_for_pid-allow") else "LOW"
            findings.append({
                "code": "BIN-ENTITLEMENT", "severity": severity,
                "title": f"notable entitlement granted ({entitlement})",
                "detail": ("the code signature grants this entitlement — it widens what the "
                           "process may do and is worth a human look"),
                "path": path, "entitlement": entitlement,
            })
        if record.get("type") == "executable" and not (signature.get("hardened_runtime")
                                                       or record.get("hardening", {}).get(
                                                           "hardened_runtime")):
            findings.append({
                "code": "BIN-NO-HARDENED-RUNTIME", "severity": "LOW",
                "title": "no hardened-runtime flag",
                "detail": ("the code signature (when present) does not set the hardened-runtime "
                           "flag; library validation and runtime checks are not enforced"),
                "path": path,
            })
    image = record.get("uimage") or {}
    if image.get("header_crc_verified") is False:
        findings.append({
            "code": "BIN-UIMAGE-CRC", "severity": "LOW",
            "title": "uImage header CRC mismatch",
            "detail": (f"the header checksum does not match the file ({image.get('header_crc')} "
                       f"stored vs {image.get('header_crc_expected')} computed) — the image was "
                       "modified or damaged after it was built"),
            "path": path,
        })
    if image.get("data_crc_verified") is False:
        findings.append({
            "code": "BIN-UIMAGE-PAYLOAD", "severity": "HIGH",
            "title": "uImage payload CRC mismatch",
            "detail": ("the payload checksum in the header does not match the payload bytes — "
                       "the firmware image is corrupt or was re-packed"),
            "path": path,
        })
    if image.get("truncated"):
        findings.append({
            "code": "BIN-UIMAGE-PAYLOAD", "severity": "HIGH",
            "title": "uImage payload is truncated",
            "detail": (f"the header declares {image.get('payload_size')} payload bytes but the "
                       "file holds fewer"),
            "path": path,
        })
    for container in record.get("containers_followed") or []:
        if container.get("package") and container.get("package_signed") is False:
            findings.append({
                "code": "BIN-DEB-UNSIGNED", "severity": "LOW",
                "title": "no detached signature on the .deb",
                "detail": ("the archive has no `_gpgorigin` member, so this package's contents "
                           "are not covered by a signature inside the file. Note that .deb "
                           "signatures normally live in the repository metadata (Release/InRelease) "
                           "rather than in the package, so this is a provenance signal, not evidence "
                           "of tampering"),
                "path": path,
            })
    if record.get("format") == "rpm" and record.get("signed") is False:
        findings.append({
            "code": "BIN-RPM-UNSIGNED", "severity": "MEDIUM",
            "title": "RPM package carries no signature",
            "detail": ("the signature header has no RSA/DSA/PGP entry, so the package's "
                       "provenance cannot be established from the file — anyone who can write "
                       "this artefact can rewrite its contents"),
            "path": path,
        })
    if record.get("format") == "pe":
        hardening = record.get("hardening") or {}
        if hardening.get("aslr") is False:
            findings.append({
                "code": "BIN-NO-ASLR", "severity": "MEDIUM",
                "title": "PE image is not position independent (no DYNAMIC_BASE)",
                "detail": ("IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE is not set, so the image "
                           "loads at its preferred base address and its addresses are stable "
                           "across runs — a ROP target"),
                "path": path,
            })
        if hardening.get("dep") is False:
            findings.append({
                "code": "BIN-NO-DEP", "severity": "HIGH",
                "title": "PE image does not opt into DEP (no NX_COMPAT)",
                "detail": ("IMAGE_DLLCHARACTERISTICS_NX_COMPAT is not set, so the loader may "
                           "map writable pages as executable"),
                "path": path,
            })
        if hardening.get("cfg") is False:
            findings.append({
                "code": "BIN-NO-CFG", "severity": "LOW",
                "title": "PE image is not compiled with Control Flow Guard",
                "detail": ("IMAGE_DLLCHARACTERISTICS_GUARD_CF is not set — indirect calls are "
                           "not checked"),
                "path": path,
            })
        elif hardening.get("cfg_instrumented") is False:
            findings.append({
                "code": "BIN-NO-CFG", "severity": "LOW",
                "title": "Control Flow Guard is declared but not instrumented",
                "detail": ("GUARD_CF is set but the load config does not mark the image as CFG "
                           "instrumented, so the check function may not be called"),
                "path": path,
            })
        if record.get("load_config") and hardening.get("gs") is False:
            findings.append({
                "code": "BIN-NO-STACK-CANARY", "severity": "LOW",
                "title": "PE image has a load config but no security cookie (/GS)",
                "detail": ("the load config directory is present and its SecurityCookie pointer "
                           "is null, so stack-cookie protection is not initialised"),
                "path": path,
            })
    for dll in record.get("delay_imports") or []:
        findings.append({
            "code": "BIN-DELAYED-IMPORT", "severity": "INFO",
            "title": f"delay-loaded dependency ({dll})",
            "detail": ("this DLL is imported through the delay-load table: it is absent from the "
                       "static import directory, but it is still loaded (and its code still runs) "
                       "the first time a delayed call is made"),
            "path": path,
        })
    signature = record.get("signature")
    if signature and signature.get("present") is False and record.get("format") == "pe":
        findings.append({
            "code": "BIN-UNSIGNED-PE", "severity": "INFO",
            "title": "no Authenticode signature table",
            "detail": ("the PE has no certificate table — unsigned, or the signature was stripped; "
                       "code signing is not proven either way by this scanner"),
            "path": path,
        })
    for library, versions in (record.get("symbol_versions") or {}).items():
        if not any(token in library for token in ("crypto", "ssl", "sodium", "tls", "ssl3")):
            continue
        known = {row["library"].lower() for row in (crypto.get("libraries") or [])
                 if row.get("version")}
        if known:
            continue
        crypto_versions = [v for v in versions if v.upper().startswith(("OPENSSL", "LIBRESSL", "GNUTLS"))]
        findings.append({
            "code": "BIN-CRYPTO-VERSION-FLOOR", "severity": "INFO",
            "title": f"{library} version floor from its symbol requirements",
            "detail": (f"{path} requires {', '.join(sorted(crypto_versions)[:4]) or ', '.join(versions[:4])} "
                       f"from {library} — the exact version is not embedded in this file, so CVEs "
                       "cannot be matched from it alone"),
            "path": path, "library": library,
        })
    if crypto.get("weak_primitives") and record.get("format") == "java-class":
        findings.append({
            "code": "BIN-WEAK-PRIMITIVE-CLASS", "severity": "MEDIUM",
            "title": "weak primitive referenced by a Java class",
            "detail": "the constant pool names " + ", ".join(sorted(crypto["weak_primitives"])[:6]),
            "path": path,
        })
    java = record.get("java") or {}
    if record.get("format") == "java-class" and java.get("constant_pool_truncated_at"):
        findings.append({
            "code": "BIN-PARTIAL-PARSE", "severity": "LOW",
            "title": "Java constant pool parsed only in part",
            "detail": (f"the walk stopped at entry {java['constant_pool_truncated_at']}; classes and "
                       "strings after that point are not in this report"),
            "path": path,
        })
    embedded = record.get("embedded") or []
    for derived in embedded:
        derived_crypto = derived.get("crypto") or {}
        libraries = derived_crypto.get("libraries") or []
        if not libraries and not derived_crypto.get("algorithms"):
            continue
        eol = [row for row in libraries if row.get("end_of_life")]
        detail = (f"{derived.get('path')} contains "
                  + ", ".join(f"{row['library']} {row.get('version') or '(no version)'}"
                              for row in libraries[:4])
                  if libraries else
                  f"{derived.get('path')} references "
                  + ", ".join(derived_crypto.get("algorithms")[:6]))
        findings.append({
            "code": "BIN-EMBEDDED-CRYPTO", "severity": "HIGH" if eol else "MEDIUM",
            "title": "cryptographic implementation inside an embedded container",
            "detail": (detail + (" — includes end-of-life components: "
                                 + ", ".join(f"{row['library']} {row.get('version')}" for row in eol)
                                 if eol else "")),
            "path": derived.get("path"), "derived_from": path,
            "libraries": [{"library": row["library"], "version": row.get("version"),
                           "end_of_life": bool(row.get("end_of_life"))} for row in libraries[:8]],
        })
    for container in record.get("containers_followed") or []:
        if container.get("parsed") or container.get("members_listed"):
            findings.append({
                "code": "BIN-CONTAINER-FOLLOWED", "severity": "INFO",
                "title": f"container followed ({container.get('format')})",
                "detail": "; ".join(container.get("opened") or []) or
                          f"listed {container.get('members_listed')} member(s)",
                "path": path,
            })
        for refused in container.get("refused") or []:
            findings.append({
                "code": "BIN-CONTAINER-REFUSED", "severity": "LOW",
                "title": f"container not opened ({refused.get('format') or 'member'})",
                "detail": f"reason: {refused.get('reason')}",
                "path": path,
            })
    parsed = record.get("parsed")
    if record.get("format") == "raw" or parsed is False or (parsed is None and record.get("parse_note")):
        findings.append({
            "code": "BIN-NOT-PARSED", "severity": "LOW",
            "title": f"{record.get('format')} identified but not parsed",
            "detail": str(record.get("parse_note") or "container not unpacked"),
            "path": path,
        })
    for rpath in record.get("rpath") or []:
        if rpath.startswith(("/tmp", "/home", ".", "")):
            findings.append({
                "code": "BIN-RPATH-WRITABLE", "severity": "LOW",
                "title": "RPATH points at a non-system directory",
                "detail": f"DT_RUNPATH/RPATH {rpath!r} — a writable search path can become a load hijack",
                "path": path,
            })
    return findings


def scan_path(target: str | Path, *, recursive: bool = True, include_raw: bool = False,
              max_binaries: int = MAX_BINARIES) -> dict[str, Any]:
    """Walk a file or directory and scan every recognisable binary."""
    base = Path(target).expanduser()
    if not base.exists():
        raise FileNotFoundError(f"target not found: {base}")
    if base.is_file():
        candidates = [base]
        root = base.parent
    else:
        root = base
        walker = base.rglob("*") if recursive else base.glob("*")
        candidates = []
        for index, candidate in enumerate(walker):
            if index >= MAX_FILES_WALKED:
                break
            if not candidate.is_file():
                continue
            if any(part in SKIP_DIRS for part in candidate.parts):
                continue
            candidates.append(candidate)

    records: list[dict[str, Any]] = []
    for candidate in candidates:
        if len(records) >= max_binaries:
            break
        record = scan_file(candidate, root=root)
        if record is None:
            continue
        if record["format"] == "raw" and not include_raw:
            continue
        records.append(record)

    return {
        "target": str(base),
        "target_kind": "binary",
        "files_walked": len(candidates),
        "binaries_scanned": len(records),
        "binaries": records,
        "by_format": _counts(record["format"] for record in records),
        "by_arch": _counts(str(record.get("arch") or record.get("machine") or "unknown")
                           for record in records),
        "limits": {"max_binaries": max_binaries, "max_file_bytes": MAX_FILE_BYTES,
                   "truncated": len(records) >= max_binaries},
    }


def _record_packages(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Packages the file declares about itself, in any of the formats we parse."""
    packages: list[dict[str, Any]] = []
    if record.get("name") and record.get("version") and record.get("format") == "rpm":
        packages.append({"name": record["name"], "version": record.get("version"),
                         "manager": "rpm", "license": record.get("license"),
                         "vendor": record.get("vendor"), "arch": record.get("arch_package")})
    for container in record.get("containers_followed") or []:
        package = container.get("package")
        if package:
            packages.append({"name": package["name"], "version": package.get("version"),
                             "manager": "deb", "arch": package.get("architecture"),
                             "depends": package.get("depends")})
    go = record.get("go") or {}
    if go.get("module"):
        packages.append({"name": go["module"], "version": go.get("module_version"),
                         "manager": "go", "scope": "root"})
    java = record.get("java") or {}
    if java.get("artifact"):
        name = f"{java['group']}:{java['artifact']}" if java.get("group") else java["artifact"]
        packages.append({"name": name, "version": java.get("version"), "manager": "maven"})
    python = record.get("python") or {}
    if python.get("name"):
        packages.append({"name": python["name"], "version": python.get("version"),
                         "manager": "pip", "license": python.get("license")})
    return packages


def _flatten_records(records: Iterable[dict[str, Any]],
                     depth: int = 0) -> list[dict[str, Any]]:
    """Top-level binaries plus everything that was extracted from a container.

    An implementation found inside an embedded image is part of the artefact's
    inventory, and it carries ``derived_from`` so the report can say where it came
    from instead of presenting it as a loose file.
    """
    out: list[dict[str, Any]] = []
    if depth > MAX_EXTRACT_DEPTH + 1:
        return out
    for record in records:
        out.append(record)
        out.extend(_flatten_records(record.get("embedded") or [], depth + 1))
    return out


def _counts(values: Iterable[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


# ------------------------------------------------------- result assembly ---- #
def sbom_result(scan: dict[str, Any]) -> dict[str, Any]:
    """Adapt a binary scan to the canonical result shape the SBOM renderer takes.

    Packages are what the binary *contains* (Go modules, jar/wheel/NuGet
    coordinates). Linked dependencies of the host system are libraries, not
    packages — mixing the two would report the OS as part of the artefact.
    """
    packages: list[dict[str, Any]] = []
    libraries: list[dict[str, Any]] = []
    dependencies: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    seen_packages: set[tuple[str, str]] = set()
    seen_libraries: set[tuple[str, str]] = set()

    for record in _flatten_records(scan.get("binaries") or []):
        path = record.get("path") or record.get("name")
        go = record.get("go") or {}
        if go.get("module"):
            # the module the binary was built from is part of the artefact's identity
            key = (str(go["module"]).lower(), str(go.get("module_version") or ""))
            if key not in seen_packages:
                seen_packages.add(key)
                packages.append({"name": go["module"], "version": go.get("module_version"),
                                 "manager": "go", "scope": "root", "source": path,
                                 "note": f"main module built into {record.get('name')}",
                                 "go_version": go.get("go_version")})
        if go.get("go_version"):
            key = ("go", f"go{go['go_version']}")
            if key not in seen_packages:
                seen_packages.add(key)
                packages.append({"name": "go", "version": go["go_version"], "manager": "go",
                                 "scope": "resolved", "source": path,
                                 "note": "toolchain embedded in the binary"})
        for dep in go.get("dependencies") or []:
            if dep.get("kind") != "dep":
                continue
            key = (str(dep["name"]).lower(), str(dep.get("version") or ""))
            if key in seen_packages:
                continue
            seen_packages.add(key)
            purl = f"pkg:golang/{dep['name']}@{dep['version']}" if dep.get("version") else None
            packages.append({"name": dep["name"], "version": dep.get("version"), "manager": "go",
                             "scope": "resolved", "purl": purl, "source": path,
                             "integrity": dep.get("sum"), "direct": False})
            if go.get("module"):
                dependencies.append({"from": go["module"], "to": dep["name"]})
        java = record.get("java") or {}
        if java.get("artifact"):
            key = (str(java["artifact"]).lower(), str(java.get("version") or ""))
            if key not in seen_packages:
                seen_packages.add(key)
                group = java.get("group")
                name = f"{group}:{java['artifact']}" if group else str(java["artifact"])
                packages.append({"name": name, "version": java.get("version"), "manager": "maven",
                                 "scope": "resolved", "source": path,
                                 "classes": java.get("class_count")})
        python = record.get("python") or {}
        if python.get("name"):
            key = (str(python["name"]).lower(), str(python.get("version") or ""))
            if key not in seen_packages:
                seen_packages.add(key)
                packages.append({"name": python["name"], "version": python.get("version"),
                                 "manager": "pip", "scope": "resolved",
                                 "license": python.get("license"), "source": path})
        for library in (record.get("crypto") or {}).get("libraries") or []:
            name = str(library.get("library"))
            version = library.get("version")
            key = (name.lower(), str(version or ""))
            if key in seen_libraries:
                row = next(row for row in libraries if (str(row["name"]).lower(), str(row.get("version") or "")) == key)
                row.setdefault("found_in", []).append(path)
                continue
            seen_libraries.add(key)
            algorithms = (record.get("crypto") or {}).get("algorithms") or []
            libraries.append({
                "name": name, "version": version, "manager": "binary",
                "vendor": library.get("provider"), "algorithms": algorithms,
                "evidence": library.get("evidence_classes"), "deprecated": bool(library.get("end_of_life")),
                "language": "c", "found_in": [path],
            })
            pkg_key = (name.lower(), str(version or ""))
            if pkg_key not in seen_packages:
                # a crypto implementation found inside a binary is a component of
                # that artefact, so it becomes a package too (it appears in the
                # SBOM, gets licence treatment and can be matched against feeds)
                seen_packages.add(pkg_key)
                packages.append({
                    "name": name, "version": version, "manager": "binary", "scope": "bundled",
                    "source": path, "vendor": library.get("provider"),
                    "note": ("embedded crypto implementation detected in " + str(path)
                             + " (evidence: " + ", ".join(library.get("evidence_classes") or []) + ")"),
                    "algorithms": algorithms, "detection": "binary-evidence",
                })
        if go.get("module"):
            dependencies.append({"from": record.get("name"), "to": go["module"]})
        findings.extend(record.get("findings") or [])

    all_records = _flatten_records(scan.get("binaries") or [])
    crypto_libraries = [row for row in libraries]
    algorithms = sorted({algorithm for record in all_records
                         for algorithm in (record.get("crypto") or {}).get("algorithms") or []})
    pqc = sorted({marker for record in all_records
                  for marker in (record.get("crypto") or {}).get("pqc_markers") or []})
    quantum_vulnerable = sorted({name for record in all_records
                                 for name in (record.get("crypto") or {}).get("quantum_vulnerable") or []})
    return {
        "target": scan.get("target"),
        "target_kind": "binary",
        "packages": packages,
        "libraries": crypto_libraries,
        "binaries": [{
            "name": record.get("name"),
            "path": record.get("path"),
            "file_name": record.get("file_name") or record.get("name"),
            "version": ((record.get("version_info") or {}).get("version")
                        or record.get("version")
                        or next((lib.get("version")
                                 for lib in (record.get("crypto") or {}).get("libraries") or []
                                 if lib.get("version")), None)),
            "sha256": record.get("sha256"),
            "type": f"{record.get('format')}:{record.get('arch') or 'unknown'}"
                    + (":efi" if record.get("uefi") else ""),
            "detection_method": "magic+parser",
            "algorithms": (record.get("crypto") or {}).get("algorithms") or [],
            "libraries": record.get("libraries") or [],
            "size": record.get("size"),
            "stripped": record.get("stripped"),
            "static": record.get("static"),
            "format": record.get("format"),
            "arch": record.get("arch") or record.get("machine"),
            "hardening": record.get("hardening"),
            "packer": (record.get("packer") or {}).get("name"),
            "interpreter": record.get("interpreter"),
            "publisher": (record.get("version_info") or {}).get("vendor"),
            "product": (record.get("version_info") or {}).get("product"),
            "symbol_versions": record.get("symbol_versions"),
            "dylib_versions": record.get("dylib_versions"),
            "signature": {k: v for k, v in (record.get("signature") or {}).items()
                          if k != "entitlements"} if record.get("signature") else None,
            "install_name": record.get("install_name"),
            "minimum_os": record.get("minimum_os"),
            "encrypted": record.get("encrypted"),
            "uimage": record.get("uimage"),
            "signature_package": record.get("signature") if record.get("format") == "rpm" else None,
            "load_config": record.get("load_config"),
            "package_signed": (record.get("containers_followed") or [{}])[0].get("package_signed"),
            "signed_package": record.get("signed"),
            "symbols_sampled": record.get("symbols_sampled"),
            "import_count": len(record.get("imports") or []),
            "export_count": len(record.get("exports") or []),
            "sections": (record.get("sections") or [])[:16],
            "crypto_constants": [row.get("algorithm") for row in record.get("crypto_constants") or []],
            "packages_inside": [{"name": pkg.get("name"), "version": pkg.get("version"),
                                 "manager": pkg.get("manager")}
                                for pkg in _record_packages(record)],
            "derived_from": record.get("derived_from"),
            "depth": record.get("depth"),
            "container": (record.get("containers_followed") or [{}])[0].get("format")
            if record.get("containers_followed") else None,
        } for record in _flatten_records(scan.get("binaries") or [])],
        "vulnerabilities": [],
        "manifests": [],
        "manifest_count": 0,
        "dependencies": dependencies,
        "crypto": {"algorithms": algorithms, "pqc_markers": pqc,
                   "quantum_vulnerable": quantum_vulnerable,
                   "libraries": [{"name": row["name"], "version": row.get("version"),
                                  "end_of_life": row.get("deprecated")} for row in libraries]},
        "findings": findings,
        "findings_by_severity": _counts(str(row.get("severity"))
                                        for row in findings),
        "binaries_scanned": scan.get("binaries_scanned", 0),
        "files_walked": scan.get("files_walked", 0),
        "by_format": scan.get("by_format") or {},
        "by_arch": scan.get("by_arch") or {},
        "embedded_binaries": sum(1 for record in all_records if record.get("derived_from")),
        "containers_followed": sum(len(record.get("containers_followed") or [])
                                   for record in scan.get("binaries") or []),
        "containers_refused": sum(len(container.get("refused") or [])
                                  for record in scan.get("binaries") or []
                                  for container in record.get("containers_followed") or []),
        "packed_binaries": sum(1 for record in all_records if record.get("packer")),
        "limits": scan.get("limits") or {},
        "extraction_limits": {"max_payload_bytes": MAX_EXTRACT_BYTES,
                              "max_depth": MAX_EXTRACT_DEPTH,
                              "max_members": MAX_EXTRACT_FILES,
                              "max_member_bytes": MAX_MEMBER_BYTES},
    }


# ------------------------------------------------------------- CBOM --------- #
#: ordered primitive rules (first match wins) — a CBOM asset must carry a
#: primitive, and a guessed one is worse than none, so anything unmatched is
#: reported as "unknown" instead of being forced into a family
_ALGORITHM_PRIMITIVE_RULES: tuple[tuple[str, str], ...] = (
    (r"AES.*(GCM|CCM|OCB)|CHACHA20-POLY1305|POLY1305", "aead"),
    (r"^AES", "block-cipher"),
    (r"CHACHA20|SALSA20|RC4", "stream-cipher"),
    (r"ML-KEM|KYBER|FRODOKEM|BIKE|HQC|SNTRUP", "kem"),
    (r"ML-DSA|DILITHIUM|SLH-DSA|SPHINCS|FALCON|ECDSA|ED25519|ED448|^RSA.*SIGN", "signature"),
    (r"X25519|X448|ECDH|^DH|KEYAGREE|KEY-AGREE", "key-agree"),
    (r"^RSA|^ELGAMAL", "pke"),
    (r"SHA|MD5|MD4|BLAKE|RIPEMD", "hash"),
    (r"HMAC|KMAC", "mac"),
    (r"ARGON2|SCRYPT|PBKDF|BCRYPT|HKDF", "kdf"),
    (r"CSPRNG|RAND|DRBG", "drbg"),
    (r"^TLS|^SSH|^IPSEC", "protocol"),
)


def algorithm_primitive(name: str) -> str:
    """CycloneDX primitive for an algorithm name, or "unknown" — never a guess."""
    upper = str(name or "").upper().replace("_", "-")
    for pattern, primitive in _ALGORITHM_PRIMITIVE_RULES:
        if re.search(pattern, upper):
            return primitive
    return "unknown"


def cbom_document(scan: dict[str, Any], *, target: str | None = None,
                  created_by: str | None = None) -> dict[str, Any]:
    """CycloneDX CBOM (1.5) of the cryptographic assets found in the binaries.

    One ``cryptographic-asset`` component per (library, algorithm) pair — the
    algorithm is the asset; the library carrying it is recorded as a property
    together with the file it was found in, so the inventory can answer both
    "what algorithms do we depend on" and "which binary brings them".
    """
    import uuid
    from datetime import datetime, timezone

    result = sbom_result(scan) if "binaries" in scan and "packages" not in scan else scan
    components: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    seen_libraries: set[str] = set()
    # the same implementation shows up in the top-level file *and* inside every
    # container that carries it, so an existing asset gains locations instead of
    # being reported once and then ignored
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    def _add_algorithm_asset(name: str, version: str | None, library_row: dict[str, Any],
                             algorithm: str, record: dict[str, Any], path: str) -> None:
        """One algorithm asset per (implementation, algorithm), locations merged."""
        key = (name, str(algorithm))
        if key in by_key:
            occurrences = by_key[key]["evidence"]["occurrences"]
            if not any(row["location"] == str(path) for row in occurrences):
                occurrences.append({"location": str(path)})
            return
        vulnerable = any(token.lower() in str(algorithm).lower()
                         for token in QUANTUM_VULNERABLE_ALGORITHMS)
        properties = _asset_properties(name, version, library_row, path,
                                       derived_from=record.get("derived_from"),
                                       depth=record.get("depth"))
        properties.append({"name": "cryptoscan:quantum-vulnerable",
                           "value": "true" if vulnerable else "false"})
        components.append({
            "type": "cryptographic-asset",
            "bom-ref": f"cryptoscan:binary/{name}@{version or 'unknown'}/{algorithm}",
            "name": str(algorithm),
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": algorithm_primitive(str(algorithm)),
                    "implementationPlatform": "binary",
                    # absent when it does not apply — a null would be schema-invalid
                    **({"nistQuantumSecurityLevel": 0} if vulnerable else {}),
                },
            },
            "evidence": {"occurrences": [{"location": str(path)}]},
            "properties": properties,
        })
        by_key[key] = components[-1]

    for record in _flatten_records(scan.get("binaries") or []):
        path = record.get("path") or record.get("name")
        crypto = record.get("crypto") or {}
        if not crypto.get("libraries"):
            # an algorithm proven by a constant table or a transformation string
            # with no implementation claimed: still a cryptographic asset
            for algorithm in crypto.get("algorithms") or []:
                _add_algorithm_asset("unattributed", None, {}, str(algorithm), record, path)
            continue
        for library in crypto.get("libraries") or []:
            name = str(library.get("library"))
            version = library.get("version")
            algorithms = crypto.get("algorithms") or []
            if not algorithms:
                if name in seen_libraries:
                    continue
                seen_libraries.add(name)
                if (name, "") in by_key:
                    continue
                component = {
                    "type": "cryptographic-asset",
                    "bom-ref": f"cryptoscan:binary/{name}@{version or 'unknown'}",
                    "name": name,
                    "cryptoProperties": {
                        "assetType": "algorithm",
                        "algorithmProperties": {"primitive": "implementation"},
                    },
                    "properties": _asset_properties(name, version, library, path,
                                                    derived_from=record.get("derived_from"),
                                                    depth=record.get("depth")),
                }
                by_key[(name, "")] = component
                components.append(component)
                continue
            for algorithm in algorithms:
                _add_algorithm_asset(name, version, library, str(algorithm), record, path)
        for marker in crypto.get("pqc_markers") or []:
            key = ("post-quantum", str(marker))
            if key in seen:
                continue
            seen.add(key)
            components.append({
                "type": "cryptographic-asset",
                "bom-ref": f"cryptoscan:binary/post-quantum/{marker}",
                "name": str(marker),
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": algorithm_primitive(str(marker)),
                        "implementationPlatform": "binary",
                        "nistQuantumSecurityLevel": 3,
                    },
                },
                "evidence": {"occurrences": [{"location": str(path)}]},
                "properties": [{"name": "cryptoscan:post-quantum", "value": "true"},
                               {"name": "cryptoscan:found-in", "value": str(path)}],
            })

    metadata: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tools": [{"vendor": "CryptoScan", "name": "binary scanner", "version": "1.0"}],
        "component": {"type": "application", "bom-ref": "cryptoscan:target",
                      "name": str(target or scan.get("target") or "binaries")},
        "properties": [
            {"name": "cryptoscan:binaries-scanned", "value": str(result.get("binaries_scanned", 0))},
            {"name": "cryptoscan:files-walked", "value": str(result.get("files_walked", 0))},
        ],
    }
    if created_by:
        metadata["authors"] = [{"name": str(created_by)}]
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": metadata,
        "components": components,
    }
    return document


def _asset_properties(library: str, version: str | None, library_row: dict[str, Any],
                      path: str, *, derived_from: str | None = None,
                      depth: int | None = None) -> list[dict[str, str]]:
    """Asset properties, including where an embedded asset came from."""
    properties = [{"name": "cryptoscan:library", "value": str(library)},
                  {"name": "cryptoscan:found-in", "value": str(path)}]
    if derived_from:
        properties.append({"name": "cryptoscan:derived-from", "value": str(derived_from)})
        properties.append({"name": "cryptoscan:depth", "value": str(depth or 1)})
    if version:
        properties.append({"name": "cryptoscan:library-version", "value": str(version)})
    if library_row.get("evidence_classes"):
        properties.append({"name": "cryptoscan:evidence",
                           "value": ", ".join(library_row["evidence_classes"])})
    if library_row.get("end_of_life"):
        properties.append({"name": "cryptoscan:end-of-life", "value": "true"})
    return properties
