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
    ("java-class", b"\xca\xfe\xba\xbe"),      # ambiguous with fat Mach-O — resolved below
)
COMPRESSION_FORMATS = {"gzip", "xz", "zstd", "bzip2", "lzma", "lz4"}
FILESYSTEM_FORMATS = {"squashfs", "squashfs-be", "jffs2", "jffs2-le", "ubi", "ubifs", "cramfs", "ext"}
ARCHIVE_FORMATS = {"ar", "zip", "rpm"}
ELF_FORMATS = {"elf"}
PE_FORMATS = {"pe"}
MACHO_FORMATS = {"macho", "macho64", "macho-be", "macho64-be", "macho-fat", "macho-fat-le"}
EXECUTABLE_FORMATS = ELF_FORMATS | PE_FORMATS | MACHO_FORMATS | {"wasm"}

ELF_MACHINES = {
    0x03: "x86", 0x08: "MIPS", 0x14: "PowerPC", 0x15: "PowerPC64", 0x16: "S390",
    0x28: "ARM", 0x2A: "SuperH", 0x32: "IA-64", 0x3E: "x86-64", 0xB7: "AArch64",
    0xF3: "RISC-V", 0x102: "LoongArch",
}
ELF_TYPES = {0: "none", 1: "relocatable", 2: "executable", 3: "shared", 4: "core"}
PE_MACHINES = {0x014C: "x86", 0x8664: "x86-64", 0x01C0: "ARM", 0xAA64: "AArch64",
               0x0200: "IA-64", 0x01C4: "ARMv7", 0x0166: "MIPS"}
MACHO_CPUS = {7: "x86", 0x01000007: "x86-64", 12: "ARM", 0x0100000C: "AArch64",
              18: "PowerPC", 0x01000012: "PowerPC64"}
MACHO_PLATFORMS = {1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS", 6: "macCatalyst"}

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
    go = parse_go_buildinfo(data, by_name, reader)
    if go:
        out["go"] = go
    return out


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
        out["subsystem"] = {2: "windows-gui", 3: "console"}.get(subsystem, str(subsystem))
    except Exception:  # noqa: BLE001
        pass
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

    if number_of_dirs > 1:
        try:
            import_rva, import_size = reader.unpack("<II", directory_base + 8)
            out["libraries"] = _pe_imports(reader, import_rva, import_size, rva_to_offset)
        except Exception:  # noqa: BLE001
            pass
    if number_of_dirs > 14:
        try:
            clr_rva, clr_size = reader.unpack("<II", directory_base + 14 * 8)
            if clr_rva and clr_size:
                out["dotnet"] = True
                out["framework"] = ".NET"
        except Exception:  # noqa: BLE001
            pass
    out["imports"] = [f"{dll}!" for dll in out["libraries"]]
    return out


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
                cpu, _sub, offset, size = struct.unpack_from(">IIII", data, 8 + index * 20)
            except Exception:  # noqa: BLE001
                break
            architectures.append({"cpu": MACHO_CPUS.get(cpu, hex(cpu)), "size": size, "offset": offset})
        out: dict[str, Any] = {"format": "macho", "type": "universal",
                               "architectures": architectures, "libraries": []}
        if architectures and architectures[0]["offset"]:
            sliced = data[architectures[0]["offset"]:]
            try:
                thin = _parse_macho_thin(sliced)
                out.update({k: v for k, v in thin.items() if k not in ("format", "type")})
                out["type"] = "universal"
                out["architectures"] = architectures
            except Exception:  # noqa: BLE001
                pass
        return out
    return _parse_macho_thin(data)


def _parse_macho_thin(data: bytes) -> dict[str, Any]:
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
    cpu, _sub, filetype = struct.unpack_from(end + "III", data, 4)
    ncmds, _sizeofcmds = struct.unpack_from(end + "II", data, 16)
    out: dict[str, Any] = {
        "format": "macho", "bits": 64 if is64 else 32,
        "arch": MACHO_CPUS.get(cpu, hex(cpu)),
        "type": {1: "object", 2: "executable", 6: "dylib", 8: "bundle"}.get(filetype, "other"),
        "libraries": [], "imports": [], "rpath": [],
    }
    position = 32 if is64 else 28
    for _ in range(min(ncmds, 8192)):
        try:
            cmd, cmdsize = struct.unpack_from(end + "II", data, position)
        except Exception:  # noqa: BLE001
            break
        if cmdsize <= 0 or position + cmdsize > len(data):
            break
        if cmd in (0xC, 0x18, 0x1F):          # LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB / reexport
            try:
                name_offset = struct.unpack_from(end + "I", data, position + 8)[0]
                name = data[position + name_offset:position + cmdsize].split(b"\x00")[0].decode("utf-8", "replace")
                if name and name not in out["libraries"]:
                    out["libraries"].append(name)
            except Exception:  # noqa: BLE001
                pass
        elif cmd == 0x1B:                     # LC_UUID
            out["uuid"] = data[position + 8:position + 24].hex()
        elif cmd == 0x32:                     # LC_BUILD_VERSION
            try:
                platform = struct.unpack_from(end + "I", data, position + 8)[0]
                out["platform"] = MACHO_PLATFORMS.get(platform, str(platform))
            except Exception:  # noqa: BLE001
                pass
        elif cmd == 0x1C:                     # LC_RPATH
            try:
                name_offset = struct.unpack_from(end + "I", data, position + 8)[0]
                rpath = data[position + name_offset:position + cmdsize].split(b"\x00")[0].decode("utf-8", "replace")
                if rpath and rpath not in out["rpath"]:
                    out["rpath"].append(rpath)
            except Exception:  # noqa: BLE001
                pass
        position += cmdsize
    out["imports"] = [f"@rpath/{lib.split('/')[-1]}" for lib in out["libraries"]]
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
            name = raw_name
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


# ------------------------------------------------------ crypto evidence ----- #
#: markers strong enough to assert a library from text alone (distinctive tokens)
STRONG_MARKERS: dict[str, tuple[str, ...]] = {
    "BoringSSL": ("BoringSSL", "openSSLIsBoringSSL"),
    "BouncyCastle": ("BouncyCastleProvider", "org/bouncycastle", "org.bouncycastle"),
    "Crypto++": ("CryptoPP", "cryptopp"),
    ".NET cryptography": ("System.Security.Cryptography",),
    "JCA-JCE": ("javax/crypto", "javax.crypto", "java/security/MessageDigest"),
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
                    exports: Iterable[str] = ()) -> dict[str, Any]:
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
        format="binary", imports=import_names, symbols=export_names, strings=strings[:MAX_STRINGS]))
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
            pattern = re.compile(_BOUNDARY.format(token=re.escape(marker + suffix)), re.IGNORECASE)
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
        "wasm": parse_wasm,
    }.get(fmt)
    try:
        if parser is not None:
            parsed = parser(data)
            record.update(parsed)
            record["parsed"] = True
        elif fmt in ("squashfs", "squashfs-be", "jffs2", "jffs2-le", "ubi", "ubifs",
                     "cramfs", "ext", "uimage", "dtb", "gzip", "xz", "zstd", "bzip2",
                     "lzma", "lz4", "ustar", "rpm", "java-class", "raw"):
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
    if fmt == "rpm":
        return ("RPM header identified; the package header is not unpacked — components inside "
                "an RPM are reported by the package-manager inventory, not by this file scan")
    if fmt in FILESYSTEM_FORMATS:
        return ("filesystem image identified; contents are NOT extracted (squashfs/JFFS2/UBIFS "
                "need binwalk). Scan the mounted or extracted tree to inventory its packages")
    if fmt == "java-class":
        return "Java class file identified; the constant pool is not parsed"
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
    record["name"] = path.name
    record["sha256"] = digest
    record["size"] = size
    strings = extract_strings(data)
    record["strings_sampled"] = len(strings)
    crypto = crypto_evidence(data, strings, imports=record.get("imports") or [],
                             exports=record.get("exports") or [])
    record["crypto"] = crypto
    record["findings"] = _binary_findings(record)
    return record


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
    if record.get("packed_or_encrypted"):
        findings.append({
            "code": "BIN-PACKED", "severity": "MEDIUM",
            "title": "packed or encrypted content",
            "detail": (f"entropy {record.get('entropy')} suggests compression/encryption, so "
                       "string-level crypto detection may be incomplete"),
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
        findings.append({
            "code": "BIN-FIRMWARE-NOT-EXTRACTED", "severity": "LOW",
            "title": "filesystem inside the image was not extracted",
            "detail": (f"detected {detected} container(s) inside the image; their contents are NOT "
                       "unpacked by this scanner (that needs binwalk/squashfs-tools), so anything "
                       "inside them is out of scope for this report — inventory the extracted tree "
                       "separately"),
            "path": path, "containers": detected,
        })
    if record.get("format") in ("raw", "rpm", "java-class") or record.get("parsed") is False:
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

    for record in scan.get("binaries") or []:
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

    crypto_libraries = [row for row in libraries]
    algorithms = sorted({algorithm for record in scan.get("binaries") or []
                         for algorithm in (record.get("crypto") or {}).get("algorithms") or []})
    pqc = sorted({marker for record in scan.get("binaries") or []
                  for marker in (record.get("crypto") or {}).get("pqc_markers") or []})
    quantum_vulnerable = sorted({name for record in scan.get("binaries") or []
                                 for name in (record.get("crypto") or {}).get("quantum_vulnerable") or []})
    return {
        "target": scan.get("target"),
        "target_kind": "binary",
        "packages": packages,
        "libraries": crypto_libraries,
        "binaries": [{
            "name": record.get("name"),
            "path": record.get("path"),
            "version": next((lib.get("version") for lib in (record.get("crypto") or {}).get("libraries") or []
                             if lib.get("version")), None),
            "sha256": record.get("sha256"),
            "type": f"{record.get('format')}:{record.get('arch') or 'unknown'}",
            "detection_method": "magic+parser",
            "algorithms": (record.get("crypto") or {}).get("algorithms") or [],
            "libraries": record.get("libraries") or [],
            "size": record.get("size"),
            "stripped": record.get("stripped"),
            "static": record.get("static"),
            "format": record.get("format"),
            "arch": record.get("arch") or record.get("machine"),
        } for record in scan.get("binaries") or []],
        "vulnerabilities": [],
        "manifests": [],
        "manifest_count": 0,
        "dependencies": dependencies,
        "crypto": {"algorithms": algorithms, "pqc_markers": pqc,
                   "quantum_vulnerable": quantum_vulnerable,
                   "libraries": [{"name": row["name"], "version": row.get("version"),
                                  "end_of_life": row.get("deprecated")} for row in libraries]},
        "findings": findings,
        "binaries_scanned": scan.get("binaries_scanned", 0),
        "files_walked": scan.get("files_walked", 0),
        "by_format": scan.get("by_format") or {},
        "by_arch": scan.get("by_arch") or {},
        "limits": scan.get("limits") or {},
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
    for record in scan.get("binaries") or []:
        path = record.get("path") or record.get("name")
        crypto = record.get("crypto") or {}
        for library in crypto.get("libraries") or []:
            name = str(library.get("library"))
            version = library.get("version")
            algorithms = crypto.get("algorithms") or []
            if not algorithms:
                if name in seen_libraries:
                    continue
                seen_libraries.add(name)
                components.append({
                    "type": "cryptographic-asset",
                    "bom-ref": f"cryptoscan:binary/{name}@{version or 'unknown'}",
                    "name": name,
                    "cryptoProperties": {
                        "assetType": "algorithm",
                        "algorithmProperties": {"primitive": "implementation"},
                    },
                    "properties": _asset_properties(name, version, library, path),
                })
                continue
            for algorithm in algorithms:
                key = (name, str(algorithm))
                if key in seen:
                    continue
                seen.add(key)
                vulnerable = any(token.lower() in str(algorithm).lower()
                                 for token in QUANTUM_VULNERABLE_ALGORITHMS)
                properties = _asset_properties(name, version, library, path)
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
                            **( {"nistQuantumSecurityLevel": 0} if vulnerable else {} ),
                        },
                    },
                    "evidence": {"occurrences": [{"location": str(path)}]},
                    "properties": properties,
                })
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
                      path: str) -> list[dict[str, str]]:
    properties = [{"name": "cryptoscan:library", "value": str(library)},
                  {"name": "cryptoscan:found-in", "value": str(path)}]
    if version:
        properties.append({"name": "cryptoscan:library-version", "value": str(version)})
    if library_row.get("evidence_classes"):
        properties.append({"name": "cryptoscan:evidence",
                           "value": ", ".join(library_row["evidence_classes"])})
    if library_row.get("end_of_life"):
        properties.append({"name": "cryptoscan:end-of-life", "value": "true"})
    return properties
