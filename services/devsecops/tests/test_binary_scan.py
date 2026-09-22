"""Binary/firmware scanner: real parsers, graded evidence, honest gaps.

Fixtures are assembled byte by byte (ELF/PE/ar/zip/firmware) so the parsers are
exercised against structures they were written for, not against whatever
happens to be installed on the build machine. Nothing here needs a compiler.
"""
from __future__ import annotations

import struct
import zipfile

import pytest

from devsecops import binary_scan as bs


# --------------------------------------------------------------- builders --- #
def _elf64(*, e_type: int = 3, machine: int = 0x3E, deps=(), soname: str | None = None,
           runpath: str | None = None, comment: bytes | None = None, build_id: bytes | None = None,
           imports=(), exports=(), strings=(), go_section: bytes | None = None) -> bytes:
    """Assemble a real ELF64 with dynamic/symbol/comment/note sections."""
    dynstr = bytearray(b"\x00")
    offsets: dict[str, int] = {}

    def _intern(text: str) -> int:
        if text in offsets:
            return offsets[text]
        offsets[text] = len(dynstr)
        dynstr.extend(text.encode() + b"\x00")
        return offsets[text]

    dynamic: list[tuple[int, int]] = []
    for dep in deps:
        dynamic.append((1, _intern(dep)))
    if soname:
        dynamic.append((14, _intern(soname)))
    if runpath:
        dynamic.append((29, _intern(runpath)))
    dynamic.append((0, 0))

    symtab = bytearray()
    for offset, shndx in ((_intern(name), 0) for name in imports):
        symtab.extend(struct.pack("<IBBHQQ", offset, (1 << 4) | 2, 0, shndx, 0, 0))
    for offset in (_intern(name) for name in exports):
        symtab.extend(struct.pack("<IBBHQQ", offset, (1 << 4) | 2, 0, 1, 0, 0))

    dynamic_bytes = b"".join(struct.pack("<qQ", tag, value) for tag, value in dynamic)
    text = b"\x90" * 16
    sections: list[tuple[str, int, bytes, int, int]] = [
        ("", 0, b"", 0, 0),
        (".text", 1, text, 0, 0),
        (".dynstr", 3, bytes(dynstr), 0, 0),
        (".dynsym", 11, bytes(symtab), 2, 24),          # sh_link -> .dynstr
        (".dynamic", 6, dynamic_bytes, 2, 16),
    ]
    if comment is not None:
        sections.append((".comment", 1, comment, 0, 1))
    if build_id is not None:
        name = b"GNU\x00"
        descriptor = build_id + bytes((4 - len(build_id) % 4) % 4)
        note = struct.pack("<III", len(name), len(build_id), 3) + name + descriptor
        sections.append((".note.gnu.build-id", 7, note, 0, 0))
    if go_section is not None:
        sections.append((".go.buildinfo", 1, go_section, 0, 1))
    # .data before .shstrtab so e_shstrndx stays the last section index
    sections.append((".data", 1, b"".join(s.encode() + b"\x00" for s in strings), 0, 0))
    sections.append((".shstrtab", 3, b"", 0, 0))

    shstr = bytearray(b"\x00")
    name_offsets: list[int] = []
    for name, _type, _data, _link, _entsize in sections:
        if not name:
            name_offsets.append(0)
            continue
        name_offsets.append(len(shstr))
        shstr.extend(name.encode() + b"\x00")
    sections[-1] = (".shstrtab", 3, bytes(shstr), 0, 0)

    body = bytearray()
    layout_offsets: list[int] = []
    cursor = 64
    file_sections: list[tuple[str, int, bytes, int, int, int]] = []
    for name, stype, data, link, entsize in sections:
        layout_offsets.append(cursor if data else 0)
        file_sections.append((name, stype, bytes(data), link, entsize, cursor if data else 0))
        body.extend(data)
        cursor += len(data)
        while cursor % 8:
            body.append(0)
            cursor += 1

    shoff = cursor
    header = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01\x00" + bytes(8), e_type,
                         machine, 1, 0, 0, shoff, 0, 64, 0, 0, 64, len(file_sections), len(file_sections) - 1)
    section_headers = b""
    for index, (name, stype, data, link, entsize, offset) in enumerate(file_sections):
        section_headers += struct.pack("<IIQQQQIIQQ", name_offsets[index], stype, 0, 0, offset,
                                       len(data), link, 0, 0x1000 if index == 1 else 0, entsize)
    return header + bytes(body) + section_headers


def _go_section(module: str, version: str, deps, toolchain: str = "go1.21.5") -> bytes:
    lines = [f"go\t{toolchain}", f"path\t{module}", f"mod\t{module}\t{version}\t"]
    lines += [f"dep\t{path}\t{ver}\th1:deadbeefcafe=" for path, ver in deps]
    blob = ("\n".join(lines) + "\n").encode()
    header = b"\xff\xff\xff\xf1" + toolchain.encode().ljust(18, b"\x00") + bytes([8] + [0] * 9)
    return header + blob + b"\x00\x00"


def _pe(*, machine: int = 0x8664, imports=("KERNEL32.dll",), dotnet: bool = False) -> bytes:
    """Minimal but structurally valid PE32+ with an import directory."""
    optional = 0x98
    section_table = optional + 240
    raw_offset = 0x400
    # allocate the whole file up front: writing past the end of a bytearray with
    # a slice assignment appends instead of padding, which would silently move
    # every RVA target
    data = bytearray(b"\x00" * (raw_offset + 0x200))
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, 0x84, machine, 1, 0x5F5E1000, 0, 0, 240, 0x0022)
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<H", data, optional + 68, 3)                       # console subsystem
    struct.pack_into("<I", data, optional + 108, 16)                     # number of directories
    if dotnet:
        struct.pack_into("<II", data, optional + 112 + 14 * 8, 0x1200, 0x48)   # CLR directory
    struct.pack_into("<II", data, optional + 112 + 1 * 8, 0x1000, 0x28)       # import directory
    data[section_table:section_table + 8] = b".rdata\x00\x00"
    # Name(8) VirtualSize(4) VirtualAddress(4) SizeOfRawData(4) PointerToRawData(4)
    struct.pack_into("<IIII", data, section_table + 8, 0x200, 0x1000, 0x200, raw_offset)
    descriptors = b""
    for offset, dll in enumerate(imports):
        name_rva = 0x1040 + sum(len(item) + 1 for item in imports[:offset])
        descriptors += struct.pack("<IIIII", 0, 0, 0, name_rva, 0x1080)
    descriptors += b"\x00" * 20
    data[raw_offset:raw_offset + len(descriptors)] = descriptors
    blob = b"".join(dll.encode() + b"\x00" for dll in imports)
    data[raw_offset + 0x40:raw_offset + 0x40 + len(blob)] = blob
    return bytes(data)


def _firmware(*, model: str = "FriendlyARM NanoPi R5S",
              compatible=(b"rockchip,rk3568", b"rockchip,rk3568-nanopi-r5s")) -> bytes:
    strings_block = b"\x00".join([b"model", model.encode()] + [b"compatible", *compatible, b""])
    strings_off = 64
    total = strings_off + len(strings_block)
    dtb = (struct.pack(">IIIIIIIIII", 0xD00DFEED, total, strings_off, 0, 0, 0, 0, 0, total - 8, 0)
           + b"\x00" * (strings_off - 40) + strings_block)
    uimage = (struct.pack(">IIIIIII", 0x27051956, 0, 0, len(dtb) + 64, 0, 0, 0x0F)
              + b"Linux-6.1-image\x00".ljust(32, b"\x00") + b"\x00" * 4)
    return uimage + dtb + b"hsqs" + b"\x00" * 40 + b"\x1f\x8b\x08" + b"\x00" * 60


# ------------------------------------------------------------------ tests --- #
def test_identify_uses_magic_not_extension(tmp_path):
    elf = _elf64()
    fake = tmp_path / "not-an-executable.txt"
    fake.write_bytes(elf)
    assert bs.identify(elf, "not-an-executable.txt")["format"] == "elf"
    assert bs.identify(b"#!/bin/sh\necho hi\n", "script.sh")["format"] == "raw"
    # "MZ" alone is not a PE — the PE signature must sit at e_lfanew
    doc = b"MZ" + b"\x00" * 200
    assert bs.identify(doc, "doc.doc")["format"] == "raw"


def test_elf_dynamic_symbols_and_comment():
    elf = _elf64(deps=("libc.so.6", "libssl.so.3"), soname="libtest.so.1",
                 comment=b"GCC: (Ubuntu 13.2.0) 13.2.0\x00",
                 build_id=bytes.fromhex("7d90f38412d00023e58392b03612a24b62fcaede"),
                 imports=("EVP_EncryptInit_ex", "malloc"), exports=("SSL_new", "OPENSSL_init"))
    parsed = bs.parse_elf(elf)
    assert parsed["bits"] == 64 and parsed["arch"] == "x86-64-64"
    assert parsed["type"] == "shared-library" and parsed["stripped"] is True
    assert parsed["libraries"] == ["libc.so.6", "libssl.so.3"]
    assert parsed["soname"] == "libtest.so.1"
    assert parsed["compiler"][0].startswith("GCC:")
    assert parsed["build_id"] == "7d90f38412d00023e58392b03612a24b62fcaede"
    assert parsed["imports"] == ["EVP_EncryptInit_ex", "malloc"]
    assert parsed["exports"] == ["SSL_new", "OPENSSL_init"]
    assert parsed["import_count"] == 2 and parsed["export_count"] == 2


def test_elf_runpath_and_go_buildinfo():
    go = _go_section("github.com/acme/paymentsvc", "v1.4.2",
                     [("github.com/golang-jwt/jwt/v5", "v5.2.0"), ("golang.org/x/crypto", "v0.31.0")])
    elf = _elf64(deps=("libc.so.6",), runpath="/tmp/app/lib", go_section=go)
    parsed = bs.parse_elf(elf)
    assert parsed["rpath"] == ["/tmp/app/lib"]
    assert parsed["go"]["go_version"] == "go1.21.5"
    assert parsed["go"]["module"] == "github.com/acme/paymentsvc"
    assert parsed["go"]["module_version"] == "v1.4.2"
    assert [dep["name"] for dep in parsed["go"]["dependencies"]] == [
        "github.com/golang-jwt/jwt/v5", "golang.org/x/crypto"]

    result = bs.sbom_result({"target": "x", "binaries": [{"name": "paymentsvc", "path": "paymentsvc",
                                                          "sha256": "ab", "format": "elf",
                                                          "arch": "x86-64", "go": parsed["go"],
                                                          "crypto": {}, "findings": []}],
                             "binaries_scanned": 1, "files_walked": 1})
    names = {pkg["name"] for pkg in result["packages"]}
    assert {"github.com/acme/paymentsvc", "github.com/golang-jwt/jwt/v5",
            "golang.org/x/crypto"} <= names
    purls = {pkg.get("purl") for pkg in result["packages"]}
    assert "pkg:golang/golang.org/x/crypto@v0.31.0" in purls
    edges = {(edge["from"], edge["to"]) for edge in result["dependencies"]}
    assert ("paymentsvc", "github.com/acme/paymentsvc") in edges
    assert ("github.com/acme/paymentsvc", "golang.org/x/crypto") in edges


def test_go_buildinfo_absent_section_is_not_invented():
    elf = _elf64(deps=("libc.so.6",))
    assert "go" not in bs.parse_elf(elf)


def test_pe_imports_subsystem_and_dotnet():
    parsed = bs.parse_pe(_pe(imports=("KERNEL32.dll", "CRYPT32.dll")))
    assert parsed["machine"] == "x86-64" and parsed["bits"] == 64
    assert parsed["subsystem"] == "console"
    assert parsed["libraries"] == ["KERNEL32.dll", "CRYPT32.dll"]
    assert parsed["sections"] == [".rdata"]
    assert bs.parse_pe(_pe(dotnet=True)).get("dotnet") is True


def test_ar_resolves_gnu_long_names(tmp_path):
    long_name = b"a-very-long-member-name-that-needs-the-table.o/\n"

    def _member(name: bytes, payload: bytes) -> bytes:
        header = (name.ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6)
                  + b"100644".ljust(8) + str(len(payload)).ljust(10).encode() + b"`\n")
        assert len(header) == 60, len(header)
        return header + payload

    archive = (b"!<arch>\n"
               + _member(b"/", b"")                      # symbol index table
               + _member(b"//", long_name)               # GNU long-name table
               + _member(b"/0", b"\x90" * 8))
    parsed = bs.parse_ar(archive)
    assert parsed["type"] == "static-library"
    assert parsed["symbol_table_entries"] == 1
    assert [m["name"] for m in parsed["members"]] == ["a-very-long-member-name-that-needs-the-table.o"]


@pytest.mark.parametrize("name", ["demo-1.2.3-py3-none-any.whl", "lib.jar"])
def test_zip_metadata_for_wheel_and_jar(tmp_path, name):
    path = tmp_path / name
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        if name.endswith(".whl"):
            archive.writestr("demo-1.2.3.dist-info/METADATA",
                             "Name: demo\nVersion: 1.2.3\nLicense: MIT\nRequires-Dist: cryptography\n")
        else:
            archive.writestr("META-INF/maven/org.acme/demo/pom.properties",
                             "groupId=org.acme\nartifactId=demo\nversion=9.1\n")
            archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nImplementation-Version: 9.1\n")
            archive.writestr("org/acme/Demo.class", "not-a-real-class")
            archive.writestr("org/bouncycastle/jce/Provider.class", "x")
    parsed = bs.parse_zip(path.read_bytes(), path.name)
    if name.endswith(".whl"):
        assert parsed["type"] == "python-wheel"
        assert parsed["python"]["name"] == "demo" and parsed["python"]["version"] == "1.2.3"
        assert parsed["python"]["license"] == "MIT"
    else:
        assert parsed["type"] == "java-archive"
        assert parsed["java"]["artifact"] == "demo" and parsed["java"]["group"] == "org.acme"
        assert parsed["java"]["version"] == "9.1"
        assert parsed["java"]["class_count"] == 2
        assert "BouncyCastle" in parsed["libraries"]


def test_firmware_chain_and_device_tree_identity(tmp_path):
    path = tmp_path / "fw.img"
    path.write_bytes(_firmware())
    record = bs.scan_file(path)
    formats = [row["format"] for row in record["containers"]]
    assert formats[:4] == ["uimage", "dtb", "squashfs", "gzip"]
    assert record["device_tree"]["model"] == "FriendlyARM NanoPi R5S"
    assert "rockchip,rk3568" in record["device_tree"]["compatible"]
    assert record["embedded_filesystems"][0]["format"] == "squashfs"
    codes = {finding["code"] for finding in record["findings"]}
    assert "BIN-FIRMWARE-NOT-EXTRACTED" in codes
    note = next(finding["detail"] for finding in record["findings"]
                if finding["code"] == "BIN-FIRMWARE-NOT-EXTRACTED")
    assert "NOT" in note and "binwalk" in note


def test_crypto_evidence_grades_and_does_not_invent(tmp_path):
    """A symbol table full of lookalikes must not produce library claims."""
    elf = _elf64(deps=("libcrypto.so.3",),
                 imports=("EVP_sha224", "EVP_aes_128_cbc_hmac_sha256", "EVP_sha256",
                          "aes_128_gcm_init"), exports=("ossl_der_oid_id_slh_dsa_sha2_192f",),
                 strings=("OpenSSL 3.0.20 7 Apr 2026", "string::new", "something::ring::aead"))
    path = tmp_path / "libcrypto.so.3"
    path.write_bytes(elf)
    record = bs.scan_file(path)
    libraries = {row["library"]: row for row in record["crypto"]["libraries"]}
    assert libraries["OpenSSL"]["version"] == "3.0.20"
    assert "RustCrypto" not in libraries
    suppressed = {row["library"] for row in record["crypto"]["suppressed_libraries"]}
    assert "RustCrypto" in suppressed
    assert any("single lexical hit" in row["reason"] or "substring" in row["reason"]
               for row in record["crypto"]["suppressed_libraries"])
    # counts as evidence that crypto exists, without claiming a specific library
    reasons = {finding["code"] for finding in record["findings"]}
    assert "BIN-CRYPTO-NO-VERSION" not in reasons


def test_weak_primitive_and_quantum_findings(tmp_path):
    elf = _elf64(deps=("libcrypto.so.3",), exports=("RSA_sign", "MD5Init", "EVP_md5", "EVP_sha1"))
    path = tmp_path / "libweak.so"
    path.write_bytes(elf)
    record = bs.scan_file(path)
    codes = {finding["code"]: finding for finding in record["findings"]}
    assert codes["BIN-WEAK-PRIMITIVE-PRESENT"]["severity"] == "HIGH"
    assert "MD5" in codes["BIN-WEAK-PRIMITIVE-PRESENT"]["detail"]
    assert codes["BIN-QUANTUM-VULNERABLE"]["severity"] == "MEDIUM"
    assert "RSA" in codes["BIN-QUANTUM-VULNERABLE"]["algorithms"]


def test_pqc_and_ecc_are_classified_separately(tmp_path):
    """X25519 is classical ECC: it accelerates migration, it is not post-quantum."""
    path = tmp_path / "node"
    path.write_bytes(_elf64(exports=("x25519_keygen", "ml_kem_encapsulate", "ml_dsa_verify")))
    record = bs.scan_file(path)
    crypto = record["crypto"]
    assert "ml_kem" in crypto["pqc_markers"] and "ml_dsa" in crypto["pqc_markers"]
    assert "X25519" in crypto["ecc_markers"] or "x25519" in crypto["ecc_markers"]
    assert "X25519" not in crypto["pqc_markers"]
    # a binary that has both must say so rather than reading as fully migrated
    detail = next(finding["detail"] for finding in record["findings"]
                  if finding["code"] == "BIN-PQC-CAPABLE")
    assert "ALSO references classical primitives" in detail


def test_static_binary_without_deps_is_reported_as_static(tmp_path):
    elf = bytearray(_elf64())
    struct.pack_into("<H", elf, 16, 2)          # ET_EXEC
    struct.pack_into("<H", elf, 18, 0x28)       # ARM
    path = tmp_path / "statically-linked"
    path.write_bytes(bytes(elf))
    parsed = bs.parse_elf(bytes(elf))
    assert parsed["machine"] == "ARM"
    record = bs.scan_file(path)
    assert record["arch"].startswith("ARM")


def test_scan_path_walks_parses_and_respects_caps(tmp_path):
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "libdemo.so").write_bytes(_elf64(deps=("libc.so.6",),
                                                            strings=("OpenSSL 1.1.1w 11 Sep 2023",)))
    (tmp_path / "plain.txt").write_text("nothing to see")
    (tmp_path / "app.bin").write_bytes(_firmware())
    scan = bs.scan_path(tmp_path)
    assert scan["binaries_scanned"] == 2
    assert scan["by_format"]["elf"] == 1 and scan["by_format"]["uimage"] == 1
    paths = {record["path"] for record in scan["binaries"]}
    assert "nested/libdemo.so" in paths and "app.bin" in paths
    assert scan["limits"]["truncated"] is False

    capped = bs.scan_path(tmp_path, max_binaries=1)
    assert capped["binaries_scanned"] == 1 and capped["limits"]["truncated"] is True


def test_raw_files_need_crypto_evidence_to_be_reported(tmp_path):
    journal = tmp_path / "image.dd"
    journal.write_bytes(b"\x00" * 64 + b"nothing here" + b"\x00" * 64)
    assert bs.scan_file(journal) is None
    journal.write_bytes(b"\x00" * 64 + b"Linked against libcrypto.so.3 (OpenSSL 3.0.20 7 Apr 2026)"
                        + b"\x00" * 64)
    record = bs.scan_file(journal)
    assert record is not None and record["format"] == "raw"
    assert record["parse_note"] and "string-level evidence" in record["parse_note"]
    assert any(finding["code"] == "BIN-NOT-PARSED" for finding in record["findings"])


def test_unparsed_containers_state_their_limit(tmp_path):
    rpm = tmp_path / "pkg.rpm"
    rpm.write_bytes(b"\xed\xab\xee\xdb" + b"\x00" * 200)
    record = bs.scan_file(rpm)
    assert record["format"] == "rpm" and record["parsed"] is False
    assert "not unpacked" in record["parse_note"]
    cls = tmp_path / "Demo.class"
    cls.write_bytes(b"\xca\xfe\xba\xbe" + b"\x00\x00\x00\x3d" + b"\x00" * 100)
    class_record = bs.scan_file(cls)
    assert class_record["format"] == "java-class"
    assert any(finding["code"] == "BIN-NOT-PARSED" for finding in class_record["findings"])


def test_strings_and_entropy_are_bounded():
    blob = b"\x01\x02" + b"A" * 40 + b"\x00" + b"B" * 12 + b"\xff" * 4
    strings = bs.extract_strings(blob, min_len=6)
    assert strings == ["A" * 40, "B" * 12]
    assert bs.extract_strings(b"C" * 100, limit=3) == ["C" * 100]
    assert bs.entropy(b"\x00" * 1000) == 0.0
    assert 7.9 < bs.entropy(bytes(range(256)) * 4) <= 8.0


def test_version_and_eol_helpers():
    assert bs.version_tuple("3.0.20") == (3, 0, 20)
    assert bs.version_tuple("no-version") == ()
    assert bs.is_end_of_life("OpenSSL", "1.1.1w") is True
    assert bs.is_end_of_life("OpenSSL", "3.0.20") is False
    assert bs.is_end_of_life("Node.js", "22.22.3") is False
    assert bs.is_end_of_life("Unknown", "1.0.0") is False      # never guessed
    assert bs.is_end_of_life("OpenSSL", None) is False


def test_cbom_document_is_ingestible(tmp_path):
    from cbom.inventory import is_crypto_component, records_from_bom, validate_document

    path = tmp_path / "libcrypto.so.3"
    path.write_bytes(_elf64(deps=("libc.so.6",),
                            exports=("EVP_EncryptInit_ex", "RSA_sign", "EVP_sha256"),
                            strings=("OpenSSL 3.0.20 7 Apr 2026", "ML-KEM-768")))
    scan = bs.scan_path(tmp_path)
    document = bs.cbom_document(scan, target="host crypto", created_by="tester")
    assert document["bomFormat"] == "CycloneDX" and document["specVersion"] == "1.5"
    assert document["metadata"]["component"]["name"] == "host crypto"
    assert validate_document(document)["ok"] is True
    assert all(is_crypto_component(component) for component in document["components"])
    records = records_from_bom(document)
    assert records, "CBOM must yield crypto inventory records"
    by_name = {record["name"]: record for record in records}
    assert "RSA" in by_name and by_name["RSA"]["algorithm"] == "RSA"
    rsa = next(c for c in document["components"] if c["name"] == "RSA")
    assert rsa["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 0
    aes = next((c for c in document["components"] if c["name"].startswith("AES")), None)
    if aes is not None:
        assert "nistQuantumSecurityLevel" not in aes["cryptoProperties"]["algorithmProperties"]
    pqc = next(c for c in document["components"] if c["name"] == "ML-KEM-768")
    assert pqc["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 3
    assert any(prop["name"] == "cryptoscan:found-in" for prop in pqc["properties"])


def test_sbom_adapter_feeds_the_standard_renderer(tmp_path):
    from container_scanner.reports.sbom import build_sbom
    from devsecops import sbom_scan

    path = tmp_path / "libcrypto.so.3"
    path.write_bytes(_elf64(deps=("libc.so.6",), exports=("EVP_EncryptInit_ex",),
                            strings=("OpenSSL 3.0.20 7 Apr 2026",)))
    result = bs.sbom_result(bs.scan_path(tmp_path))
    bom = sbom_scan.enrich_bom(build_sbom(result), result, created_by="tester")
    names = {component["name"] for component in bom["components"]}
    assert "OpenSSL" in names and "libcrypto.so.3" in names
    openssl = next(c for c in bom["components"] if c["name"] == "OpenSSL")
    assert openssl["version"] == "3.0.20"
    assert openssl["properties"] and any(p["name"] == "cryptoscan:crypto-library"
                                         for p in openssl["properties"])
    binary = next(c for c in bom["components"] if c["name"] == "libcrypto.so.3")
    assert binary["bom-ref"] == "cryptoscan:binary/libcrypto.so.3"
    assert binary["hashes"][0]["alg"] == "SHA-256"
    assert bom["metadata"]["authors"] == [{"name": "tester"}]


def test_sbom_adapter_keeps_scan_metadata_visible(tmp_path):
    (tmp_path / "app.bin").write_bytes(_firmware())
    result = bs.sbom_result(bs.scan_path(tmp_path))
    assert result["target_kind"] == "binary"
    assert result["binaries_scanned"] == 1
    assert result["by_format"] == {"uimage": 1}
    assert any(finding["code"] == "BIN-FIRMWARE-NOT-EXTRACTED" for finding in result["findings"])
    assert result["vulnerabilities"] == []          # never invented without a feed


def test_documented_gaps_are_stated_not_hidden():
    """The module must say what it does not do — the docstring is the contract."""
    text = bs.__doc__ or ""
    assert "does **not** unpack squashfs" in text
    assert "identified-but-not-parsed" in text
    assert "graded" in text


def test_diff_does_not_confuse_a_binary_with_a_library(tmp_path):
    """A binary named `openssl` and the `OpenSSL` library are two components.

    Keying a diff on the component name alone would report one of them and hide
    the other, so a re-scan could look unchanged while a binary appeared.
    """
    from devsecops.sbom_assurance import diff_boms
    from container_scanner.reports.sbom import build_sbom
    from devsecops import sbom_scan

    directory = tmp_path / "bin"
    directory.mkdir()
    (directory / "libcrypto.so.3").write_bytes(
        _elf64(exports=("EVP_EncryptInit_ex",), strings=("OpenSSL 3.0.20 7 Apr 2026",)))
    before = sbom_scan.enrich_bom(build_sbom(bs.sbom_result(bs.scan_path(directory))),
                                  bs.sbom_result(bs.scan_path(directory)))
    (directory / "openssl").write_bytes(
        _elf64(exports=("EVP_EncryptInit_ex",), strings=("OpenSSL 3.0.20 7 Apr 2026",)))
    # the same scan result drives both sides, so the collision is what changes
    after = sbom_scan.enrich_bom(build_sbom(bs.sbom_result(bs.scan_path(directory))),
                                 bs.sbom_result(bs.scan_path(directory)))
    report = diff_boms(before, after)
    names = {row["name"] for row in report["added"]}
    assert "openssl" in names, report
    assert report["summary"]["added"] >= 1
    # the versioned library is still tracked by name, so upgrades stay upgrades
    assert all(row["ref"] for row in report["added"])


def test_diff_still_detects_an_upgrade_by_name():
    from devsecops.sbom_assurance import diff_boms

    def _bom(version, ref):
        return {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
            {"type": "library", "name": "requests", "version": version, "bom-ref": ref}]}

    report = diff_boms(_bom("2.31.0", "pkg:pypi/requests@2.31.0"),
                       _bom("2.32.0", "pkg:pypi/requests@2.32.0"))
    assert report["verdict"] == "UPDATED"
    assert [(c["name"], c["direction"]) for c in report["changed"]] == [("requests", "upgrade")]
