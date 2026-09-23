# Binary & firmware scanning — what is parsed, what is proven, what is refused

This guide covers scanning **executables, shared libraries, archives and firmware
images** for cryptographic content, and carrying the result through the SBOM/CBOM
pipeline. Everything here runs offline and deterministically: no unpacking, no
AI inference, no "looks like OpenSSL" without the evidence that produced it.

## 1. Run it

```bash
# API — operators only (admin / superadmin / security_analyst / auditor)
curl -sX POST https://host/api/v1/devsecops/binary/scan \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"target":"/opt/app","recursive":true,"ingest_cbom":true,"system_name":"payments-prod"}'
```

```bash
# or through the general scan endpoint, which gives you rescan/diff for free
curl -sX POST https://host/api/v1/devsecops/sbom/scan \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"kind":"binary","target":"/opt/app","format":"cyclonedx"}'
```

Console: **DevSecOps → Binaries** — path, format, feed, then *Scan binaries*.
The result shows formats/architectures, crypto implementations, graded findings,
and the SBOM/CBOM documents; the artifact id works on the SBOM tab for gate,
licence, VEX, diff and rescan.

`GET /api/v1/devsecops/binary/artifacts/{artifact_id}/cbom` returns the CBOM that
was stored with the scan.

## 2. What is actually parsed

| Format | Depth |
|---|---|
| ELF (32/64, LE/BE) | type (exec/PIE/shared/core), machine, `DT_NEEDED` libraries, `RPATH`/`RUNPATH`, `DT_SONAME`, `.note.gnu.build-id`, `.comment` compiler string, dynamic symbols split into imports/exports, stripped/static detection, **Go build info** (toolchain + module graph with exact versions and sums), **program headers** (segment list, `PT_INTERP` interpreter, `PT_GNU_STACK` executable-stack flag), **`.gnu.version_r` symbol-version floors** (e.g. `libcrypto.so.3` requires `OPENSSL_3.0.3`), **`.note.gnu.property`** CPU features (CET IBT/SHSTK), **hardening flags** (PIE, NX, RELRO, full RELRO/BIND_NOW, stack canary, `_FORTIFY_SOURCE`), **crypto constant tables** (known AES/SHA/MD5/ChaCha20 tables located in `.rodata`/`.text`/`.data` → `CONSTANT_MATCH` 0.9) |
| PE (PE32/PE32+) | machine, subsystem (incl. UEFI runtime/boot → `type: efi-image`), COFF timestamp, sections, **mitigations from `DllCharacteristics`** (ASLR/DYNAMIC_BASE, high-entropy VA, DEP/NX_COMPAT, SEH, isolation, CFG, force-integrity) and **`IMAGE_LOAD_CONFIG_DIRECTORY`** (SecurityCookie ⇒ `/GS` is really initialised, SafeSEH table, `GuardFlags` ⇒ CFG is instrumented, not merely declared), imported DLLs resolved through the section table, **delay-load imports**, **`RT_VERSION` resources** (StringFileInfo: company/product/file version/original filename, `VS_FIXEDFILEINFO`, translation table), **debug directory** (CodeView `RSDS` PDB path, GUID, age), **Authenticode presence** (entries, size, PKCS#7 — validity and chain are explicitly *not* verified), **CLR/`.NET` metadata** (BSJB → framework version), **Rich header** (linker product/build pairs — attribution evidence only) |
| Mach-O (thin + fat) | CPU type/subtype, file type, `LC_UUID`, platform + minimum OS + SDK (`LC_BUILD_VERSION` / `LC_VERSION_MIN_*`), **linked dylibs with their current/compatibility versions** (`LC_LOAD_DYLIB`/weak/reexport/lazy), `install_name`, `LC_RPATH`, section list, **symbol table split into imports/exports** via `LC_DYSYMTAB` (dyld's leading `_` is stripped so the C name keys the crypto tables), **code signature**: signing identifier, team id, hash type, flags (hardened runtime, library validation, ad-hoc), **entitlements** (with the notable ones called out), **encryption** (`LC_ENCRYPTION_INFO*` cryptid → the file's strings and symbols are not readable) |
| `ar` / `.deb` | members incl. GNU long-name table, symbol-index presence, **Debian `control` file** (package, version, architecture, maintainer, section, homepage, `Depends`) |
| zip (`.jar`/`.war`/`.whl`/`.nupkg`/`.apk`) | entry list, Maven coordinates from `pom.properties`, `MANIFEST.MF` version/main-class, Python `dist-info/METADATA` (name/version/licence/requires), native extensions |
| **Java class** | constant pool: referenced classes (`javax/crypto/Cipher`, `org/bouncycastle/…`), method names, transformation strings (`AES/GCM/NoPadding`), class file version; a truncated pool says where the walk stopped |
| **RPM** | lead + **signature header** + main header: whether the package is **signed** (RSA/DSA/PGP/GPG tags) and which digests it carries (sha256/sha1/md5, read as raw bytes and reported as hex — a digest tag is integrity metadata, not a signature), name, version, release, licence, vendor, architecture, `PROVIDES`/`REQUIRES` package names (the crypto sonames a package depends on), payload digest algorithm, payload compressor and payload offset |
| WASM | import and export names (where crypto markers live) |
| Firmware | **uImage (legacy U-Boot) header decoded**: image name, OS, architecture, image type (kernel/ramdisk/filesystem/firmware/…), compression, load/entry addresses, payload size, build date — and **both CRCs verified** (header CRC over the header with its own field zeroed; payload CRC when present and the image is within the 64 MiB verification cap, with `data_crc_checked: false` and a reason when it is not). A mismatch or a truncated payload is a finding (`BIN-UIMAGE-CRC`, `BIN-UIMAGE-PAYLOAD`). Also: container chain with offsets (device-tree, squashfs, JFFS2, UBIFS, cramfs, gzip/xz/zstd/bzip2/lzma/lz4, tar), device-tree `model` + `compatible` identity, Shannon entropy / packed-content signal, **cpio/initramfs member listing** |
| Raw blobs | reported only when they carry crypto evidence — never as an unnameable "binary" |

### 2.1 Containers are followed, inside a budget

Compression and archive formats are actually opened, one member at a time:

| Container | What happens |
|---|---|
| gzip, xz/lzma, bzip2 | decompressed with a hard output cap, then identified again (tar/cpio get their member list) |
| tar, cpio (initramfs) | members listed; members that are themselves a parseable format are parsed. A **bare** `.cpio`/`initramfs` (newc/crc magic at offset 0, not wrapped in gzip) is identified and opened the same way; the old ASCII `odc` format is identified and refused with the reason |
| zip, `ar`/`.deb` | members listed; the Debian `control` file becomes the package identity, and a detached package signature (`_gpgorigin`/`_gpgbuilder` member) is reported when present |
| RPM | payload decompressed and the cpio member list read; parseable members are parsed |
| zstd, lz4, squashfs/JFFS2/UBIFS/cramfs/ext | **refused with the reason** (`BIN-CONTAINER-REFUSED`) — there is no stdlib decoder for zstd/lz4, and filesystem images need external tooling |

Anything found inside a container keeps its provenance: the path is
`<container>!<member>` (`firmware.bin@0x1f0000!lib/libcrypto.so.3` when the stream
sat at an offset), `derived_from` names the container, and `depth` records how
deep the chain went. Parsed members become components in the SBOM and assets in
the CBOM with `cryptoscan:derived-from` / `cryptoscan:depth` properties — an
implementation inside an image is never presented as a loose file at the top
level.

## 3. Evidence, not assertions

Crypto detection is graded, and every claim keeps the evidence that produced it:

```
STRING_MATCH 0.4  <  SYMBOL_MATCH 0.7  <  IMPORT_MATCH 0.8  <  CONSTANT_MATCH 0.9  <  FINGERPRINT 1.0
```

One deliberate exception sits next to those levels: **platform crypto APIs**. A call
to `CC_SHA256` (Apple CommonCrypto), `BCryptGenRandom` (Windows CNG),
`SecKeyEncrypt` (Apple Security.framework), `getrandom`, `SSLCreateContext` or
`AES_set_encrypt_key` names the primitive directly, so it is reported at
`IMPORT`/`SYMBOL` level with the symbol as its source. Constructors that say only
*that* a cipher is used — `CCCryptorCreate`, `BCryptEncrypt`,
`EVP_CIPHER_CTX_new`, `BCryptOpenAlgorithmProvider` — are reported as library
markers and are **never** promoted to an algorithm: an ambiguous constructor is
not evidence of AES.

* **Versions** come from banners read out of the file itself (`OpenSSL 3.0.20 …`),
  not from a filename.
* **Library claims need real evidence.** A loose substring is not evidence: the
  shared fingerprint table would report `RustCrypto` in OpenSSL because an
  OpenSSL symbol contains `sha2`, and `ring::` inside `string::`. This scanner
  re-verifies weak single-marker claims on identifier boundaries, requires either
  a qualified module/symbol path (`rustls::`, `sha2/`) or two independent
  markers, and **lists what it dropped** in `suppressed_libraries` with the
  reason.
* **PQC vs classical ECC is kept separate.** `ML-KEM-768`, `ml_dsa`, `slh_dsa`
  are post-quantum and reported in full. `X25519`/`Ed25519` are classical
  elliptic-curve crypto — excellent today, broken by Shor tomorrow — so they are
  counted as migration candidates (`BIN-ECC-NO-PQC`), never as PQC.
* **Weak primitives** are matched on token boundaries against detected
  algorithms, so `ACCESS_DESCRIPTION_new` is not reported as DES.

* **String-layer evidence is labelled as such.** Transformation strings
  (`AES/GCM/NoPadding`, `TLS_AES_256_GCM_SHA384`, `HMAC-SHA256`) and Java
  constant-pool entries are reported at the `STRING` level (0.4) with the matched
  text as the source — enough to look, never enough to claim a dependency.

### 3.1 Embedded key material

A key inside a shipped binary is the most direct way a build leaks a secret, so
the key itself is searched for byte-first — not only through the symbols and
strings a format exposes. The DER/ASN.1 reader is hand-rolled (no third-party
crypto dependency), so it works on containers the scanner refuses to unpack, on
stripped binaries, and on a raw blob.

What is recognised, and what is reported about it:

* **PEM armour** for every key/certificate/request label, including the legacy
  `Proc-Type: 4,ENCRYPTED` + `DEK-Info` form (header ignored, `encrypted: true`).
* **DER structures**, classified by their real inner layout rather than by the
  file that contained them: RSA `PKCS#1`, `PKCS#8` (plain, and the encrypted
  `PBES2` wrapper, which is identified and **not** decrypted), SEC1 EC keys,
  `SubjectPublicKeyInfo`, X.509 v1/v3 certificates, PKCS#10 requests,
  PKCS#7/CMS containers, PKCS#12 bundles, ML-KEM/ML-DSA via OID.
* **Non-PEM containers**: OpenSSH `openssh-key-v1` (cipher, KDF, KDF rounds,
  note that the private section was not read), PuTTY key files, OpenPGP
  packets with their armour CRC-24 verified or reported as unverified, JKS/JCEKS
  keystores with aliases, entry types and the certificate inside each trusted
  entry, and `ssh-*`/`ecdsa-sha2-*` host keys.
* **Encoded copies**: a base64 or hex blob that decodes to a key structure is
  found wherever it sits — including inside a filesystem image the scanner does
  not unpack.

Certificates are read for their public facts: version, serial, subject, issuer,
validity window, signature algorithm, key type and curve, `self_signed`,
`basicConstraints CA`, `keyUsage`, `extendedKeyUsage` and SANs. For every key
the report carries kind, type, size, curve, detector, encryption state,
`material_sha256`, byte length, offset(s) and occurrence count — **never the key
material itself**, not even a fragment of it.

* `BIN-EMBEDDED-PRIVATE-KEY` — **CRITICAL** when the key is unencrypted (a
  plaintext secret shipped to every customer), HIGH when it is passphrase- or
  container-encrypted. The detail says what to do: rotate, remove from source,
  keep the key in a KMS/HSM.
* `BIN-EMBEDDED-KEYSTORE` — HIGH when the store holds private keys (a JKS is
  protected by its store password alone, which the detail states), otherwise
  MEDIUM for a trust store.
* `BIN-EMBEDDED-CERTIFICATE` — MEDIUM, and explicitly *not* a verification: the
  finding says the certificate was not chain-validated, not revoked-checked and
  not treated as an anchor.
* `BIN-EMBEDDED-TEST-KEY` — INFO for a key the surrounding bytes call a sample,
  an example key, a placeholder or "do not use". These are inventoried and
  counted, but they do not raise a false alarm.

Keys that are structurally identical in wording are one row: the same material
found twice (once loose, once in an archive) is reported once with both offsets
and both locations.

Finding codes: `BIN-EOL-CRYPTO`, `BIN-CRYPTO-NO-VERSION`,
`BIN-WEAK-PRIMITIVE-PRESENT`, `BIN-WEAK-PRIMITIVE-CLASS`,
`BIN-QUANTUM-VULNERABLE`, `BIN-PQC-CAPABLE`, `BIN-ECC-NO-PQC`,
`BIN-CRYPTO-VERSION-FLOOR`, `BIN-PACKED`, `BIN-HIGH-ENTROPY`,
`BIN-STATIC-CRYPTO`, `BIN-RPATH-WRITABLE`, `BIN-EXECUTABLE-STACK`,
`BIN-NO-RELRO`, `BIN-PARTIAL-RELRO`, `BIN-NO-STACK-CANARY`,
`BIN-UNSIGNED-PE`, `BIN-UNSIGNED-MACHO`, `BIN-ENTITLEMENT` (notable
entitlements such as `get-task-allow`, `allow-unsigned-executable-memory`,
`disable-library-validation`), `BIN-NO-HARDENED-RUNTIME`, `BIN-ENCRYPTED`
(Mach-O `cryptid` — the file is encrypted, so string/symbol evidence for it is
structurally incomplete), `BIN-DELAYED-IMPORT` (a delay-loaded DLL still loads
and still runs), `BIN-EMBEDDED-CRYPTO`, `BIN-CONTAINER-FOLLOWED`,
`BIN-CONTAINER-REFUSED`, `BIN-NOT-PARSED`, `BIN-PARTIAL-PARSE`,
`BIN-UIMAGE-CRC` (header checksum mismatch — the image was modified or damaged),
`BIN-UIMAGE-PAYLOAD` (payload checksum mismatch or truncation),
`BIN-NO-ASLR` (PE without `DYNAMIC_BASE` — stable addresses across runs),
`BIN-NO-DEP` (PE without `NX_COMPAT`), `BIN-NO-CFG` (not compiled with Control
Flow Guard, or CFG declared but not instrumented),
`BIN-RPM-UNSIGNED` (the RPM signature header has no RSA/DSA/PGP entry),
`BIN-DEB-UNSIGNED` (no `_gpgorigin` member),
`BIN-EMBEDDED-PRIVATE-KEY`, `BIN-EMBEDDED-KEYSTORE`,
`BIN-EMBEDDED-CERTIFICATE`, `BIN-EMBEDDED-TEST-KEY`,
`BIN-FIRMWARE-NOT-EXTRACTED`.

## 4. What flows onward

* **SBOM (CycloneDX 1.5 / SPDX 2.3)** — every parsed binary is a component
  (`cryptoscan:binary/<path>`, sha256, `cryptoscan:binary-type`,
  `cryptoscan:detection`); every crypto implementation found is a component too
  (`pkg:generic/OpenSSL@3.0.20`, with `cryptoscan:crypto-library`, vendor and
  algorithms); Go binaries contribute their module graph as components **and**
  dependency edges (binary → main module → dependencies).
* **CBOM (CycloneDX 1.5)** — one `cryptographic-asset` per (library, algorithm)
  with `algorithmProperties.primitive`, `nistQuantumSecurityLevel: 0` on
  quantum-vulnerable algorithms (absent when it does not apply), `evidence.occurrences`
  pointing at the file, and `cryptoscan:*` properties. Validated and ingested
  through the same path as `POST /cbom/ingest`; `ingest_cbom: true` marks the
  assets in the crypto inventory under `system_name`. Key material is inventoried
  under `assetType: related-crypto-material` (type, size, `securedBy`, test
  vectors as `seed`) and certificates under `assetType: certificate` (subject,
  issuer, validity window); a key is identified by
  `cryptoscan:material-sha256` — the material itself is not in the document, and
  the same key shipped in two binaries is one asset with two locations.
  `manifest.binary_summary.key_material` counts what was found
  (`private_keys`, `unencrypted_private_keys`, `certificates`, `keystores`,
  `test_vectors`, `artefacts_with_keys`).
* **Gate / licence / VEX / diff** — the artifact is a normal SBOM artefact, so
  `POST /sbom/{id}/gate`, `/sbom/license`, `/sbom/vex`, `/sbom/{id}/rescan` and
  the Diff tab all work. Feed rows for binary-detected implementations match on
  ecosystem `generic`.
* **Rescan** re-walks the same target with the recorded options. A component
  diff keys on name **and** reference, so a binary called `openssl` and the
  `OpenSSL` library it contains are tracked separately.

## 5. Limits, stated up front

* **Firmware filesystems are not extracted.** squashfs/JFFS2/UBIFS/cramfs are
  identified with offsets; their contents are out of scope for this scanner
  (binwalk/squashfs-tools territory) and every such image carries
  `BIN-FIRMWARE-NOT-EXTRACTED`. What *can* be opened (a gzip/xz stream or a cpio
  initramfs in the same image) is followed and reported alongside. To inventory
  what is inside a filesystem, scan the mounted or extracted tree.
* **A mitigation flag is not the same as a live mitigation.** `DllCharacteristics`
  says what the image was *built* for; the load config says whether the security
  cookie is initialised and CFG is instrumented. Both are reported, and the
  finding only fires on the weaker of the two statements.
* **Package signatures are read from the file, with their real meaning.** An RPM
  with no RSA/DSA/PGP entry in its signature header is reported
  (`BIN-RPM-UNSIGNED`, MEDIUM): anyone who can write the artefact can rewrite its
  contents. A digest tag (sha256/sha1/md5) is reported as integrity metadata and
  explicitly **not** counted as a signature. A `.deb` without a `_gpgorigin`
  member is reported as `BIN-DEB-UNSIGNED` at LOW, because `.deb` signatures
  normally live in the repository metadata (`Release`/`InRelease`) rather than in
  the package — the finding says so instead of implying tampering.
* **A uImage checksum is verified, not assumed.** When a CRC is present it is
  computed and reported (`header_crc_verified`, `data_crc_verified`); a payload
  CRC over the 64 MiB verification cap is reported as *not checked* with the
  reason rather than as valid.
* **zstd and lz4 are refused, not guessed.** There is no zstd/lz4 decoder in the
  standard library, so those containers are reported with the reason; nothing is
  claimed about their contents.
* **Signatures are reported, never trusted.** For PE this is Authenticode
  presence (entries, size, revision); for Mach-O it is the code signature's
  identifier, team id, hash type and entitlements. No chain, revocation,
  notarisation or trust decision is made, and `signature.note` says so in the
  output. An entitlement is evidence about what the binary *may* do, not proof of
  what it does.
* **Symbol-version floors are floors, not versions.** `libcrypto.so.3 →
  OPENSSL_3.0.3` means the binary needs at least that ABI; CVEs are matched
  against banners read from the file, and the floor finding states the limit.
  A `SONAME` in `REQUIRES` (RPM) is a dependency name, not a version.
* **Packed binaries are labelled, not unpacked.** A recognised packer (UPX,
  ASPack, MPRESS, Themida, VMProtect, Enigma, PECompact, Petite, PyInstaller,
  Electron/asar) yields `BIN-PACKED` and a warning that string-level detection is
  structurally incomplete for that file.
* **A container member that is not a format this scanner knows is listed, not
  parsed.** The member list is the honest statement: the file's name and size were
  read, its contents were not interpreted.
* **Name matching still exists for container images** (`container_scanner`
  `_discover_binaries`) as a cheap pre-filter; the deep parser is this scanner.
* **Caps, on purpose**: 512 MiB per file, 4 000 files walked, 750 binaries parsed,
  6 000 strings sampled, firmware container search bounded to the first 128 MiB,
  and the extraction budget: 64 MiB decompressed per level, depth 2, 60 members
  listed per container, 16 MiB per member, 400 RPM header entries, 96 MiB scanned
  for crypto constant tables. Every one of these is reported in
  `summary.extraction_limits`, and a truncated walk is flagged in the manifest
  (`binary_summary.truncated`) — never silently reported as a complete scan.
* **A raw blob is only reported when it carries crypto evidence** (version banner,
  library marker, **or key material**); otherwise it is skipped rather than
  listed as an unnameable "binary". A key found inside a container is never
  dropped for being in an unparsed member.
* **Encrypted key material is reported, never cracked.** An encrypted PKCS#8,
  a PKCS#12 bundle, a JKS private entry, a passphrase-protected OpenSSH key and
  an OpenPGP string-to-key packet are all identified and flagged — the scanner
  does not attempt to decrypt anything, and the finding says so. Absence of a
  decrypt attempt is not absence of a finding: an encrypted private key in a
  shipped binary is still HIGH.
* **Key detection has its own caps**, reported like the rest: a 64 MiB search
  window, 32 MiB for encoded-blob runs, 64 key rows per file, 64 PEM blocks,
  ASN.1 nesting depth 8 and 1 MiB per ASN.1 element. A search that stops at a
  cap says so instead of implying there was nothing more to find.
