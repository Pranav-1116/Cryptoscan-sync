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
| ELF (32/64, LE/BE) | type (exec/PIE/shared/core), machine, `DT_NEEDED` libraries, `RPATH`/`RUNPATH`, `DT_SONAME`, `.note.gnu.build-id`, `.comment` compiler string, dynamic symbols split into imports/exports, stripped/static detection, **Go build info** (toolchain + module graph with exact versions and sums) |
| PE (PE32/PE32+) | machine, subsystem, COFF timestamp, sections, imported DLLs resolved through the section table, .NET/CLR flag |
| Mach-O (thin + fat) | CPU type, file type, `LC_UUID`, platform, linked dylibs, `LC_RPATH` |
| `ar` / `.deb` | members incl. GNU long-name table, symbol-index presence, `.deb` identification |
| zip (`.jar`/`.war`/`.whl`/`.nupkg`/`.apk`) | entry list, Maven coordinates from `pom.properties`, `MANIFEST.MF` version/main-class, Python `dist-info/METADATA` (name/version/licence/requires), native extensions |
| WASM | import and export names (where crypto markers live) |
| Firmware | container chain with offsets (uImage, device-tree, squashfs, JFFS2, UBIFS, cramfs, gzip/xz/zstd/bzip2/lzma/lz4, tar), device-tree `model` + `compatible` identity, Shannon entropy / packed-content signal |
| Java class, RPM, raw | identified; string-level evidence only — see the gaps below |

## 3. Evidence, not assertions

Crypto detection is graded, and every claim keeps the evidence that produced it:

```
STRING_MATCH 0.4  <  SYMBOL_MATCH 0.7  <  IMPORT_MATCH 0.8  <  CONSTANT_MATCH 0.9  <  FINGERPRINT 1.0
```

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

Finding codes: `BIN-EOL-CRYPTO`, `BIN-CRYPTO-NO-VERSION`,
`BIN-WEAK-PRIMITIVE-PRESENT`, `BIN-QUANTUM-VULNERABLE`, `BIN-PQC-CAPABLE`,
`BIN-ECC-NO-PQC`, `BIN-PACKED`, `BIN-STATIC-CRYPTO`, `BIN-RPATH-WRITABLE`,
`BIN-NOT-PARSED`, `BIN-FIRMWARE-NOT-EXTRACTED`.

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
  assets in the crypto inventory under `system_name`.
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
  `BIN-FIRMWARE-NOT-EXTRACTED`. Scan the mounted or extracted tree to inventory
  what is inside.
* **RPM headers are not unpacked**; package contents come from the package
  manager inventory, not from this file scan.
* **Java class constant pools are not parsed** — only the archive metadata.
* **Name matching still exists for container images** (`container_scanner`
  `_discover_binaries`) as a cheap pre-filter; the deep parser is this scanner.
* **Caps, on purpose**: 512 MiB per file, 4 000 files walked, 750 binaries parsed,
  6 000 strings sampled, firmware container search bounded to the first 128 MiB.
  A truncated walk is flagged in the manifest (`binary_summary.truncated`), never
  silently reported as a complete scan.
* **A raw blob is only reported when it carries crypto evidence** (version banner,
  library marker); otherwise it is skipped rather than listed as an unnameable
  "binary".
