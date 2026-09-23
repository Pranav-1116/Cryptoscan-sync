# SBOM scanner: architecture vs. what ships

This page maps the **target architecture** (11 collection sources, a Kafka
ingestion bus, 10 Flink stream-processing jobs, Neo4j + S3 WORM storage, a VEX
and license pipeline) against what this repository actually runs. It exists so
nobody plans a deployment against a diagram.

Two rules govern this document:

1. **Nothing is marked shipped that a reader cannot exercise.** Every "shipped"
   row names the module or endpoint that implements it.
2. **Where the platform refuses to make a claim, that refusal is the feature.**
   Reachability analysis, license compatibility rulings, and "clean" verdicts on
   unchecked code are absent on purpose, not pending.

## 1. Collection sources

| Source in the target architecture | Status here | Where it lives |
|---|---|---|
| Source code manifests (13 ecosystems) | **Shipped** — manifest + lockfile parsers, resolved/transitive graph | `devsecops/sbom_scan.py`, `devsecops/sbom_lockfiles.py` |
| Container image | **Shipped** — deterministic rootfs/`docker save`/as-image path; registry pull fails closed with an honest 503 when Docker is unavailable | `devsecops/sbom_scan.py`, `POST /devsecops/sbom/scan {kind: container}` |
| Binary / firmware | **Shipped (parse) / Partial (extract)** — real parsers for ELF (dynamic deps, RPATH, build-id, compiler, dynamic symbols, **Go build info incl. the module graph**), PE (imports via RVA mapping, subsystem, .NET), Mach-O (fat + thin, load commands, UUID), `ar`/`.deb`, zip (jar/wheel/nupkg/APK metadata), WASM, Java class, RPM header, raw blobs, and firmware container chains (uImage, device-tree `model`/`compatible`, squashfs, JFFS2, UBIFS, cramfs, gzip/xz/zstd…). Crypto evidence is graded (string < symbol < import < constant < fingerprint) with per-file provenance. Embedded key material is detected byte-first (hand-rolled DER/ASN.1: PEM, PKCS#1/8/10/12, SEC1, SPKI, X.509, PKCS#7/CMS, OpenSSH, PuTTY, OpenPGP, JKS/JCEKS, ML-KEM/ML-DSA OIDs, plus base64/hex-encoded copies) and reported as kind/type/size/curve/encryption/hash — **never the key bytes**; encrypted material is identified and not decrypted. **Squashfs/JFFS2 contents are NOT extracted (that needs binwalk); an RPM header is not unpacked; Java class constant pools are not read** — each of these is reported as a finding, never implied | `services/devsecops/devsecops/binary_scan.py`, `POST /devsecops/binary/scan`, `container_scanner/core/scanner.py` (`_discover_binaries` remains for image-wide name matching) |
| Build system (CI plugins, SLSA) | **Partial** — CI gate ships (`devsecops.sbom_gate` CLI + `scripts/ci_gate.py`); SLSA/in-toto attestation ingestion is **not implemented** | `services/devsecops/devsecops/sbom_gate.py` |
| Vendor SBOM ingestion | **Shipped (ingest + assurance)** — stored as artifacts, format detected, signature/digest verified, NTIA scored, licensed, gated | `POST /devsecops/sbom/import`, `/sbom/validate`, `/sbom/license`, `/sbom/{id}/gate` |
| Manual upload | **Shipped** — same import endpoint, console tab | console → DevSecOps → SBOM → Import |
| Package manager integration (8 OS families) | **Partial** — dpkg / apk / rpm / npm / pip / go / cargo / composer / gem / gradle / nuget by file parsing; **no host agent**, so "query the running system every N minutes" does not exist | `devsecops/sbom_lockfiles.py`, container scanner inventory |
| Runtime SBOM (eBPF) | **Not implemented** — no kernel agent, no `/proc/{pid}/maps` collector | — |
| Cloud resource SBOM (Lambda, Functions, Cloud Run…) | **Partial** — cloud scanning exists (`services/cloud_scanner`) but does not emit SBOM components for managed runtimes | `services/cloud_scanner` |
| Third-party API (Venafi, Snyk, Black Duck…) | **Partial** — `services/vendor_intel` imports CycloneDX **cryptographic-asset** components from a vendor SBOM/CBOM into the inventory; per-vendor SBOM exporters (Snyk, Black Duck, FOSSA…) are not implemented | `vendor_intel/sbom_import.py`, `services/connector_sdk` |
| Firmware (binwalk, SquashFS/JFFS2) | **Partial** — firmware images are identified and their container chain mapped (offsets for uImage/DTB/squashfs/JFFS2/UBIFS/gzip/xz/zstd), device-tree identity extracted, entropy reported; **no extraction and no filesystem mounting** (binwalk needed), and the finding `BIN-FIRMWARE-NOT-EXTRACTED` says so on every such image | `devsecops/binary_scan.py` (`parse_firmware`, `_parse_dtb`) |
| Registry webhooks (ECR, ACR, Harbor…) | **Shipped** — a single authenticated endpoint handles push events from ACR/GCR/ECR/Harbor/Docker Hub style registries (HMAC signature or machine API key, fail-closed), documented in the admin guide | `api/routers/webhooks.py::container_registry_webhook` |

### 1.1 Binary scanning — how a binary becomes a component

The binary scanner is not a separate stack: it produces the same canonical result
shape the SBOM renderer consumes, so binaries flow through rendering, NTIA
scoring, licence policy, gate, signing, VEX, diff and CBOM like any other scan.

| Step | What happens | Evidence kept |
|---|---|---|
| Identify | magic bytes only; `MZ` must carry `PE\0\0` at `e_lfanew`, fat Mach-O is told apart from a Java class file by arch count | format, arch, bits |
| Parse | ELF/PE/Mach-O/ar/zip/WASM/class/RPM/firmware parsers (stdlib only, every read bounds-checked) | dependencies, symbols, compiler, build-id, Go module graph, archive members, DTB model |
| Fingerprint | universal-crypto tables plus version banners read from the file, with identifier-boundary matching | per library: `evidence_classes`, verdict, and the versions of anything the strict pass refused to confirm (`suppressed_libraries`, with the reason) |
| Classify crypto | AES/RSA/ECDSA/MD5/SHA-1… graded per detection; PQC designations captured in full (`ML-KEM-768`, not `ML-KEM`); X25519/Ed25519 counted as **classical ECC** (Shor-vulnerable), never as PQC | confidence level + strongest evidence + the strings/symbols that produced it |
| Report | findings cite the file and the evidence; EOL versions, weak primitives, statically linked crypto, packed content, non-system RPATH, and every "we did not parse this" gap | `BIN-*` codes with severity |
| Emit | CycloneDX SBOM (crypto libraries become components, Go module graph becomes the dependency tree) and CycloneDX CBOM (`cryptographic-asset` per algorithm, ingestible via `POST /cbom/ingest`) | component `bom-ref`, sha256, `cryptoscan:*` properties |

## 2. Ingestion and processing

The target architecture specifies Kafka topics and 10 Flink jobs. **This repo
has no Kafka and no Flink**: those are deployment options, not code that ships
here. What exists is the same *logic*, implemented as deterministic Python over
documents, invoked synchronously by the API and CLI.

| Target job | Status here | Implementation |
|---|---|---|
| 1. Parse CycloneDX / SPDX / SWID | **Partial** — CycloneDX + SPDX fully; SWID is **not** parsed | `sbom_assurance.py`, `sbom.py` |
| 2. Normalize to canonical form | **Shipped** — one component shape across both formats; `render_sbom` emits either vocabulary | `sbom_scan.py` (`enrich_bom`, `render_sbom`) |
| 3. Deduplicate across sources | **Shipped** — declared rows merge with resolved lockfile rows, resolved version wins, `declared_spec` retained | `sbom_scan.py` (`_merge_declared_and_resolved`) |
| 4. Vulnerability matching (NVD/OSV/GHSA/KEV) | **Partial** — deterministic matching against a feed you supply; version bounds honoured both directions; **no live NVD/OSV/GHSA/KEV fetch** (offline by design) | `sbom_scan.enrich_vulnerabilities`, `container_scan.match_packages` |
| 5. License compliance | **Shipped** — inventory, SPDX expression parsing, family-aware policy verdicts, copyleft *review trigger* (never a compatibility ruling) | `devsecops/sbom_license.py`, `POST /devsecops/sbom/license` |
| 6. VEX generation | **Shipped (deterministic)** — derived statements plus validated operator overrides; `not_affected` requires a justification, on purpose | `devsecops/sbom_vex.py`, `POST /devsecops/sbom/vex`, `GET /sbom/{id}/vex` |
| 7. Graph sync (Neo4j) | **Partial** — the resolved dependency graph ships inside the BOM (CycloneDX `dependencies[]`, SPDX `DEPENDS_ON`); the graph engine ships syncers for certificates, cloud resources, crypto assets, systems, vendors and business processes, but **no component/dependency syncer yet** | `sbom_scan.enrich_bom`, `services/graph_engine/builders/` |
| 8. CBOM enrichment | **Shipped** — crypto-relevant components carry algorithms/vendor, and the CBOM service has a CycloneDX CBOM export | `sbom_scan.enrich_bom`, `services/cbom` |
| 9. Delta detection | **Shipped** — SBOM-to-SBOM diff with upgrade/downgrade direction, license changes, crypto deltas, verdict | `sbom_assurance.diff_boms`, `POST /sbom/diff`, `POST /sbom/{id}/rescan` |
| 10. Evidence chain | **Shipped** — artifact blob sha256 + HMAC-SHA256 manifest signature, re-verifiable, plus the platform audit chain | `sbom_scan.sign_manifest`/`verify_artifact`, `/sbom/{id}/verify` |

Continuously-running monitors in the target architecture (6-hourly KEV checks,
scheduled re-matching) are **not SBOM scheduler jobs here**. The platform has a
scheduling service and report distribution, but no job that re-matches
advisories against the stored inventory on a timer. The equivalent today is
`POST /sbom/{id}/rescan` invoked by a pipeline or scheduler you own, which is
stated plainly rather than implied by a diagram.

## 3. Storage and output

| Target | Status here | Reality |
|---|---|---|
| PostgreSQL tables (`sbom_versions`, `sbom_components`, …) | **Not implemented as separate tables** — artifacts live in a content-addressed store (`SBOM_STORAGE_DIR`, 0600, atomic writes) with manifests carrying the summary fields; audit rows go to the platform audit chain | `governance/backup_jobs.py` storage pattern |
| S3 WORM 7-year retention | **Not implemented** — `DiskBackupStorage` is a real durable directory that survives restarts; WORM/object-lock is deployment work. Retention is enforced by `DELETE /sbom/artifacts?older_than_days=` | `governance/backup_jobs.py` |
| Redis hot cache | **Not implemented for SBOM** | — |
| CycloneDX 1.5 / SPDX 2.3 JSON | **Shipped** | `/sbom/scan`, `/sbom/{id}/download` |
| CycloneDX 1.6 / SPDX 3.0 / SWID | **Not implemented** — the renderer pins 1.5 / 2.3 | — |
| XML, PDF exports | **Not implemented** — JSON plus a markdown auditor report | `/sbom/{id}/report` |
| VEX export | **Shipped** — CycloneDX VEX JSON + markdown, with `?dl=true` | `GET /sbom/{id}/vex` |
| NTIA / minimum-elements reporting | **Shipped** — per-element PASS/PARTIAL/FAIL with named gaps | `/sbom/validate`, every scan response |
| SIEM / ticketing push | **Partial** — SIEM and ticketing integrations exist platform-wide; no SBOM-specific event routing | `services/observability`, tickets API |

## 4. Cross-artifact views

The target API lists "where is this component used?" and "what does this CVE
affect?" as first-class queries. Both ship, with the honesty caveat that matters
to a reviewer:

* `GET /devsecops/sbom/components?q=&crypto=&limit=` — component rows joined to
  the artifacts carrying them. Reads artifact bodies, so it is bounded and says
  how many artifacts it scanned.
* `GET /devsecops/sbom/advisories?severity=&cve=` — advisories recorded across
  stored artifacts, **counting only artifacts that were actually matched against
  a feed** and reporting how many were not. A scan run without a feed can never
  contribute a "no advisories" row to this view.

## 5. Known gaps, stated plainly

| Gap | Why it matters | What would close it |
|---|---|---|
| No live NVD/OSV/GHSA/KEV feed fetch | Advisory data must be supplied per scan; keeping it offline is a deliberate air-gap property | A feed-sync service with signed mirrors |
| No host/agent runtime SBOM | Build-time vs runtime drift is invisible today | eBPF or `/proc` agent + comparison job |
| No SLSA/in-toto attestation ingestion | Build provenance cannot be independently verified | Attestation verification in the build-ingest path |
| SWID, CycloneDX 1.6, SPDX 3.0, XML/PDF | Some consumers require them | Additional renderers/parsers |
| No Kafka/Flink/Neo4j/S3-WORM deployment | Throughput ceiling and 7-year immutable retention are deployment concerns | Real infra, not code |
| VEX has no reachability analysis | Statements beyond "matched the advisory range" are operator judgement | Static analysis or runtime instrumentation |
| No license compatibility matrix | Deliberate — that is legal advice the platform will not fabricate | Counsel-authored rules, kept as data |

## 6. Reading the console

DevSecOps → **SBOM** is a seven-tab workspace:

| Tab | What it is for |
|---|---|
| Scan & generate | produce an SBOM from a source tree or container, with an optional advisory feed |
| Artifacts | verify / gate / re-scan / report / download, with kind, format and target filters |
| Diff | compare two stored artifacts, or two inline documents |
| Validate | NTIA minimum-elements scoring for a supplier document |
| Licenses | inventory + policy verdict, including the copyleft review trigger |
| Index | cross-artifact components and advisories |
| Import | pinning and dependency-graph view of an imported document |
