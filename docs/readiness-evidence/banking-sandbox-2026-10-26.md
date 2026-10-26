# Synthetic banking-estate sandbox — measured readiness, 2026-10-26

**Verdict: additive local engineering sandbox implemented and exercised; full requested live-estate acceptance remains incomplete. Not production-qualified.** No customer systems, real bank networks, credentials or production keys were used. CryptoScan core was not modified to make these tests pass. Independent review remains pending.

Implementation: [`tools/banking_sandbox`](../../tools/banking_sandbox/), root [`generate_sandbox.py`](../../generate_sandbox.py). [Runbook](../../tools/banking_sandbox/docs/README.md), [architecture](../../tools/banking_sandbox/docs/architecture.md), [coverage](../../tools/banking_sandbox/docs/coverage.md), [operator procedures](../../tools/banking_sandbox/docs/operations.md).

## Agreed bounded gates and outcomes

Targets were recorded before the measurement runs in [`acceptance.json`](../../tools/banking_sandbox/acceptance.json): 10/50/100/150 banks, deterministic replay, valid references, 35 difficult cases, 15 represented modes, oracle exclusion and no external network for static collection. **No accuracy floor was agreed.** Unexercised queue/database/API capacity must remain UNKNOWN.

| Gate | Result | Exact scope |
|---|---|---|
| 10/50/100/150-bank collection | Measured, all four runs completed | Small-scale synthetic portfolios; normal static collector library calls |
| Large mixed-estate generation | Measured | 150 banks, 17,273 systems; not 150 live banks |
| Replay | Tested | Same options/seed/epoch produce byte-identical public manifest and LAB metadata; elapsed metrics excluded |
| Referential integrity / schemas | Passed | All 39,798 public hashes and 154,557 actual CycloneDX/SPDX documents on mixed estate |
| 35 difficult cases / 15 modes | Represented and checked | Representation does not certify full product execution of each mode |
| Oracle exclusion | Actually tested | Landlock receipt: oracle read denied; no oracle staged or served |
| Static no external network | Actually tested | Seccomp socket creation denied; failed pre-guard attempts are not accepted as proof |
| Actual TLS/runtime sample | Measured separately | Two TLS negotiations plus Python/OpenSSL operations inside NIC-less VM |
| 200 banks | Functional test passed | Minimal profile generation, unique IDs and all twenty archetypes; not a 200-bank throughput benchmark |
| Production/import/correlation/API/queue capacity | UNKNOWN / not accepted | Not inferred from static throughput |

## 150-bank mixed estate

Generated with `banks=150`, `scale=mixed`, `profile=worst-case-bank`, all feature flags true, all complexity choices high, default seed and simulated epoch `2030-01-01T00:00:00Z`.

| Inventory | Count |
|---|---:|
| Banks | 150 |
| Systems | 17,273 |
| Applications | 34,546 |
| Component instances | 207,276 |
| Services/endpoints | 69,092 |
| Public leaf certificates | 69,092 |
| HSM metadata/simulations | 750 |
| KMS key metadata | 34,546 |
| Vendor product records | 3,450 |
| Distinct fictional vendor names | 503 |
| SBOM documents | 120,011 |
| CBOM declarations | 34,546 |
| Same-scope conflict scenarios | 600 |
| Public fixture bytes | 698,630,097 |
| Public files | 39,798 |

All six BOMs are present: **NBOM, CBOM, SBOM, TechBOM, HBOM, VBOM**. The 154,557 schema-checked documents are the SBOM+CBOM documents, not a claim that the four lab-specific projections have an official universal schema. Full validation explicitly reports `FIXTURE_INTEGRITY_VALIDATED_NOT_PRODUCT_DISCOVERY`. Generator wall time was 39.893 seconds; it is not normal CryptoScan CBOM generation latency.

Actual static collection: **34,096 materialized source files**, zero collector errors, 36.486 seconds parent collection wall, 36.355 seconds child CPU, child peak RSS **73,808 KiB**, approximately 934.49 files/s over that collection window. Integrity/staging time precedes the timed child window. The collector is unchanged `scanner.registry.language_scanners.scan_file`, source SHA-256 `ab043bcc434ff424c5c0583c64ef84408c061af88fb2ff4eac86bb2c16b411bd`.

Final family-per-file scoring: **TP 26,346; FP 0; FN 7,300; precision 1.0; recall 0.783035; failed/missing files 0**. The missing families were Ruby SHA-256 (2,432), COBOL-like SHA-256 (2,432), and .NET XML/config AES (2,436). They are retained misses, not waived as successes. This score is not field-wide security accuracy: it does not evaluate actual key-size inference, ownership, runtime attribution, CBOM completeness or every semantic pattern in every language.

## Four measured small-scale runs

| Banks | Systems | Files | Collection wall s | Child CPU s | Child peak RSS KiB | Precision | Recall |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 | 206 | 382 | 1.269 | 1.179 | 45616 | 1.000 | 0.7934 |
| 50 | 1002 | 1854 | 2.728 | 2.673 | 46360 | 1.000 | 0.7894 |
| 100 | 1960 | 3620 | 4.680 | 4.611 | 50704 | 1.000 | 0.7873 |
| 150 | 2961 | 5472 | 6.743 | 6.651 | 60260 | 1.000 | 0.7857 |

These are sequential static library calls with fresh fixtures, not a worker-fleet or queue/database/API capacity test. Generator peak RSS is explicitly a **cumulative process high-water mark**. Complete numbers, storage counts, source/manifest/raw-finding hashes and receipts are in [static-scale.json](banking-sandbox-2026-10-26/static-scale.json). Accuracy JSONs include per-language counts and bounded example misses; full raw findings and full miss lists remain in the external local cache, not Git. The ten-bank run has no completed negative-file denominator, so FPR is **null**, not a demonstrated zero.

After collection, retained findings were rescored with composite family normalization (`SHA256withRSA`, HMAC/SHA variants) and failed-negative exclusion from TN/FPR. **Collection timings were not rerun or edited.** This is disclosed in the scale report. The larger mixed run also has an explicitly rescored accuracy summary. The earlier scale attempt failed before the guard due to lab `operator.py` shadowing stdlib `operator`; it is retained as a failed attempt and superseded, not acceptance evidence. Any historical network-denial field in that attempt is invalid because no guard receipt existed. The lab file is now `operations.py`.

## Actual isolated live witness

**Source qualification:** “unchanged” means unchanged **by this sandbox increment**. The TLS handshaker already had a user working-tree modification before this task; it was preserved and is **not included in this publication**. The VM bundle binds the measured working-tree source hash. [Source provenance](banking-sandbox-2026-10-26/live-source-provenance.json) records measured versus HEAD hashes. Rebuilding/rerunning from a clean published checkout is required before claiming that exact checkout reproduces this live witness. The static scanner source has no such working-tree difference.

[Successful VM run 02](banking-sandbox-2026-10-26/live-vm-run-02.json): `MEASURED_ISOLATED_VM_SAMPLE`, wall **10.680 seconds**, 256 MiB, one TCG CPU, no external NIC, loopback-only endpoints, unchanged parent boot/network/mount identities. Bundle SHA-256 `85626c64117763b09fa57b4fada697c071dd039fc02b3e3f1b75c28a558e0d6b`; serial SHA-256 `8a2546d129b007276d4a01ce222051eb57ae415e150e3aafd0a24ba77d4017d0`.

- Unchanged production TLS handshaker actually negotiated **TLS 1.2 / ECDHE-RSA-AES256-GCM-SHA384** and **TLS 1.3 / TLS_AES_256_GCM_SHA384**.
- One ephemeral synthetic certificate fingerprint was observed by both handshakes. Authentication was **not verified**; this is discovery, not an mTLS/identity proof.
- Python/OpenSSL actually executed SHA-256 and HMAC-SHA256 and reported loaded libcrypto. This is **not** proof of the normal runtime-agent pipeline.
- An actual refused-service injection returned FAILED with `crypto_absent=null`.
- Disposable private keys remained inside guest RAM; only public fingerprints and result metadata were exported.
- [Run 01](banking-sandbox-2026-10-26/live-vm-run-01-failed.json) is retained as `GUEST_FAILED` due to missing OpenSSL default configuration. Run 02 uses an explicit minimal config.

## Tests and dashboard

**51 focused tests passed**: deterministic replay; all eleven profiles; functional 200-bank generation and twenty archetypes; six BOM presence and official SBOM/CBOM schemas; actual CA chain verification; no serialized private keys; reference/visibility integrity; configured-vs-executed/conflict semantics; drift baseline preservation; corruption; traversal/symlink containment; strict JSON; scoring denominators/composite families; cross-bank rejection; UNKNOWN≠SAFE; dashboard truth exclusion; metadata-only Kubernetes secrets; failure exercises; real normal static collection with tested Landlock/seccomp/oracle denial. Ruff, formatting, Python compilation and dashboard JavaScript syntax checks passed. These are focused sandbox tests, **not a claim that the entire repository suite was rerun**.

A read-only dashboard is running on port **8080**, bound to `0.0.0.0` for the Arena preview. HTTP smoke checks: `/`, catalog and bank systems returned 200; control and plain/encoded traversal returned 404; directory listing returned 403. No browser visual automation was available; visual/browser interaction acceptance remains pending. Counts are visibly labeled generated fixtures, not discoveries. Existing unrelated edits/deletions were preserved using **5,063 outside-owned file fingerprints**.

## Remaining work before full requested acceptance

1. Execute isolated live TLS1.0/1.1/mTLS/SSH/IKE/database/MQ/Kafka and selected multi-language runtime scenarios through normal collectors. Current records are configuration/import fixtures, not observations.
2. Implement and independently qualify actual HSM/PKCS#11/payment/KMS operations and PQC/hybrid negotiation. Current maturity 0–5 and device capabilities are declarations only.
3. Exercise normal production BOM import/correlation/ownership/dependency/evidence pipelines, with actual normalized product outputs compared against hidden truth. Current full schema checks and source-family accuracy do not establish those capabilities.
4. Execute real scoped DB/Redis/cluster/HSM/KMS outages and recovery. Only malformed input/hash failures, visibility gaps, boundary denial and a refused VM service were actually exercised here.
5. Measure queue, worker, API, database, network/runtime throughput and end-to-end CBOM/correlation latency under agreed targets. Current values are null/UNKNOWN; no production capacity or 24/7 SLA is inferred.
6. Agree accuracy floors before detector improvement and rerun the same workload; current recall gaps are explicit. Complete independent security/source-authenticity/license review and operator acceptance. Optional Compose is untested because Docker is absent.

The artifact index provides integrity hashes, **not independent authenticity or an external audit**. Large estates, native bundles, caches, VM keys and raw collector datasets are intentionally excluded from Git. All publication changes are additive and scoped; no workflow or core scanner changes are part of this increment.
