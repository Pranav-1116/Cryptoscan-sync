# Connected Lab — Sandbox (Product 1) → CryptoScan (Product 2)

Two products in one repo, local connector, offline.

**Estate**: `/tmp/demo-estate-10` — 10 banks, 206 systems, 412 applications, 106 LB role instances, 510 LB crypto hops, worst-case-bank, small.

**Connector**: `python -m tools.banking_sandbox.cli connect --estate /tmp/demo-estate-10 --output /tmp/demo-output-10`

Scans run in Landlock+seccomp child: `oracle_read_denied=true`, `socket_creation_denied=true`, `collector_source_sha256=ab043bcc434ff424c5c0583c64ef84408c061af88fb2ff4eac86bb2c16b411bd`.

## Measured output — `/tmp/demo-output-10` (cached as `/home/user/.cache/cryptoscan-connected-10`)

| Signal | Observed |
|--------|----------|
| Static files scanned | 382 |
| LB config files scanned (5 filenames) | 382 (`nginx.conf`, `haproxy.cfg`, `envoy.yaml`, `gateway.yaml`, `loadbalancer.json`) |
| Collector errors | 0 (`failure_rate 0.0`, not `NO_CRYPTO`) |
| Static wall | 1.17 s, LB wall 0.59 s, connector wall 4.73 s |
| Precision / Recall | 1.0 / 0.793 (TP 311 FP 0 FN 81, misses Ruby+COBOL) |
| FPR negative | null (no pure-negative files in this estate) |

Misses are honest: `source/bank-0001/…/*.rb` and `*.cbl` expected `SHA-256` but scanner reported nothing — historic Ruby/COBOL blind spot, not counted as `NO_CRYPTO`.

## Six BOMs (real generators)

Each document header states provenance: `SCANNER_OBSERVED` vs `FIXTURE_DERIVED_NOT_LIVE_PROBED`.

| BOM | Generator call | Components | File |
|-----|----------------|------------|------|
| CBOM | `CbomGenerator.from_records(crypto, spec 1.5)` | 334 | `boms/cbom.json` + `cbom.xml` |
| SBOM | TechBOM sbom layer (`app_component`) | 412 | `boms/sbom.json` |
| TechBOM | `materialize_technology_bom(inventory, env, v1)` | 1288 total (sbom 412, cbom 334, hbom 312, vendor 230), fp `32ed16e8…`, snapshot `TECHBOM-20261026-094812` | `boms/techbom.json` |
| HBOM | `generate_hbom(rows, env)` | 312 devices, HSM 74, `content_hash 43d0e130…` | `boms/hbom.json` + `.cyclonedx.json` |
| VBOM | `VbomGenerator` `add_vendor` → `to_document`/`to_cyclonedx` | 86 vendors, 258 crypto entries, `pqc_ready 0` | `boms/vbom.json` + `.cyclonedx.json` |
| NBOM | `build_nbom(endpoints, estate)` | 946 comps (endpoint 112, cert 824, device 10), unobserved 112 | `boms/nbom.json` |
| LB-NBOM | `build_nbom(lb_endpoints)` | 227 (endpoint 106, cert 106, device 15) | `boms/lb-nbom.json` |

TechBOM is the unified view; its fingerprint is over canonical components+deps. HBOM `dependencies` empty by declaration (`No collector records hardware-to-system edges yet`). NBOM `observed=false` — unprobed excluded from verdicts.

All boms in `bom-summary-10.json`; validation in `validation-10.json`; manifest hashes every file.

## Dashboard

`dashboard/index.html` — three panes:

- **Product 1** (Sandbox): `LAB.json`, `integrity` (file_hashes_checked, bom docs), `catalog.json`.
- **Product 2** (CryptoScan): scan metrics, guard proofs, BOM counts, artifact links.
- **Validation**: precision/recall/FN per language, `UNKNOWN ≠ SAFE` banner, schema checks, honest limits.

Serve locally:

```bash
python -m tools.banking_sandbox.cli serve-output --output /tmp/demo-output-10 --port 8080 --host 0.0.0.0
# → http://localhost:8080/dashboard/
# → http://localhost:8080/boms/cbom.json  etc.
```

## Limits (not claimed)

- Only `static` + `lb-config` exercised; 15 modes not fully.
- Network/HBOM/VBOM are `FIXTURE_DERIVED_NOT_LIVE_PROBED`, not live probed/mTLS/HSM op.
- LB hop owner from controlled LB topology, not auto-detected.
- Key-size / attribution / PQC = `null` / `VENDOR_DECLARED_NOT_VERIFIED`.
- No SLA/benchmark — wall time is operational sample.

See `products/README.md` for product boundaries, `products/connector/README.md` for pipeline, `products/sandbox/README.md` and `products/cryptoscan/README.md` for each product.

Evidence:

- [BOM summary](bom-summary-10.json)
- [Validation](validation-10.json)
- [Manifest](manifest-10.json)
